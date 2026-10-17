<?php

declare(strict_types=1);

namespace DaemonLabs\ShieldOidc;

use CodeIgniter\Cache\CacheInterface;
use CodeIgniter\Session\SessionInterface;
use DaemonLabs\ShieldOidc\Config\ShieldOidc;
use DaemonLabs\ShieldOidc\Exceptions\OidcException;
use DaemonLabs\ShieldOidc\Http\HttpClient;
use DaemonLabs\ShieldOidc\Jose\Base64Url;
use DaemonLabs\ShieldOidc\Jose\IdTokenVerifier;
use Throwable;

/**
 * OpenID Connect relying party (the "client" side of a sign-in).
 *
 * A sign-in has two halves:
 *
 *  1. authorizationUrl() builds the URL that sends the browser to the provider. It creates a
 *     random state, nonce and PKCE verifier and parks them in the session (SESSION_KEY).
 *  2. handleCallback() runs when the provider sends the browser back. It matches the state,
 *     swaps the one-time code for tokens over a back channel (server to provider, TLS), and
 *     verifies the ID token. Nothing from the browser is trusted beyond the code and state.
 *
 * Security features: authorization code flow with PKCE (S256), single-use state bound to one
 * provider, a nonce per sign-in, RFC 9207 issuer identification (mix-up defence), and ID
 * token verification by IdTokenVerifier. Provider metadata (discovery document, signing keys)
 * is validated, https-only, and cached.
 *
 * This class knows nothing about Shield users; UserResolver turns the verified claims into one.
 */
class OidcClient
{
    /**
     * Session key holding sign-ins in progress, keyed by state:
     * [state => [provider, nonce, verifier, started, expires, return, link]].
     */
    public const SESSION_KEY = 'shield_oidc_pending';

    /** Sign-ins kept per session at once (several tabs); older ones are dropped. */
    private const MAX_PENDING = 5;

    /** Seconds between forced key refetches (Microsoft recommends no more than every 5 minutes). */
    private const REFETCH_AFTER = 300;

    /** Seconds a last-known-good discovery document or key set is kept for provider outages. */
    private const LAST_KNOWN_GOOD_TTL = 604800;

    /**
     * Built by the oidcClient service (Config\Services); construct it yourself only in tests or
     * to swap a dependency.
     */
    public function __construct(
        protected readonly ShieldOidc $config,
        protected readonly HttpClient $http,
        protected readonly CacheInterface $cache,
        protected readonly SessionInterface $session,
    ) {
    }

    /** A configured provider by key; throws OidcException when unknown or misconfigured. */
    public function provider(string $key): Provider
    {
        return Provider::fromConfig($key, $this->config);
    }

    /**
     * The callback URL for a provider, exactly as it must be registered at the provider:
     * the 'redirectUri' option if set, otherwise site_url('<routePrefix>/<key>/callback').
     */
    public function redirectUri(Provider $provider): string
    {
        $custom = (string) $provider->option('redirectUri', '');

        return $custom !== '' ? $custom : site_url(trim($this->config->routePrefix, '/') . '/' . $provider->key . '/callback');
    }

    /* ------------------------------------------------------------------ discovery */

    /**
     * The provider's discovery document (/.well-known/openid-configuration), cached for
     * $cacheTtl. Before it's cached it is checked: the required endpoints exist, its issuer
     * matches the configured one (OIDC Discovery 4.3; Entra's tenant templates are allowed),
     * every endpoint is https, and the lists we rely on contain only strings.
     *
     * @param bool $fresh Skip the cache (oidc:check uses this)
     *
     * @return array<string, mixed>
     *
     * @throws OidcException When the provider can't be reached or the document is unacceptable
     */
    public function discovery(Provider $provider, bool $fresh = false): array
    {
        $this->assertUrl($provider->issuer, 'issuer');
        $cacheKey = 'shieldoidc_disc_' . md5($provider->issuer);
        if (! $fresh && is_array($doc = $this->cacheGet($cacheKey))) {
            return $doc;
        }

        $url = $provider->issuer . '/.well-known/openid-configuration';
        try {
            $doc = $this->getJson($url, 'discovery document');
        } catch (OidcException $e) {
            // Provider unreachable: keep signing people in with the last good copy (but let
            // oidc:check, which asks for a fresh one, see the failure).
            if ($fresh) {
                throw $e;
            }

            return $this->lastKnownGood($cacheKey, $e);
        }
        foreach (['issuer', 'authorization_endpoint', 'token_endpoint', 'jwks_uri'] as $k) {
            if (! is_string($doc[$k] ?? null) || $doc[$k] === '') {
                throw OidcException::config('Discovery document at ' . $url . ' has no ' . $k . '.');
            }
        }
        if (! $this->discoveryIssuerOk($provider, $doc['issuer'])) {
            throw OidcException::config('Discovery document issuer "' . $doc['issuer'] . '" does not match the configured issuer "' . $provider->issuer . '".');
        }
        foreach (['authorization_endpoint', 'token_endpoint', 'jwks_uri', 'userinfo_endpoint', 'end_session_endpoint'] as $k) {
            if (! array_key_exists($k, $doc)) {
                continue;
            }
            if (! is_string($doc[$k])) {
                throw OidcException::config('Discovery document ' . $k . ' is not a URL.');
            }
            $this->assertUrl($doc[$k], $k);
        }
        // Lists the rest of the code relies on: keep only their string entries.
        foreach (['id_token_signing_alg_values_supported', 'token_endpoint_auth_methods_supported', 'code_challenge_methods_supported'] as $k) {
            if (array_key_exists($k, $doc)) {
                $doc[$k] = is_array($doc[$k]) ? array_values(array_filter($doc[$k], 'is_string')) : [];
            }
        }
        if (isset($doc['code_challenge_methods_supported']) && ! in_array('S256', $doc['code_challenge_methods_supported'], true)) {
            log_message('warning', 'Shield OIDC: provider {p} does not advertise PKCE S256; sending it anyway.', ['p' => $provider->key]);
        }

        $this->cacheSave($cacheKey, $doc);
        $this->cacheSave($cacheKey . '_lkg', $doc, self::LAST_KNOWN_GOOD_TTL);

        return $doc;
    }

    /**
     * The provider's signing keys (JWKS), cached for $cacheTtl.
     *
     * $fresh asks for a new copy, which IdTokenVerifier does when a token names a key id we
     * haven't seen (the provider rotated its keys). Forced refetches are honoured at most once
     * a minute per key set, and never right after a normal fetch, so a run of bad tokens can't
     * turn into a stream of requests to the provider.
     *
     * @param array<string, mixed> $doc The discovery document
     *
     * @return array<string, mixed>
     *
     * @throws OidcException When the keys can't be fetched
     */
    public function jwks(array $doc, bool $fresh = false): array
    {
        $uri      = (string) $doc['jwks_uri'];
        $cacheKey = 'shieldoidc_jwks_' . md5($uri);
        $cached   = $this->cacheGet($cacheKey);
        // A forced refetch is honoured at most once every 5 minutes per key set (Microsoft's
        // rollover guidance; it also keeps a run of bad tokens from hammering the provider).
        $recent = is_int($last = $this->cacheGet($cacheKey . '_at')) && $last > time() - self::REFETCH_AFTER;
        if (is_array($cached) && (! $fresh || $recent)) {
            return $cached;
        }

        try {
            $set = $this->getJson($uri, 'signing keys');
            if (! isset($set['keys']) || ! is_array($set['keys'])) {
                throw OidcException::config('The JWKS at ' . $uri . ' has no "keys".');
            }
        } catch (OidcException $e) {
            return $this->lastKnownGood($cacheKey, $e);
        }
        $this->cacheSave($cacheKey, $set);
        $this->cacheSave($cacheKey . '_lkg', $set, self::LAST_KNOWN_GOOD_TTL);
        $this->cacheSave($cacheKey . '_at', time());

        return $set;
    }

    /* ------------------------------------------------------------------ sign-in request */

    /**
     * Builds the URL to send the browser to, and remembers state, nonce and PKCE verifier in
     * the session for handleCallback().
     *
     * The provider's 'authParams' are added last and can't replace any parameter set here.
     * When linking, prompt=login and max_age=0 are always sent.
     *
     * @param string|null     $returnTo   Local path to land on afterwards (anything else is dropped)
     * @param int|string|null $linkUserId The signed-in user, when connecting this provider to their account
     *
     * @throws OidcException When the provider's discovery document can't be loaded
     */
    public function authorizationUrl(Provider $provider, ?string $returnTo = null, int|string|null $linkUserId = null): string
    {
        $doc      = $this->discovery($provider);
        $state    = Base64Url::encode(random_bytes(32));
        $nonce    = Base64Url::encode(random_bytes(32));
        $verifier = Base64Url::encode(random_bytes(48));

        $params = [
            'response_type'         => 'code',
            'client_id'             => $provider->clientId,
            'redirect_uri'          => $this->redirectUri($provider),
            'scope'                 => implode(' ', $provider->scopes()),
            'state'                 => $state,
            'nonce'                 => $nonce,
            'code_challenge'        => Base64Url::encode(hash('sha256', $verifier, true)),
            'code_challenge_method' => 'S256',
        ];
        // Connecting an account: make the person sign in at the provider again, so a provider
        // session that happens to be open in this browser (someone else's, on a shared machine)
        // can't be linked silently. What "again" takes differs by provider (see Provider).
        if ($linkUserId !== null) {
            $params = array_merge($params, $provider->reauthParams());
        }
        // Extra parameters come last and can't override anything above (Provider also refuses
        // the security-relevant names outright).
        $params += array_map('strval', array_filter((array) $provider->option('authParams', []), 'is_scalar'));

        // max_age, if sent, obliges the provider to report auth_time (OIDC Core 3.1.2.1);
        // remember it so the callback can check how recent the sign-in really was.
        $maxAge = isset($params['max_age']) && ctype_digit((string) $params['max_age']) ? (int) $params['max_age'] : null;

        $pending = $this->pending();
        $pending[$state] = [
            'provider' => $provider->key,
            'nonce'    => $nonce,
            'verifier' => $verifier,
            'started'  => time(),
            'expires'  => time() + $this->config->stateTtl,
            'return'   => self::safeReturnPath($returnTo),
            'link'     => $linkUserId,
            'maxAge'   => $linkUserId !== null ? 0 : $maxAge,
        ];
        // Several tabs may start a sign-in; keep only the newest few.
        $this->session->set(self::SESSION_KEY, array_slice($pending, -self::MAX_PENDING, null, true));

        $endpoint = (string) $doc['authorization_endpoint'];

        return $endpoint . (str_contains($endpoint, '?') ? '&' : '?') . http_build_query($params, '', '&', PHP_QUERY_RFC3986);
    }

    /* ------------------------------------------------------------------ callback */

    /**
     * Handles the provider's redirect back. In order:
     *
     *  1. Finds the sign-in by state (single use: it's removed even if a later step fails) and
     *     checks it was started for this provider and hasn't expired.
     *  2. Reports a provider error (e.g. the person cancelled), only for a valid state.
     *  3. Checks the RFC 9207 iss parameter.
     *  4. Swaps the code (with the PKCE verifier) for tokens at the token endpoint.
     *  5. Verifies the ID token, including the nonce from step 1.
     *  6. When linking, checks auth_time (if sent) shows a fresh sign-in.
     *  7. Adds userinfo claims the ID token left out (never overriding it).
     *
     * @param array<string, mixed> $query The callback's query parameters, untrusted
     *
     * @return array{claims: array<string, mixed>, idToken: string, return: ?string, link: int|string|null}
     *               Verified claims, the raw ID token (kept for logout), and the return path
     *               and link user id stored when the sign-in started
     *
     * @throws OidcException With a message safe to show and a detail for the log
     */
    public function handleCallback(Provider $provider, array $query): array
    {
        $state   = is_string($query['state'] ?? null) ? $query['state'] : '';
        $pending = $this->pending();
        $flow    = $state !== '' ? ($pending[$state] ?? null) : null;
        if ($flow !== null) {
            unset($pending[$state]); // single use
            $this->session->set(self::SESSION_KEY, $pending);
        }

        if ($flow === null || $flow['provider'] !== $provider->key) {
            throw new OidcException(lang('Oidc.stateInvalid'), 'Unknown or reused state for provider ' . $provider->key . '.');
        }

        $doc = $this->discovery($provider);

        // RFC 9207, checked before anything else in the response (error responses carry iss
        // too, and an error from the wrong provider mustn't be taken as ours): if the provider
        // names itself, it must be the one we asked; if it says it always does, a missing iss
        // is a failure.
        if (isset($query['iss']) && (! is_string($query['iss']) || ! $this->tokenIssuerOk($provider, $doc, $query['iss'], null))) {
            throw OidcException::token('Callback iss parameter does not match the provider (possible mix-up attack).');
        }
        if (! isset($query['iss']) && ($doc['authorization_response_iss_parameter_supported'] ?? false) === true) {
            throw OidcException::token('Callback has no iss parameter although the provider advertises that it always sends one'
                . ' (possible mix-up attack; on Keycloak, turn off the client\'s "Exclude Issuer From Authentication Response").');
        }

        // Provider errors are only reported for a sign-in we started; anyone could craft this URL.
        if (isset($query['error'])) {
            $err  = self::clean($query['error'], 64);
            $desc = self::clean($query['error_description'] ?? '', 300);

            throw new OidcException(
                $err === 'access_denied' ? lang('Oidc.accessDenied') : lang('Oidc.providerError'),
                'Provider returned error "' . $err . '": ' . $desc,
            );
        }
        if ($flow['expires'] < time()) {
            throw new OidcException(lang('Oidc.stateExpired'), 'Sign-in took longer than stateTtl.');
        }
        $code = is_string($query['code'] ?? null) ? $query['code'] : '';
        if ($code === '') {
            throw new OidcException(lang('Oidc.stateInvalid'), 'Callback has no authorization code.');
        }

        $tokens = $this->exchangeCode($provider, $doc, $code, (string) $flow['verifier']);

        $verifier = new IdTokenVerifier(
            fn (bool $fresh): array => $this->jwks($doc, $fresh),
            $this->allowedAlgs($provider, $doc),
            $this->config->clockSkew,
        );
        $claims = $verifier->verify(
            $tokens['id_token'],
            $provider->clientId,
            fn (string $iss, array $c): bool => $this->tokenIssuerOk($provider, $doc, $iss, $c),
            (string) $flow['nonce'],
            $provider->trustedAudiences(),
        );

        $this->checkAuthTime($provider, $flow, $claims);

        // Userinfo needs a Bearer access token (OIDC Core 3.1.3.3; RFC 6749 7.1: a client must
        // not use a token type it doesn't understand). The type is case-insensitive.
        $bearer = is_string($tokens['access_token'] ?? null) && strcasecmp((string) ($tokens['token_type'] ?? ''), 'Bearer') === 0;
        if ($provider->option('userinfo', true) && is_string($doc['userinfo_endpoint'] ?? null)) {
            if ($bearer) {
                $claims = self::mergeUserinfo($claims, $this->userinfo((string) $doc['userinfo_endpoint'], $tokens['access_token'], (string) $claims['sub']));
            } else {
                log_message('warning', 'Shield OIDC: provider {p} returned no Bearer access token; userinfo skipped.', ['p' => $provider->key]);
            }
        }

        return ['claims' => $claims, 'idToken' => $tokens['id_token'], 'return' => $flow['return'], 'link' => $flow['link']];
    }

    /**
     * When the sign-in asked for a recent authentication (max_age, which linking always
     * implies), check the provider's auth_time: it must be within max_age of when the sign-in
     * started. OIDC Core 3.1.2.1 obliges the provider to send auth_time once max_age is
     * sent, so by default its absence fails; providers that don't support max_age (Entra,
     * Google) are configured with requireAuthTime off and rely on their prompt instead.
     *
     * @param array<string, mixed> $flow
     * @param array<string, mixed> $claims
     */
    protected function checkAuthTime(Provider $provider, array $flow, array $claims): void
    {
        $maxAge = $flow['maxAge'] ?? null;
        if (! is_int($maxAge)) {
            return;
        }
        if (! array_key_exists('auth_time', $claims)) {
            if ($provider->requireAuthTime()) {
                throw OidcException::token('The provider sent no auth_time although max_age was requested (set requireAuthTime => false if it never does).');
            }

            return;
        }
        $authTime = $claims['auth_time'];
        $started  = (int) ($flow['started'] ?? 0);
        if ((! is_int($authTime) && ! is_float($authTime)) || $authTime < $started - $maxAge - $this->config->clockSkew) {
            throw OidcException::token('The sign-in needed a fresh authentication, but the provider reused an earlier session (auth_time).');
        }
    }

    /**
     * Adds userinfo claims the ID token left out, never overriding it. An email and its
     * verification flags are kept as a set from one source: a verified flag for one address
     * must never vouch for a different address from the other source.
     *
     * @param array<string, mixed> $claims Verified ID token claims
     * @param array<string, mixed> $info   Userinfo claims (already matched on sub)
     *
     * @return array<string, mixed>
     */
    public static function mergeUserinfo(array $claims, array $info): array
    {
        $emailSet = ['email', 'email_verified', 'xms_edov', 'hd'];
        if (array_key_exists('email', $claims)) {
            $sameEmail = is_string($info['email'] ?? null) && is_string($claims['email'])
                && strcasecmp($info['email'], $claims['email']) === 0;
            if (! $sameEmail) {
                foreach ($emailSet as $k) {
                    unset($info[$k]);
                }
            }
        } else {
            // No email in the ID token: take userinfo's email with its own flags, not the
            // ID token's (there are none to mix with in that case).
            foreach (['email_verified', 'xms_edov', 'hd'] as $k) {
                if (array_key_exists($k, $claims)) {
                    unset($info['email'], $info['email_verified'], $info['xms_edov'], $info['hd']);
                    break;
                }
            }
        }

        return $claims + $info;
    }

    /**
     * The token request (OAuth 2.0 authorization code grant with PKCE).
     *
     * Confidential clients authenticate with exactly one method: client_secret_basic when the
     * provider supports it (or says nothing), otherwise client_secret_post. Id and secret are
     * form-encoded inside the Basic header as RFC 6749 2.3.1 requires.
     *
     * @param array<string, mixed> $doc
     *
     * @return array<string, mixed> The token response, guaranteed to have a string id_token
     *
     * @throws OidcException When the request fails or no ID token comes back
     */
    protected function exchangeCode(Provider $provider, array $doc, string $code, string $verifier): array
    {
        $form = [
            'grant_type'    => 'authorization_code',
            'code'          => $code,
            'redirect_uri'  => $this->redirectUri($provider),
            'client_id'     => $provider->clientId,
            'code_verifier' => $verifier,
        ];
        $headers = [];
        if ($provider->clientSecret !== '') {
            // Exactly one method (RFC 6749 2.3). 'auto' prefers client_secret_basic, the
            // Discovery default when nothing is advertised; set tokenAuthMethod when the
            // provider enforces the method registered for the app (Okta, Keycloak, Auth0 can).
            $method = (string) $provider->option('tokenAuthMethod', 'auto');
            if ($method === 'auto') {
                $methods = (array) ($doc['token_endpoint_auth_methods_supported'] ?? ['client_secret_basic']);
                $method  = in_array('client_secret_basic', $methods, true) || ! in_array('client_secret_post', $methods, true)
                    ? 'client_secret_basic' : 'client_secret_post';
            }
            if ($method === 'client_secret_basic') {
                // RFC 6749 2.3.1 form-encodes id and secret before Base64. rawurlencode decodes
                // to the same bytes under form decoding, and leaves "-._~" (common in Entra
                // secrets) literal, which also suits servers that don't decode at all.
                $headers['Authorization'] = 'Basic ' . base64_encode(rawurlencode($provider->clientId) . ':' . rawurlencode($provider->clientSecret));
            } else {
                $form['client_secret'] = $provider->clientSecret;
            }
        }

        try {
            $res = $this->http->post((string) $doc['token_endpoint'], $form, $headers);
        } catch (Throwable $e) {
            throw OidcException::config('Token request failed: ' . $e->getMessage(), $e);
        }
        $body = json_decode($res['body'], true);
        if ($res['status'] !== 200 || ! is_array($body) || ! is_string($body['id_token'] ?? null) || $body['id_token'] === '') {
            $err = is_array($body) ? trim(self::clean($body['error'] ?? '', 64) . ' ' . self::clean($body['error_description'] ?? '', 300)) : '';

            throw OidcException::token('Token endpoint returned HTTP ' . $res['status'] . ($err !== '' ? ': ' . $err : ' without an id_token') . '.');
        }

        return $body;
    }

    /**
     * Claims from the userinfo endpoint, or [] if it's unavailable or answers for a different
     * subject (OIDC Core 5.3.2). Failures here never fail the sign-in; the caller merges the
     * result under the ID token's claims, so it can only add, never override.
     *
     * @return array<string, mixed>
     */
    protected function userinfo(string $endpoint, string $accessToken, string $sub): array
    {
        try {
            $res  = $this->http->get($endpoint, ['Authorization' => 'Bearer ' . $accessToken]);
            $info = json_decode($res['body'], true);
        } catch (Throwable $e) {
            log_message('warning', 'Shield OIDC: userinfo request failed: {m}', ['m' => $e->getMessage()]);

            return [];
        }
        if ($res['status'] !== 200 || ! is_array($info) || ($info['sub'] ?? null) !== $sub) {
            return [];
        }

        return $info;
    }

    /* ------------------------------------------------------------------ logout */

    /**
     * URL that ends the session at the provider (OIDC RP-Initiated Logout), or null when the
     * provider has no end_session_endpoint. The provider sends the browser on to
     * $postLogoutUri, which must be registered with it.
     *
     * @param string|null $idToken The ID token from sign-in, sent as id_token_hint when available
     */
    public function endSessionUrl(Provider $provider, ?string $idToken, string $postLogoutUri, ?string $logoutHint = null): ?string
    {
        $doc      = $this->discovery($provider);
        $endpoint = $doc['end_session_endpoint'] ?? null;
        if (! is_string($endpoint) || $endpoint === '') {
            return null;
        }
        $params = ['client_id' => $provider->clientId, 'post_logout_redirect_uri' => $postLogoutUri];
        if ($provider->type === 'entra') {
            // Entra documents post_logout_redirect_uri and logout_hint (from the login_hint
            // optional claim), not id_token_hint; don't put the ID token in a URL for nothing.
            if ($logoutHint !== null && $logoutHint !== '') {
                $params['logout_hint'] = $logoutHint;
            }
        } elseif ($idToken !== null && $idToken !== '') {
            // RECOMMENDED by RP-Initiated Logout 1.0, and required by Okta.
            $params['id_token_hint'] = $idToken;
        }

        return $endpoint . (str_contains($endpoint, '?') ? '&' : '?') . http_build_query($params, '', '&', PHP_QUERY_RFC3986);
    }

    /* ------------------------------------------------------------------ issuer rules */

    /**
     * Is the issuer in the discovery document the one this provider should have?
     * (OIDC Discovery 4.3: identical to the issuer the URL was built from.) The configured
     * issuer may omit or add one trailing slash, since the discovery URL is the same either
     * way (Discovery 4.1); the exact document issuer is what ID tokens are compared against.
     */
    protected function discoveryIssuerOk(Provider $provider, string $docIssuer): bool
    {
        if ($provider->type !== 'entra') {
            $ok = rtrim($docIssuer, '/') === $provider->issuer;
            if ($ok && $docIssuer !== (string) $provider->option('issuer')) {
                log_message('info', 'Shield OIDC: provider {p} issuer is "{d}"; configure it exactly like that.', ['p' => $provider->key, 'd' => $docIssuer]);
            }

            return $ok;
        }
        $base = preg_quote($this->entraAuthority($provider), '#');
        $guid = '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}';
        if (! preg_match('#^' . $base . '/(\{tenantid\}|' . $guid . ')/v2\.0$#i', $docIssuer, $m)) {
            return false;
        }
        if ($provider->isEntraMultiTenant()) {
            // common/organizations publish the template https://login.microsoftonline.com/{tenantid}/v2.0;
            // consumers publishes the personal-accounts tenant id.
            return strtolower($provider->tenant) !== 'consumers' || strtolower($m[1]) === Provider::ENTRA_CONSUMERS_TID;
        }
        // Single tenant: a tenant configured by domain resolves to its id; one configured by id
        // must resolve to that same id.
        $pinned = $provider->tenantGuid();

        return $m[1] !== '{tenantid}' && ($pinned === null || strtolower($m[1]) === $pinned);
    }

    /**
     * Is $iss (from the ID token, or the callback's iss parameter when $claims is null) acceptable?
     *
     * @param array<string, mixed>      $doc
     * @param array<string, mixed>|null $claims
     */
    protected function tokenIssuerOk(Provider $provider, array $doc, string $iss, ?array $claims): bool
    {
        if ($provider->type !== 'entra' || ! $provider->isEntraMultiTenant()) {
            // Exact match (RFC 9207 2.4, OIDC Core 3.1.3.7). Google documents its ID token iss
            // as either form, with or without the scheme; its redirect iss always has it.
            return $iss === (string) $doc['issuer']
                || ($claims !== null && $provider->isGoogle() && $iss === 'accounts.google.com');
        }

        // Multi-tenant Entra: iss must be the authority + the token's own tenant id (Microsoft's
        // documented rule: substitute the token's tid into the {tenantid} template).
        $guid = '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}';
        if (! preg_match('#^' . preg_quote($this->entraAuthority($provider), '#') . '/(' . $guid . ')/v2\.0$#i', $iss, $m)) {
            return false;
        }
        $tid = strtolower($m[1]);
        if ($claims !== null && strtolower((string) ($claims['tid'] ?? '')) !== $tid) {
            return false;
        }
        $tenant = strtolower($provider->tenant);
        if ($tenant === 'organizations' && $tid === Provider::ENTRA_CONSUMERS_TID) {
            return false;
        }
        if ($tenant === 'consumers' && $tid !== Provider::ENTRA_CONSUMERS_TID) {
            return false;
        }

        return $provider->allowedTenants === [] || in_array($tid, $provider->allowedTenants, true);
    }

    private function entraAuthority(Provider $provider): string
    {
        return rtrim((string) $provider->option('authority', 'https://login.microsoftonline.com'), '/');
    }

    /**
     * Signing algorithms to accept: the provider's 'algorithms' option, limited to what this
     * package can verify and to what the provider advertises. Never widened: if nothing is
     * left, that's a configuration error rather than a silent fallback.
     *
     * @param array<string, mixed> $doc
     *
     * @return list<string>
     */
    protected function allowedAlgs(Provider $provider, array $doc): array
    {
        $configured = array_intersect((array) $provider->option('algorithms', ['RS256']), IdTokenVerifier::supportedAlgs());
        $wanted     = isset($doc['id_token_signing_alg_values_supported'])
            ? array_intersect($configured, (array) $doc['id_token_signing_alg_values_supported'])
            : $configured;
        if ($wanted === []) {
            // Never fall back to something the configuration didn't allow.
            throw OidcException::config('No usable ID token algorithm: the provider offers '
                . implode(', ', (array) ($doc['id_token_signing_alg_values_supported'] ?? [])) . '; allowed here: ' . implode(', ', $configured) . '.');
        }

        return array_values($wanted);
    }

    /** A provider-supplied value made safe for a log line: a short, single-line string. */
    private static function clean(mixed $value, int $max): string
    {
        $value = is_scalar($value) ? (string) $value : '';
        $value = (string) preg_replace('/[\x00-\x1f\x7f]+/', ' ', $value);

        return mb_strlen($value) > $max ? mb_substr($value, 0, $max) . '…' : $value;
    }

    /* ------------------------------------------------------------------ helpers */

    /**
     * A local path to return to after sign-in, or null. Only "/something" is accepted: no
     * scheme, no protocol-relative "//host", no backslashes or control characters, nothing
     * over 2000 characters. The path is later resolved with site_url(), so it's relative to
     * app.baseURL and can't leave the site.
     */
    public static function safeReturnPath(?string $path): ?string
    {
        if ($path === null || $path === '' || $path[0] !== '/' || str_starts_with($path, '//') || str_starts_with($path, '/\\')
            || preg_match('/[\x00-\x1f\x7f\\\\]/', $path) || strlen($path) > 2000) {
            return null;
        }

        return $path;
    }

    /**
     * Sign-ins in progress from the session. Expired ones are kept for an extra hour so the
     * person gets "took too long" rather than "not valid", then dropped.
     *
     * @return array<string, array<string, mixed>>
     */
    private function pending(): array
    {
        $pending = $this->session->get(self::SESSION_KEY);
        if (! is_array($pending)) {
            return [];
        }
        $now = time();

        return array_filter($pending, static fn ($f) => is_array($f) && ($f['expires'] ?? 0) >= $now - 3600);
    }

    /**
     * GET a JSON document from the provider. $what names it in error messages.
     *
     * @return array<string, mixed>
     */
    private function getJson(string $url, string $what): array
    {
        try {
            $res = $this->http->get($url);
        } catch (Throwable $e) {
            throw OidcException::config('Could not fetch the ' . $what . ' from ' . $url . ': ' . $e->getMessage(), $e);
        }
        $data = json_decode($res['body'], true);
        if ($res['status'] !== 200 || ! is_array($data)) {
            throw OidcException::config('Could not read the ' . $what . ' from ' . $url . ' (HTTP ' . $res['status'] . ').');
        }

        return $data;
    }

    /**
     * Provider URLs must be https. Plain http is allowed only for localhost and only with
     * $allowLocalHttp, for a provider running on a developer's machine.
     */
    private function assertUrl(string $url, string $what): void
    {
        $parts = parse_url($url);
        $host  = strtolower((string) ($parts['host'] ?? ''));
        $local = in_array($host, ['localhost', '127.0.0.1', '[::1]', '::1'], true) || str_ends_with($host, '.localhost');
        $ok    = ($parts['scheme'] ?? '') === 'https' || (($parts['scheme'] ?? '') === 'http' && $local && $this->config->allowLocalHttp);
        if (! $ok || $host === '') {
            throw OidcException::config('The provider ' . $what . ' must be an https URL (got "' . $url . '").');
        }
    }

    /**
     * The last good copy of a document when the provider can't be reached, or the original
     * error when there is none. Keeps sign-in working through a short provider outage after
     * the normal cache expired (Microsoft's key rollover guidance recommends exactly this).
     *
     * @return array<string, mixed>
     *
     * @throws OidcException
     */
    private function lastKnownGood(string $cacheKey, OidcException $e): array
    {
        $lkg = $this->cacheGet($cacheKey . '_lkg');
        if (! is_array($lkg)) {
            throw $e;
        }
        log_message('warning', 'Shield OIDC: {d} Using the last good copy.', ['d' => $e->getDetail()]);

        return $lkg;
    }

    /** Cache reads and writes never fail a sign-in: without a cache we simply fetch again. */
    private function cacheGet(string $key): mixed
    {
        try {
            return $this->cache->get($key);
        } catch (Throwable) {
            return null;
        }
    }

    private function cacheSave(string $key, array|int $value, ?int $ttl = null): void
    {
        try {
            $this->cache->save($key, $value, $ttl ?? $this->config->cacheTtl);
        } catch (Throwable) {
            // No cache: we'll just fetch again next time.
        }
    }
}
