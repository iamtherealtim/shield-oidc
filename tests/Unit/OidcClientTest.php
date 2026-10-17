<?php

declare(strict_types=1);

namespace Tests\Unit;

use CodeIgniter\Test\CIUnitTestCase;
use CodeIgniter\Test\Mock\MockCache;
use DaemonLabs\ShieldOidc\Config\ShieldOidc;
use DaemonLabs\ShieldOidc\Exceptions\OidcException;
use DaemonLabs\ShieldOidc\OidcClient;
use DaemonLabs\ShieldOidc\Provider;
use Tests\Support\FakeProvider;

/**
 * @internal
 */
final class OidcClientTest extends CIUnitTestCase
{
    private FakeProvider $idp;
    private ShieldOidc $config;
    private OidcClient $client;

    protected function setUp(): void
    {
        parent::setUp();
        $this->idp    = new FakeProvider();
        $this->config = new ShieldOidc();
        $this->config->providers = [
            'fake' => ['issuer' => $this->idp->issuer, 'clientId' => 'client-123', 'clientSecret' => 's3cret'],
        ];
        $this->client = $this->makeClient();
    }

    private function makeClient(?FakeProvider $idp = null): OidcClient
    {
        return new OidcClient($this->config, $idp ?? $this->idp, new MockCache(), service('session'));
    }

    private function provider(string $key = 'fake'): Provider
    {
        return Provider::fromConfig($key, $this->config);
    }

    /** Runs a full sign-in and returns the callback result. */
    private function signIn(array $claims = [], string $key = 'fake', array $extraQuery = []): array
    {
        $p = $this->provider($key);
        $q = $this->idp->sawAuthorizationUrl($this->client->authorizationUrl($p, '/dashboard'));
        $this->idp->claims = $claims + $this->idp->baseClaims($p->clientId);

        return $this->client->handleCallback($p, ['code' => 'abc', 'state' => $q['state']] + $extraQuery);
    }

    private function assertFailsWith(string $needle, callable $fn): void
    {
        try {
            $fn();
            $this->fail('Expected failure: ' . $needle);
        } catch (OidcException $e) {
            $this->assertStringContainsStringIgnoringCase($needle, $e->getDetail() . ' ' . $e->getMessage());
        }
    }

    public function testAuthorizationUrlHasPkceStateNonceAndScopes(): void
    {
        $url = $this->client->authorizationUrl($this->provider());
        $this->assertStringStartsWith($this->idp->issuer . '/authorize?', $url);
        parse_str((string) parse_url($url, PHP_URL_QUERY), $q);

        $this->assertSame('code', $q['response_type']);
        $this->assertSame('client-123', $q['client_id']);
        $this->assertSame('https://app.example.test/oidc/fake/callback', $q['redirect_uri']);
        $this->assertSame('openid profile email', $q['scope']);
        $this->assertSame('S256', $q['code_challenge_method']);
        $this->assertGreaterThanOrEqual(43, strlen($q['state']));
        $this->assertGreaterThanOrEqual(43, strlen($q['nonce']));
        $this->assertMatchesRegularExpression('/^[A-Za-z0-9_-]{43}$/', $q['code_challenge']);
    }

    public function testAuthParamsCannotSetSecurityParameters(): void
    {
        foreach (['state', 'nonce', 'redirect_uri', 'response_mode', 'code_challenge_method'] as $reserved) {
            $this->config->providers['fake']['authParams'] = [$reserved => 'x'];
            $this->assertFailsWith('may not set ' . $reserved, fn () => $this->provider());
        }
        $this->config->providers['fake']['authParams'] = ['prompt' => 'select_account'];
        parse_str((string) parse_url($this->client->authorizationUrl($this->provider()), PHP_URL_QUERY), $q);
        $this->assertSame('select_account', $q['prompt']);
    }

    public function testFullSignInReturnsVerifiedClaims(): void
    {
        $result = $this->signIn(['email' => 'pat@example.com']);
        $this->assertSame('user-1', $result['claims']['sub']);
        $this->assertSame('pat@example.com', $result['claims']['email']);
        $this->assertSame('/dashboard', $result['return']);
        $this->assertNotEmpty($result['idToken']);
    }

    public function testTokenRequestSendsVerifierAndOneClientAuthMethod(): void
    {
        $this->signIn();
        $req = $this->idp->requestsTo('/token')[0];
        $this->assertSame('authorization_code', $req['form']['grant_type']);
        $this->assertSame('abc', $req['form']['code']);
        $this->assertMatchesRegularExpression('/^[A-Za-z0-9_-]{64}$/', $req['form']['code_verifier']);
        $this->assertSame('Basic ' . base64_encode('client-123:s3cret'), $req['headers']['Authorization']);
        $this->assertArrayNotHasKey('client_secret', $req['form']);
    }

    public function testUsesClientSecretPostWhenThatsAllTheProviderSupports(): void
    {
        $this->idp->discoveryOverrides['token_endpoint_auth_methods_supported'] = ['client_secret_post'];
        $this->signIn();
        $req = $this->idp->requestsTo('/token')[0];
        $this->assertSame('s3cret', $req['form']['client_secret']);
        $this->assertArrayNotHasKey('Authorization', $req['headers']);
    }

    public function testCodeVerifierMatchesChallenge(): void
    {
        $url = $this->client->authorizationUrl($this->provider());
        $q   = $this->idp->sawAuthorizationUrl($url);
        $this->idp->claims = $this->idp->baseClaims();
        $this->client->handleCallback($this->provider(), ['code' => 'abc', 'state' => $q['state']]);
        $verifier = $this->idp->requestsTo('/token')[0]['form']['code_verifier'];
        $this->assertSame($q['code_challenge'], rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '='));
    }

    public function testStateIsSingleUse(): void
    {
        $p = $this->provider();
        $q = $this->idp->sawAuthorizationUrl($this->client->authorizationUrl($p));
        $this->idp->claims = $this->idp->baseClaims();
        $this->client->handleCallback($p, ['code' => 'abc', 'state' => $q['state']]);
        $this->assertFailsWith('state', fn () => $this->client->handleCallback($p, ['code' => 'abc', 'state' => $q['state']]));
    }

    public function testRejectsUnknownState(): void
    {
        $this->client->authorizationUrl($this->provider());
        $this->assertFailsWith('state', fn () => $this->client->handleCallback($this->provider(), ['code' => 'abc', 'state' => 'forged']));
        $this->assertCount(0, $this->idp->requestsTo('/token'), 'no code exchange without valid state');
    }

    public function testStateFromAnotherProviderIsRejected(): void
    {
        $this->config->providers['other'] = ['issuer' => $this->idp->issuer, 'clientId' => 'client-123'];
        $q = $this->idp->sawAuthorizationUrl($this->client->authorizationUrl($this->provider('other')));
        $this->assertFailsWith('state', fn () => $this->client->handleCallback($this->provider('fake'), ['code' => 'abc', 'state' => $q['state']]));
    }

    public function testExpiredState(): void
    {
        $this->config->stateTtl = -1;
        $q = $this->idp->sawAuthorizationUrl($this->client->authorizationUrl($this->provider()));
        $this->assertFailsWith('too long', fn () => $this->client->handleCallback($this->provider(), ['code' => 'abc', 'state' => $q['state']]));
    }

    public function testProviderErrorIsReported(): void
    {
        $q = $this->idp->sawAuthorizationUrl($this->client->authorizationUrl($this->provider()));
        $this->assertFailsWith('cancelled', fn () => $this->client->handleCallback($this->provider(), ['error' => 'access_denied', 'state' => $q['state']]));
    }

    public function testNonceFromAnotherSignInIsRejected(): void
    {
        $p = $this->provider();
        $q = $this->idp->sawAuthorizationUrl($this->client->authorizationUrl($p));
        $this->idp->nonce  = 'replayed-nonce';
        $this->idp->claims = $this->idp->baseClaims();
        $this->assertFailsWith('nonce', fn () => $this->client->handleCallback($p, ['code' => 'abc', 'state' => $q['state']]));
    }

    public function testIssParameterMixUpDefence(): void
    {
        $this->assertFailsWith('mix-up', fn () => $this->signIn([], 'fake', ['iss' => 'https://evil.example']));
        $this->assertSame('user-1', $this->signIn([], 'fake', ['iss' => $this->idp->issuer])['claims']['sub']);
    }

    public function testTokenEndpointErrorIsReported(): void
    {
        $this->idp->tokenResponse = ['status' => 400, 'body' => '{"error":"invalid_grant","error_description":"Code expired"}'];
        $this->assertFailsWith('invalid_grant', fn () => $this->signIn());
    }

    public function testUserinfoFillsGapsButCannotOverrideTokenClaims(): void
    {
        $this->idp->userinfo = ['sub' => 'user-1', 'email' => 'other@example.com', 'name' => 'Pat'];
        $claims = $this->signIn(['email' => 'pat@example.com'])['claims'];
        $this->assertSame('pat@example.com', $claims['email']);
        $this->assertSame('Pat', $claims['name']);
    }

    public function testUserinfoForAnotherSubjectIsIgnored(): void
    {
        $this->idp->userinfo = ['sub' => 'someone-else', 'email' => 'victim@example.com'];
        $this->assertArrayNotHasKey('email', $this->signIn()['claims']);
    }

    public function testDiscoveryIssuerMustMatch(): void
    {
        $this->idp->discoveryOverrides['issuer'] = 'https://evil.example';
        $this->assertFailsWith('does not match', fn () => $this->client->discovery($this->provider()));
    }

    public function testEndpointsMustBeHttps(): void
    {
        $this->idp->discoveryOverrides['token_endpoint'] = 'http://idp.example.test/token';
        $this->assertFailsWith('https', fn () => $this->client->discovery($this->provider()));
    }

    public function testPlainHttpIssuerOnlyForLocalhostWhenAllowed(): void
    {
        $local = new FakeProvider('http://localhost:9000');
        $this->config->providers['local'] = ['issuer' => 'http://localhost:9000', 'clientId' => 'c'];
        $client = $this->makeClient($local);
        $this->assertFailsWith('https', fn () => $client->discovery($this->provider('local')));
        $this->config->allowLocalHttp = true;
        $this->assertSame('http://localhost:9000', $client->discovery($this->provider('local'))['issuer']);

        $this->config->providers['remote'] = ['issuer' => 'http://idp.example.test', 'clientId' => 'c'];
        $this->assertFailsWith('https', fn () => $client->discovery($this->provider('remote')));
    }

    public function testDiscoveryAndKeysAreCached(): void
    {
        $this->signIn();
        $this->signIn();
        $this->assertCount(1, $this->idp->requestsTo('/openid-configuration'));
        $this->assertCount(1, $this->idp->requestsTo('/jwks'));
    }

    public function testSafeReturnPath(): void
    {
        foreach (['/dashboard', '/a/b?c=1#d'] as $ok) {
            $this->assertSame($ok, OidcClient::safeReturnPath($ok));
        }
        foreach (['https://evil.example', '//evil.example', '/\\evil.example', "/\nSet-Cookie:x", 'javascript:alert(1)', 'relative', ''] as $bad) {
            $this->assertNull(OidcClient::safeReturnPath($bad), $bad);
        }
    }

    public function testEndSessionUrl(): void
    {
        $url = $this->client->endSessionUrl($this->provider(), 'the-id-token', 'https://app.example.test/');
        $this->assertStringStartsWith($this->idp->issuer . '/logout?', $url);
        $this->assertStringContainsString('id_token_hint=the-id-token', $url);
        $this->assertStringContainsString('post_logout_redirect_uri=' . rawurlencode('https://app.example.test/'), $url);
    }

    /* ---------------- Microsoft Entra ---------------- */

    private const TENANT_A = '11111111-1111-1111-1111-111111111111';
    private const TENANT_B = '22222222-2222-2222-2222-222222222222';

    /** Points a fake at login.microsoftonline.com the way Entra publishes it. */
    private function entra(string $tenant, array $extra = []): FakeProvider
    {
        $idp = new FakeProvider('https://login.microsoftonline.com/' . $tenant . '/v2.0');
        $multi = in_array($tenant, Provider::ENTRA_MULTI, true);
        $idp->discoveryOverrides['issuer'] = $multi
            ? 'https://login.microsoftonline.com/{tenantid}/v2.0'
            : 'https://login.microsoftonline.com/' . self::TENANT_A . '/v2.0';
        $this->config->providers['ms'] = ['type' => 'entra', 'tenant' => $tenant, 'clientId' => 'app-id'] + $extra;
        $this->idp    = $idp;
        $this->client = $this->makeClient($idp);

        return $idp;
    }

    private function entraClaims(string $tid): array
    {
        return ['iss' => 'https://login.microsoftonline.com/' . $tid . '/v2.0', 'tid' => $tid, 'oid' => 'object-1', 'aud' => 'app-id'];
    }

    public function testEntraSingleTenantByDomain(): void
    {
        $this->entra('contoso.onmicrosoft.com');
        $this->assertSame('object-1', $this->signIn($this->entraClaims(self::TENANT_A), 'ms')['claims']['oid']);
    }

    public function testEntraSingleTenantRejectsOtherTenant(): void
    {
        $this->entra(self::TENANT_A);
        $this->assertFailsWith('issuer', fn () => $this->signIn($this->entraClaims(self::TENANT_B), 'ms'));
    }

    public function testEntraOrganizationsAcceptsAnyWorkTenant(): void
    {
        $this->entra('organizations');
        $this->assertSame(self::TENANT_B, $this->signIn($this->entraClaims(self::TENANT_B), 'ms')['claims']['tid']);
    }

    public function testEntraOrganizationsRejectsPersonalAccounts(): void
    {
        $this->entra('organizations');
        $this->assertFailsWith('issuer', fn () => $this->signIn($this->entraClaims(Provider::ENTRA_CONSUMERS_TID), 'ms'));
    }

    public function testEntraMultiTenantIssAndTidMustAgree(): void
    {
        $this->entra('organizations');
        $claims = ['tid' => self::TENANT_B] + $this->entraClaims(self::TENANT_A);
        $this->assertFailsWith('issuer', fn () => $this->signIn($claims, 'ms'));
    }

    public function testEntraAllowedTenants(): void
    {
        $this->entra('organizations', ['allowedTenants' => [self::TENANT_A]]);
        $this->assertSame(self::TENANT_A, $this->signIn($this->entraClaims(self::TENANT_A), 'ms')['claims']['tid']);
        $this->assertFailsWith('issuer', fn () => $this->signIn($this->entraClaims(self::TENANT_B), 'ms'));
    }

    public function testEntraIssuerFromAnotherAuthorityIsRejected(): void
    {
        $this->entra('organizations');
        $claims = ['iss' => 'https://login.evil.example/' . self::TENANT_A . '/v2.0'] + $this->entraClaims(self::TENANT_A);
        $this->assertFailsWith('issuer', fn () => $this->signIn($claims, 'ms'));
    }

    /* ---------------- audit regressions ---------------- */

    public function testConfiguredAlgorithmsAreNeverWidened(): void
    {
        $this->config->providers['fake']['algorithms'] = ['ES256'];
        $this->idp->discoveryOverrides['id_token_signing_alg_values_supported'] = ['RS256'];
        $this->assertFailsWith('no usable', fn () => $this->signIn());
    }

    public function testOddDiscoveryListsDontCrash(): void
    {
        $this->idp->discoveryOverrides['id_token_signing_alg_values_supported'] = ['RS256', ['x'], 7];
        $this->idp->discoveryOverrides['token_endpoint_auth_methods_supported'] = 'client_secret_basic';
        $this->assertSame('user-1', $this->signIn()['claims']['sub']);
    }

    public function testNonStringEndpointIsAConfigError(): void
    {
        $this->idp->discoveryOverrides['userinfo_endpoint'] = ['https://idp.example.test/userinfo'];
        $this->assertFailsWith('not a URL', fn () => $this->client->discovery($this->provider()));
    }

    public function testMalformedTokenErrorIsAClearFailure(): void
    {
        $this->idp->tokenResponse = ['status' => 400, 'body' => '{"error":["invalid_grant"],"error_description":{"x":1}}'];
        $this->assertFailsWith('HTTP 400', fn () => $this->signIn());
    }

    public function testForcedKeyRefetchIsThrottled(): void
    {
        $cache        = new MockCache();
        $this->client = new OidcClient($this->config, $this->idp, $cache, service('session'));
        $this->idp->kid = 'unknown-kid'; // signed with rsa-1 but under a kid the provider never published
        $this->assertFailsWith('signature', fn () => $this->signIn());
        $this->assertFailsWith('signature', fn () => $this->signIn());
        $this->assertFailsWith('signature', fn () => $this->signIn());
        $this->assertCount(1, $this->idp->requestsTo('/jwks'), 'keys fetched moments ago are not refetched');

        // A minute later, an unknown kid does trigger one refetch (key rotation).
        $cache->save('shieldoidc_jwks_' . md5($this->idp->issuer . '/jwks') . '_at', time() - 301);
        $this->assertFailsWith('signature', fn () => $this->signIn());
        $this->assertFailsWith('signature', fn () => $this->signIn());
        $this->assertCount(2, $this->idp->requestsTo('/jwks'));
    }

    public function testRotatedKeyIsPickedUp(): void
    {
        $cache        = new MockCache();
        $this->client = new OidcClient($this->config, $this->idp, $cache, service('session'));
        // Yesterday the provider published only rsa-2, and we cached that.
        $this->idp->published = [FakeProvider::keys()['rsa-2'][1]];
        $this->client->jwks($this->client->discovery($this->provider()));
        $cache->save('shieldoidc_jwks_' . md5($this->idp->issuer . '/jwks') . '_at', time() - 3600);

        // Today it signs with the new rsa-1.
        $this->idp->published = [FakeProvider::keys()['rsa-2'][1], FakeProvider::keys()['rsa-1'][1]];
        $this->assertSame('user-1', $this->signIn()['claims']['sub']);
        $this->assertCount(2, $this->idp->requestsTo('/jwks'));
    }

    public function testProviderErrorWithForgedStateIsNotReported(): void
    {
        $this->client->authorizationUrl($this->provider());
        try {
            $this->client->handleCallback($this->provider(), ['state' => 'forged', 'error' => 'server_error', 'error_description' => "fake\nERROR - injected log line"]);
            $this->fail('should fail');
        } catch (OidcException $e) {
            $this->assertSame(lang('Oidc.stateInvalid'), $e->getMessage());
            $this->assertStringNotContainsString('injected', $e->getDetail());
        }
    }

    public function testProviderErrorTextIsFlattenedForLogs(): void
    {
        $q = $this->idp->sawAuthorizationUrl($this->client->authorizationUrl($this->provider()));
        try {
            $this->client->handleCallback($this->provider(), ['state' => $q['state'], 'error' => 'server_error', 'error_description' => "a\nb\r\nc" . str_repeat('x', 1000)]);
            $this->fail('should fail');
        } catch (OidcException $e) {
            $this->assertStringNotContainsString("\n", $e->getDetail());
            $this->assertLessThan(450, strlen($e->getDetail()));
        }
    }

    public function testIssParameterRequiredWhenProviderAdvertisesIt(): void
    {
        $this->idp->discoveryOverrides['authorization_response_iss_parameter_supported'] = true;
        $this->assertFailsWith('no iss parameter', fn () => $this->signIn());
        $this->assertSame('user-1', $this->signIn([], 'fake', ['iss' => $this->idp->issuer])['claims']['sub']);
    }

    public function testLinkingForcesAFreshProviderLogin(): void
    {
        parse_str((string) parse_url($this->client->authorizationUrl($this->provider(), null, 42), PHP_URL_QUERY), $q);
        $this->assertSame('login', $q['prompt']);
        $this->assertSame('0', $q['max_age']);
        $this->config->providers['fake']['authParams'] = ['prompt' => 'none'];
        parse_str((string) parse_url($this->client->authorizationUrl($this->provider(), null, 42), PHP_URL_QUERY), $q);
        $this->assertSame('login', $q['prompt'], 'authParams cannot weaken linking');
    }

    /** Linking: a provider that reports an old sign-in (it ignored prompt=login) can't link. */
    public function testLinkingRejectsStaleAuthTime(): void
    {
        $link = function (array $claims): array {
            $q = $this->idp->sawAuthorizationUrl($this->client->authorizationUrl($this->provider(), null, 42));
            $this->idp->claims = $claims + $this->idp->baseClaims();

            return $this->client->handleCallback($this->provider(), ['code' => 'abc', 'state' => $q['state']]);
        };
        $this->assertSame(42, $link(['auth_time' => time()])['link']);
        // max_age obliges the provider to send auth_time (OIDC Core 3.1.2.1): missing = failure...
        $this->assertFailsWith('no auth_time', fn () => $link([]));
        // ...unless the provider is configured not to (Entra and Google are, by default).
        $this->config->providers['fake']['requireAuthTime'] = false;
        $this->assertSame(42, $link([])['link']);
        $this->assertFailsWith('fresh', fn () => $link(['auth_time' => time() - 3600]));
        $this->assertFailsWith('fresh', fn () => $link(['auth_time' => 'yesterday']));
        // Ordinary sign-ins don't care how old the provider session is.
        $this->assertSame('user-1', $this->signIn(['auth_time' => time() - 86400])['claims']['sub']);
    }

    public function testGoogleSchemelessIssuer(): void
    {
        $google = new FakeProvider('https://accounts.google.com');
        $this->config->providers['google'] = ['issuer' => 'https://accounts.google.com', 'clientId' => 'client-123'];
        $this->idp    = $google;
        $this->client = $this->makeClient($google);
        $this->assertSame('user-1', $this->signIn(['iss' => 'accounts.google.com'], 'google')['claims']['sub']);
    }

    public function testPartialDefaultsKeepPackageDefaults(): void
    {
        $this->config->defaults = ['label' => 'Company SSO'];
        $p = $this->provider();
        $this->assertSame(['openid', 'profile', 'email'], $p->scopes());
        $this->assertSame('verified', $p->linkByEmail());
        $this->assertSame('Company SSO', $p->label);
    }

    public function testUnknownOrMistypedSettingsFailClosed(): void
    {
        $this->config->providers['fake']['allowedTenant'] = ['x'];
        $this->assertFailsWith('unknown setting "allowedTenant"', fn () => $this->provider());
        unset($this->config->providers['fake']['allowedTenant']);
        $this->config->providers['fake']['register'] = 'no';
        $this->assertFailsWith('"register" must be a bool', fn () => $this->provider());
        $this->config->providers['fake']['register'] = false;
        $this->config->providers['fake']['allowedDomains'] = 'example.com';
        $this->assertFailsWith('list of strings', fn () => $this->provider());
        $this->config->providers['fake']['allowedDomains'] = ['example.com'];
        $this->config->providers['fake']['linkByEmail'] = 'yes';
        $this->assertFailsWith('linkByEmail must be', fn () => $this->provider());
    }

    /* ---------------- provider conformance (each from that provider's docs) ---------------- */

    /** Entra documents prompt=login but not max_age, and sends no auth_time by default. */
    public function testEntraLinkingUsesPromptLoginOnly(): void
    {
        $this->entra(self::TENANT_A);
        parse_str((string) parse_url($this->client->authorizationUrl($this->provider('ms'), null, 42), PHP_URL_QUERY), $q);
        $this->assertSame('login', $q['prompt']);
        $this->assertArrayNotHasKey('max_age', $q);
        $q = $this->idp->sawAuthorizationUrl($this->client->authorizationUrl($this->provider('ms'), null, 42));
        $this->idp->claims = $this->entraClaims(self::TENANT_A) + $this->idp->baseClaims('app-id');
        $this->assertSame(42, $this->client->handleCallback($this->provider('ms'), ['code' => 'c', 'state' => $q['state']])['link']);
    }

    /** Google lists prompt=none/consent/select_account only; linking shows the account picker. */
    public function testGoogleLinkingUsesSelectAccount(): void
    {
        $this->config->providers['google'] = ['issuer' => 'https://accounts.google.com', 'clientId' => 'g'];
        $this->client = $this->makeClient(new FakeProvider('https://accounts.google.com'));
        parse_str((string) parse_url($this->client->authorizationUrl($this->provider('google'), null, 42), PHP_URL_QUERY), $q);
        $this->assertSame('select_account', $q['prompt']);
        $this->assertArrayNotHasKey('max_age', $q);
        $this->assertFalse($this->provider('google')->requireAuthTime());
    }

    public function testGoogleSchemelessIssuerOnlyInIdTokens(): void
    {
        $google = new FakeProvider('https://accounts.google.com');
        $this->config->providers['google'] = ['issuer' => 'https://accounts.google.com', 'clientId' => 'client-123'];
        $this->idp    = $google;
        $this->client = $this->makeClient($google);
        // RFC 9207: the redirect's iss is compared exactly; Google always sends the https form.
        $this->assertFailsWith('mix-up', fn () => $this->signIn([], 'google', ['iss' => 'accounts.google.com']));
    }

    public function testEntraPinnedTenantIdMustMatchDiscovery(): void
    {
        $this->entra(self::TENANT_B); // discovery (as faked) answers with TENANT_A's issuer
        $this->assertFailsWith('does not match', fn () => $this->client->discovery($this->provider('ms')));
    }

    public function testEntraLogoutUsesLogoutHintNotIdToken(): void
    {
        $this->entra(self::TENANT_A);
        $url = (string) $this->client->endSessionUrl($this->provider('ms'), 'secret.id.token', 'https://app.example.test/', 'hint-123');
        $this->assertStringContainsString('logout_hint=hint-123', $url);
        $this->assertStringNotContainsString('id_token_hint', $url);
    }

    public function testUserinfoNeedsBearerTokenType(): void
    {
        $this->idp->userinfo = ['sub' => 'user-1', 'name' => 'Pat'];
        $p = $this->provider();
        // Token response with a non-Bearer type: userinfo must not be called.
        $q = $this->idp->sawAuthorizationUrl($this->client->authorizationUrl($p));
        $this->idp->tokenResponse = ['status' => 200, 'body' => (string) json_encode([
            'access_token' => 'at', 'token_type' => 'DPoP', 'id_token' => $this->idp->sign($this->idp->baseClaims() + ['nonce' => $this->idp->nonce]),
        ])];
        $claims = $this->client->handleCallback($p, ['code' => 'c', 'state' => $q['state']])['claims'];
        $this->assertArrayNotHasKey('name', $claims);
        $this->assertCount(0, $this->idp->requestsTo('/userinfo'));
        // "bearer" in any case is fine (the type is case-insensitive).
        $q = $this->idp->sawAuthorizationUrl($this->client->authorizationUrl($p));
        $this->idp->tokenResponse = ['status' => 200, 'body' => (string) json_encode([
            'access_token' => 'at', 'token_type' => 'bearer', 'id_token' => $this->idp->sign($this->idp->baseClaims() + ['nonce' => $this->idp->nonce]),
        ])];
        $this->assertSame('Pat', $this->client->handleCallback($p, ['code' => 'c', 'state' => $q['state']])['claims']['name']);
    }

    /** An email's verified flag must come from the same place as the email itself. */
    public function testUserinfoEmailFlagsStayWithTheirEmail(): void
    {
        $merged = OidcClient::mergeUserinfo(['sub' => 's', 'email' => 'a@example.com'], ['sub' => 's', 'email' => 'b@example.com', 'email_verified' => true, 'name' => 'Pat']);
        $this->assertSame('a@example.com', $merged['email']);
        $this->assertArrayNotHasKey('email_verified', $merged);
        $this->assertSame('Pat', $merged['name']);

        $same = OidcClient::mergeUserinfo(['sub' => 's', 'email' => 'A@example.com'], ['sub' => 's', 'email' => 'a@example.com', 'email_verified' => true]);
        $this->assertTrue($same['email_verified']);

        $none = OidcClient::mergeUserinfo(['sub' => 's'], ['sub' => 's', 'email' => 'c@example.com', 'email_verified' => true]);
        $this->assertSame('c@example.com', $none['email']);
        $this->assertTrue($none['email_verified']);
    }

    public function testTokenAuthMethodOverride(): void
    {
        $this->config->providers['fake']['tokenAuthMethod'] = 'client_secret_post';
        $this->signIn();
        $req = $this->idp->requestsTo('/token')[0];
        $this->assertSame('s3cret', $req['form']['client_secret']);
        $this->assertArrayNotHasKey('Authorization', $req['headers']);
        $this->config->providers['fake']['tokenAuthMethod'] = 'private_key_jwt';
        $this->assertFailsWith('tokenAuthMethod must be', fn () => $this->provider());
    }

    public function testLastKnownGoodCopyCoversAnOutage(): void
    {
        $cache        = new MockCache();
        $this->client = new OidcClient($this->config, $this->idp, $cache, service('session'));
        $this->signIn(); // caches discovery and keys
        // The normal cache entries expire, then the provider goes down.
        $cache->delete('shieldoidc_disc_' . md5($this->idp->issuer));
        $cache->delete('shieldoidc_jwks_' . md5($this->idp->issuer . '/jwks'));
        $this->idp->down = true;
        $this->assertSame('user-1', $this->signIn()['claims']['sub']);
        // oidc:check asks for a fresh copy and must see the outage.
        $this->assertFailsWith('HTTP 503', fn () => $this->client->discovery($this->provider(), true));
    }

    public function testHmacTokenGetsAClearMessage(): void
    {
        $this->idp->alg = 'HS256';
        $this->assertFailsWith('RS256', fn () => $this->signIn());
    }
}
