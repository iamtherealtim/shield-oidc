<?php

declare(strict_types=1);

namespace DaemonLabs\ShieldOidc\Jose;

use Closure;
use DaemonLabs\ShieldOidc\Exceptions\OidcException;
use OpenSSLAsymmetricKey;

/**
 * Verifies an OpenID Connect ID token: signature against the provider's JWKS, then the claims
 * (OpenID Connect Core 1.0, section 3.1.3.7). Nothing in the token is trusted before the
 * signature checks out, and the header's own key hints (jku, jwk, x5u, x5c) are never followed.
 *
 * Malformed provider data (odd keys, odd claim types) is rejected as a failed sign-in, never
 * allowed to surface as a PHP warning or TypeError.
 */
final class IdTokenVerifier
{
    /** JWS alg => [key type, openssl digest, EC coordinate length] */
    private const ALGS = [
        'RS256' => ['RSA', OPENSSL_ALGO_SHA256, 0],
        'RS384' => ['RSA', OPENSSL_ALGO_SHA384, 0],
        'RS512' => ['RSA', OPENSSL_ALGO_SHA512, 0],
        'ES256' => ['EC', OPENSSL_ALGO_SHA256, 32],
        'ES384' => ['EC', OPENSSL_ALGO_SHA384, 48],
        'ES512' => ['EC', OPENSSL_ALGO_SHA512, 66],
    ];

    private const EC_CURVES = ['ES256' => 'P-256', 'ES384' => 'P-384', 'ES512' => 'P-521'];

    /** Keys tried per token. OIDC requires a kid when a set has several keys; this bounds the rest. */
    private const MAX_CANDIDATES = 20;

    /** OpenID Connect Core 2: sub is at most 255 ASCII characters. */
    private const MAX_SUB = 255;

    /**
     * @param Closure(bool): array<string, mixed> $keys        Returns the JWKS; true asks for a fresh copy (key rotation)
     * @param list<string>                        $allowedAlgs Algorithms accepted for this provider
     */
    public function __construct(
        private readonly Closure $keys,
        private readonly array $allowedAlgs = ['RS256'],
        private readonly int $clockSkew = 120,
    ) {
    }

    /** Algorithms this verifier can check at all. */
    public static function supportedAlgs(): array
    {
        return array_keys(self::ALGS);
    }

    /**
     * @param Closure(string, array<string, mixed>): bool $issuerOk Decides whether the iss claim is acceptable
     * @param string                                      $nonce    The nonce sent with this sign-in
     * @param list<string>                                $trustedAudiences Audiences accepted besides $clientId
     * @param int|null                                    $now      For tests
     *
     * @return array<string, mixed> The verified claims
     *
     * @throws OidcException
     */
    public function verify(string $jwt, string $clientId, Closure $issuerOk, string $nonce, array $trustedAudiences = [], ?int $now = null): array
    {
        $now ??= time();
        $parts = explode('.', $jwt);
        if (count($parts) !== 3) {
            throw OidcException::token('ID token is not a compact JWS.');
        }
        [$h, $p, $s] = $parts;
        $header = json_decode((string) Base64Url::decode($h), true);
        $claims = json_decode((string) Base64Url::decode($p), true);
        $sig    = Base64Url::decode($s);
        if (! is_array($header) || ! is_array($claims) || array_is_list($claims) && $claims !== []) {
            throw OidcException::token('ID token could not be decoded.');
        }

        $alg = is_string($header['alg'] ?? null) ? $header['alg'] : '';
        if (str_starts_with($alg, 'HS')) {
            // Shared-secret (HMAC) ID tokens are never accepted: anyone holding the client secret
            // could mint them. Providers that default to HS256 (Auth0 apps created by API) can
            // switch to RS256 in their settings.
            throw OidcException::token('ID token is HMAC-signed (' . $alg . '); configure the provider to sign ID tokens with RS256.');
        }
        if (! isset(self::ALGS[$alg]) || ! in_array($alg, $this->allowedAlgs, true)) {
            throw OidcException::token('ID token algorithm "' . ($alg ?: 'none') . '" is not allowed.');
        }
        if ($sig === null || $sig === '') {
            throw OidcException::token('ID token signature could not be decoded.');
        }
        if (array_key_exists('crit', $header)) {
            throw OidcException::token('ID token uses critical header extensions, which are not supported.');
        }

        $kid = is_string($header['kid'] ?? null) ? $header['kid'] : null;
        $iss = is_string($claims['iss'] ?? null) ? $claims['iss'] : '';
        $tid = is_string($claims['tid'] ?? null) ? $claims['tid'] : '';
        $this->checkSignature($h . '.' . $p, $sig, $alg, $kid, $iss, $tid);
        $this->checkClaims($claims, $clientId, $issuerOk, $nonce, $trustedAudiences, $now);

        return $claims;
    }

    /**
     * Verifies the JWS signature over "header.payload" with a key from the provider's set.
     * $iss and $tid (from the still-unverified payload) are only used to skip keys scoped to a
     * different issuer, never to accept anything.
     *
     * @throws OidcException
     */
    private function checkSignature(string $input, string $sig, string $alg, ?string $kid, string $iss, string $tid): void
    {
        [$kty, $digest, $ecLen] = self::ALGS[$alg];
        if ($kty === 'EC') {
            $sig = Jwk::ecSignatureToDer($sig, $ecLen);
            if ($sig === null) {
                throw OidcException::token('ID token signature has the wrong length for ' . $alg . '.');
            }
        }

        // Try the cached key set first. Refetch once only when it can help: the kid isn't in the
        // cached set (rotation), or the token has no kid. A known kid that fails won't change.
        // (The token comes straight from the token endpoint over TLS, so third parties can't
        // trigger refetches; the client also throttles them.)
        foreach ([false, true] as $fresh) {
            [$keys, $kidKnown] = $this->candidates(($this->keys)($fresh), $alg, $kty, $kid, $iss, $tid);
            foreach ($keys as $key) {
                if (@openssl_verify($input, $sig, $key, $digest) === 1) {
                    return;
                }
            }
            if ($kidKnown) {
                break;
            }
        }

        throw OidcException::token('ID token signature could not be verified' . ($kid !== null ? ' (kid ' . $kid . ')' : '') . '.');
    }

    /**
     * Public keys from the set that could have made this signature, and whether the token's
     * kid was present among them.
     *
     * @param array<string, mixed> $jwks
     *
     * @return array{0: list<OpenSSLAsymmetricKey>, 1: bool}
     */
    private function candidates(array $jwks, string $alg, string $kty, ?string $kid, string $iss, string $tid): array
    {
        $out = [];
        $keys = is_array($jwks['keys'] ?? null) ? $jwks['keys'] : [];
        foreach ($keys as $jwk) {
            if (count($out) >= self::MAX_CANDIDATES) {
                break;
            }
            if (! is_array($jwk) || ($jwk['kty'] ?? null) !== $kty) {
                continue;
            }
            if ($kid !== null && ($jwk['kid'] ?? null) !== $kid) {
                continue;
            }
            if (isset($jwk['use']) && $jwk['use'] !== 'sig') {
                continue;
            }
            if (isset($jwk['key_ops']) && (! is_array($jwk['key_ops']) || ! in_array('verify', $jwk['key_ops'], true))) {
                continue;
            }
            if (isset($jwk['alg']) && $jwk['alg'] !== $alg) {
                continue;
            }
            if ($kty === 'EC' && ($jwk['crv'] ?? null) !== self::EC_CURVES[$alg]) {
                continue;
            }
            // Some providers (Entra's multi-tenant key set) scope a key to an issuer; such a key
            // may only vouch for tokens from that issuer.
            if (isset($jwk['issuer']) && (! is_string($jwk['issuer']) || str_ireplace('{tenantid}', $tid, $jwk['issuer']) !== $iss)) {
                continue;
            }
            $pem = Jwk::toPem($jwk);
            $key = $pem !== null ? @openssl_pkey_get_public($pem) : false;
            if ($key !== false) {
                $out[] = $key;
            }
        }

        return [$out, $kid !== null && $out !== []];
    }

    /** @param array<string, mixed> $claims */
    private function checkClaims(array $claims, string $clientId, Closure $issuerOk, string $nonce, array $trustedAudiences, int $now): void
    {
        $iss = $claims['iss'] ?? null;
        if (! is_string($iss) || $iss === '' || ! $issuerOk($iss, $claims)) {
            throw OidcException::token('ID token issuer "' . (is_string($iss) ? $iss : '?') . '" is not the expected one.');
        }

        $aud = $claims['aud'] ?? null;
        $aud = is_string($aud) ? [$aud] : (is_array($aud) ? array_values(array_filter($aud, 'is_string')) : []);
        if (! in_array($clientId, $aud, true)) {
            throw OidcException::token('ID token was issued for a different client.');
        }
        // OIDC Core 3.1.3.7 step 3 (errata set 2): reject audiences the client doesn't trust.
        $untrusted = array_diff($aud, [$clientId], $trustedAudiences);
        if ($untrusted !== []) {
            throw OidcException::token('ID token also names audience(s) this app doesn\'t trust: ' . implode(', ', array_slice($untrusted, 0, 3)) . ' (list them in trustedAudiences if intended).');
        }
        // Step 5: when azp is present it should be our client id. (Errata set 2 no longer asks
        // for azp on multi-audience tokens; untrusted audiences are refused above instead.)
        $azp = $claims['azp'] ?? null;
        if ($azp !== null && $azp !== $clientId) {
            throw OidcException::token('ID token authorized party does not match this client.');
        }

        foreach (['exp', 'iat', 'nbf'] as $k) {
            if ($k === 'nbf' && ! array_key_exists('nbf', $claims)) {
                continue;
            }
            $v = $claims[$k] ?? null;
            if ((! is_int($v) && ! is_float($v)) || ! is_finite((float) $v)) {
                throw OidcException::token('ID token has a missing or non-numeric "' . $k . '" claim.');
            }
        }
        if ($claims['exp'] < $now - $this->clockSkew) {
            throw OidcException::token('ID token has expired.');
        }
        if ($claims['iat'] > $now + $this->clockSkew) {
            throw OidcException::token('ID token was issued in the future; check the server clock.');
        }
        if (isset($claims['nbf']) && $claims['nbf'] > $now + $this->clockSkew) {
            throw OidcException::token('ID token is not valid yet.');
        }

        if (! is_string($claims['nonce'] ?? null) || ! hash_equals($nonce, $claims['nonce'])) {
            throw OidcException::token('ID token nonce does not match this sign-in.');
        }
        $sub = $claims['sub'] ?? null;
        if (! is_string($sub) || $sub === '' || strlen($sub) > self::MAX_SUB || preg_match('/[^\x20-\x7e]/', $sub)) {
            throw OidcException::token('ID token has no valid subject.');
        }
    }
}
