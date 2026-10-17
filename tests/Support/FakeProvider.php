<?php

declare(strict_types=1);

namespace Tests\Support;

use DaemonLabs\ShieldOidc\Http\HttpClient;
use DaemonLabs\ShieldOidc\Jose\Base64Url;

/**
 * An in-memory OpenID provider: real keys, real signatures, canned endpoints.
 * Also the HttpClient the package talks to, so no request leaves the test.
 */
final class FakeProvider implements HttpClient
{
    public string $issuer;

    /** @var array<string, mixed> Overrides merged into the discovery document */
    public array $discoveryOverrides = [];

    /** @var array<string, mixed> Claims for the next ID token (nonce is filled in automatically) */
    public array $claims = [];

    /** Signing setup for the next token */
    public string $alg = 'RS256';

    public ?string $kid = 'rsa-1';

    /** @var array<string, mixed>|null Userinfo response; null = endpoint returns 404 */
    public ?array $userinfo = null;

    /** @var array{status: int, body: string}|null Force the token endpoint's response */
    public ?array $tokenResponse = null;

    /** Simulate an outage: discovery and keys answer 503 */
    public bool $down = false;

    /** Last nonce seen in an authorization URL */
    public ?string $nonce = null;

    /** @var list<array{method: string, url: string, form: array<string, string>, headers: array<string, string>}> */
    public array $requests = [];

    /** @var list<array<string, mixed>> Keys published in the JWKS (by default all of ours) */
    public array $published;

    /** @var array<string, array{0: \OpenSSLAsymmetricKey, 1: array<string, mixed>}> kid => [private key, public JWK] */
    private static array $keys = [];

    public function __construct(string $issuer = 'https://idp.example.test')
    {
        $this->issuer    = $issuer;
        $this->published = array_map(static fn ($k) => $k[1], self::keys());
    }

    /** @return array<string, array{0: \OpenSSLAsymmetricKey, 1: array<string, mixed>}> */
    public static function keys(): array
    {
        if (self::$keys === []) {
            // Fixed throwaway keys (tests/Support/keys): generating keys needs an openssl.cnf,
            // which some PHP builds (e.g. XAMPP on Windows) don't ship.
            foreach ([['rsa-1', 'RSA', 'RS256'], ['rsa-2', 'RSA', 'RS256'], ['ec-256', 'P-256', 'ES256'], ['ec-384', 'P-384', 'ES384'], ['ec-521', 'P-521', 'ES512']] as [$kid, $type, $alg]) {
                $key = openssl_pkey_get_private((string) file_get_contents(__DIR__ . '/keys/' . $kid . '.pem'));
                $d   = openssl_pkey_get_details($key);
                $jwk = $type === 'RSA'
                    ? ['kty' => 'RSA', 'kid' => $kid, 'use' => 'sig', 'alg' => $alg, 'n' => Base64Url::encode($d['rsa']['n']), 'e' => Base64Url::encode($d['rsa']['e'])]
                    : ['kty' => 'EC', 'kid' => $kid, 'use' => 'sig', 'crv' => $type, 'x' => Base64Url::encode($d['ec']['x']), 'y' => Base64Url::encode($d['ec']['y'])];
                self::$keys[$kid] = [$key, $jwk];
            }
        }

        return self::$keys;
    }

    /** @return array<string, mixed> */
    public function discovery(): array
    {
        return $this->discoveryOverrides + [
            'issuer'                                => $this->issuer,
            'authorization_endpoint'                => $this->issuer . '/authorize',
            'token_endpoint'                        => $this->issuer . '/token',
            'jwks_uri'                              => $this->issuer . '/jwks',
            'userinfo_endpoint'                     => $this->issuer . '/userinfo',
            'end_session_endpoint'                  => $this->issuer . '/logout',
            'id_token_signing_alg_values_supported' => ['RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512'],
            'token_endpoint_auth_methods_supported' => ['client_secret_basic', 'client_secret_post'],
            'code_challenge_methods_supported'      => ['S256'],
        ];
    }

    /**
     * Claims every valid token needs, for a client id.
     *
     * @return array<string, mixed>
     */
    public function baseClaims(string $clientId = 'client-123'): array
    {
        $now = time();

        return ['iss' => $this->issuer, 'aud' => $clientId, 'sub' => 'user-1', 'iat' => $now, 'exp' => $now + 300];
    }

    /**
     * Signs a JWT. $alg 'none' or 'HS256' produce the classic forgeries.
     *
     * @param array<string, mixed> $claims
     * @param array<string, mixed> $headerExtra
     */
    public function sign(array $claims, ?string $alg = null, ?string $kid = null, array $headerExtra = []): string
    {
        $alg ??= $this->alg;
        $kid = func_num_args() >= 3 ? $kid : $this->kid;
        $header = ['alg' => $alg, 'typ' => 'JWT'] + ($kid !== null ? ['kid' => $kid] : []) + $headerExtra;
        $input  = Base64Url::encode((string) json_encode($header)) . '.' . Base64Url::encode((string) json_encode($claims));

        if ($alg === 'none') {
            return $input . '.';
        }
        if ($alg === 'HS256') {
            return $input . '.' . Base64Url::encode(hash_hmac('sha256', $input, 'guessable', true));
        }

        $keyId  = $kid ?? ['RS256' => 'rsa-1', 'RS384' => 'rsa-1', 'RS512' => 'rsa-1', 'ES256' => 'ec-256', 'ES384' => 'ec-384', 'ES512' => 'ec-521'][$alg];
        $key    = isset(self::keys()[$keyId]) ? self::keys()[$keyId][0] : self::keys()['rsa-1'][0];
        $digest = ['RS256' => OPENSSL_ALGO_SHA256, 'RS384' => OPENSSL_ALGO_SHA384, 'RS512' => OPENSSL_ALGO_SHA512,
                   'ES256' => OPENSSL_ALGO_SHA256, 'ES384' => OPENSSL_ALGO_SHA384, 'ES512' => OPENSSL_ALGO_SHA512][$alg];
        openssl_sign($input, $sig, $key, $digest);
        if (str_starts_with($alg, 'ES')) {
            $sig = self::derToRaw($sig, ['ES256' => 32, 'ES384' => 48, 'ES512' => 66][$alg]);
        }

        return $input . '.' . Base64Url::encode($sig);
    }

    /** openssl's DER ECDSA signature -> JWS r||s */
    public static function derToRaw(string $der, int $len): string
    {
        $pos = 2;
        if (ord($der[1]) & 0x80) {
            $pos += ord($der[1]) & 0x7f;
        }
        $out = '';
        for ($i = 0; $i < 2; $i++) {
            $pos++; // 0x02
            $l = ord($der[$pos++]);
            $out .= str_pad(ltrim(substr($der, $pos, $l), "\0"), $len, "\0", STR_PAD_LEFT);
            $pos += $l;
        }

        return $out;
    }

    /** Pull the nonce out of an authorization URL, as the provider would. */
    public function sawAuthorizationUrl(string $url): array
    {
        parse_str((string) parse_url($url, PHP_URL_QUERY), $q);
        $this->nonce = $q['nonce'] ?? null;

        return $q;
    }

    /* ---------------- HttpClient ---------------- */

    public function get(string $url, array $headers = []): array
    {
        $this->requests[] = ['method' => 'GET', 'url' => $url, 'form' => [], 'headers' => $headers];
        if ($this->down && ! str_ends_with($url, '/userinfo')) {
            return ['status' => 503, 'body' => ''];
        }

        return match ($url) {
            $this->issuer . '/.well-known/openid-configuration' => $this->json($this->discovery()),
            $this->discovery()['jwks_uri']                      => $this->json(['keys' => $this->published]),
            $this->issuer . '/userinfo'                         => $this->userinfo === null ? ['status' => 404, 'body' => ''] : $this->json($this->userinfo),
            default                                             => ['status' => 404, 'body' => 'not found'],
        };
    }

    public function post(string $url, array $form, array $headers = []): array
    {
        $this->requests[] = ['method' => 'POST', 'url' => $url, 'form' => $form, 'headers' => $headers];
        if ($url !== $this->discovery()['token_endpoint']) {
            return ['status' => 404, 'body' => ''];
        }
        if ($this->tokenResponse !== null) {
            return $this->tokenResponse;
        }
        $claims = $this->claims + ($this->nonce !== null ? ['nonce' => $this->nonce] : []);

        return $this->json(['access_token' => 'at-' . bin2hex(random_bytes(4)), 'token_type' => 'Bearer', 'id_token' => $this->sign($claims)]);
    }

    /** @return array{status: int, body: string} */
    private function json(array $data): array
    {
        return ['status' => 200, 'body' => (string) json_encode($data)];
    }

    /** @return list<array{method: string, url: string, form: array<string, string>, headers: array<string, string>}> */
    public function requestsTo(string $suffix): array
    {
        return array_values(array_filter($this->requests, static fn ($r) => str_ends_with($r['url'], $suffix)));
    }
}
