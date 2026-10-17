<?php

declare(strict_types=1);

namespace Tests\Unit;

use CodeIgniter\Test\CIUnitTestCase;
use DaemonLabs\ShieldOidc\Exceptions\OidcException;
use DaemonLabs\ShieldOidc\Jose\Base64Url;
use DaemonLabs\ShieldOidc\Jose\IdTokenVerifier;
use Tests\Support\FakeProvider;

/**
 * @internal
 */
final class IdTokenVerifierTest extends CIUnitTestCase
{
    private FakeProvider $idp;
    private int $fetches = 0;
    private array $freshFetches = [];

    protected function setUp(): void
    {
        parent::setUp();
        $this->idp = new FakeProvider();
    }

    private function verifier(array $algs = ['RS256', 'ES256', 'ES384'], ?array $cached = null): IdTokenVerifier
    {
        return new IdTokenVerifier(function (bool $fresh) use ($cached): array {
            $this->fetches++;
            $this->freshFetches[] = $fresh;

            return ! $fresh && $cached !== null ? ['keys' => $cached] : ['keys' => $this->idp->published];
        }, $algs, 120);
    }

    private function verify(string $jwt, string $nonce = 'n-1', ?IdTokenVerifier $v = null, string $client = 'client-123'): array
    {
        return ($v ?? $this->verifier())->verify($jwt, $client, fn (string $iss) => $iss === $this->idp->issuer, $nonce);
    }

    private function claims(array $extra = []): array
    {
        return $extra + $this->idp->baseClaims() + ['nonce' => 'n-1'];
    }

    private function assertRejected(string $jwt, string $why, string $nonce = 'n-1', ?IdTokenVerifier $v = null): void
    {
        try {
            $this->verify($jwt, $nonce, $v);
            $this->fail('Token was accepted but should fail: ' . $why);
        } catch (OidcException $e) {
            $this->assertStringContainsStringIgnoringCase($why, $e->getDetail());
        }
    }

    public function testAcceptsRs256(): void
    {
        $claims = $this->verify($this->idp->sign($this->claims()));
        $this->assertSame('user-1', $claims['sub']);
    }

    public function testAcceptsEs256AndEs384(): void
    {
        $this->assertSame('user-1', $this->verify($this->idp->sign($this->claims(), 'ES256', 'ec-256'))['sub']);
        $this->assertSame('user-1', $this->verify($this->idp->sign($this->claims(), 'ES384', 'ec-384'))['sub']);
    }

    public function testAcceptsTokenWithoutKidByTryingMatchingKeys(): void
    {
        $this->assertSame('user-1', $this->verify($this->idp->sign($this->claims(), 'RS256', null))['sub']);
    }

    public function testRejectsAlgNone(): void
    {
        $this->assertRejected($this->idp->sign($this->claims(), 'none'), 'algorithm');
    }

    public function testRejectsHs256KeyConfusion(): void
    {
        $this->assertRejected($this->idp->sign($this->claims(), 'HS256'), 'HMAC-signed');
    }

    public function testRejectsAlgorithmNotAllowedForProvider(): void
    {
        $this->assertRejected($this->idp->sign($this->claims(), 'ES256', 'ec-256'), 'not allowed', 'n-1', $this->verifier(['RS256']));
    }

    public function testRejectsTamperedPayload(): void
    {
        [$h, , $s] = explode('.', $this->idp->sign($this->claims()));
        $evil = Base64Url::encode((string) json_encode($this->claims(['sub' => 'admin'])));
        $this->assertRejected($h . '.' . $evil . '.' . $s, 'signature');
    }

    public function testRejectsSignatureFromAnotherKeyWithSameKid(): void
    {
        // Signed by rsa-2 but claiming to be rsa-1
        $jwt = $this->idp->sign($this->claims(), 'RS256', 'rsa-2');
        [, $p, $s] = explode('.', $jwt);
        $h = Base64Url::encode((string) json_encode(['alg' => 'RS256', 'kid' => 'rsa-1']));
        $this->assertRejected($h . '.' . $p . '.' . $s, 'signature');
    }

    public function testRejectsEcKeyUsedWithRsaAlg(): void
    {
        $jwt = $this->idp->sign($this->claims(), 'ES256', 'ec-256');
        [, $p, $s] = explode('.', $jwt);
        $h = Base64Url::encode((string) json_encode(['alg' => 'RS256', 'kid' => 'ec-256']));
        $this->assertRejected($h . '.' . $p . '.' . $s, 'signature');
    }

    public function testRejectsCriticalHeader(): void
    {
        $this->assertRejected($this->idp->sign($this->claims(), 'RS256', 'rsa-1', ['crit' => ['exp']]), 'critical');
    }

    public function testIgnoresEmbeddedJwkHeader(): void
    {
        // The provider publishes only rsa-1. An attacker signs with their own key (rsa-2) and
        // embeds its public half in the header (jwk / jku): it must never be used.
        $this->idp->published = [FakeProvider::keys()['rsa-1'][1]];
        $attackerJwk = FakeProvider::keys()['rsa-2'][1];
        foreach ([['jwk' => $attackerJwk], ['jku' => 'https://evil.example/jwks']] as $extra) {
            $forged = $this->idp->sign($this->claims(['sub' => 'admin']), 'RS256', 'rsa-2', $extra);
            $this->assertRejected($forged, 'signature');
        }
        $legit = $this->idp->sign($this->claims(), 'RS256', 'rsa-1', ['jwk' => $attackerJwk]);
        $this->assertSame('user-1', $this->verify($legit)['sub']);
    }

    public function testRefetchesKeysOnceWhenKidUnknown(): void
    {
        // Cached set has only rsa-2; the token uses rsa-1 (rotated in)
        $v = $this->verifier(['RS256'], [FakeProvider::keys()['rsa-2'][1]]);
        $this->assertSame('user-1', $this->verify($this->idp->sign($this->claims()), 'n-1', $v)['sub']);
        $this->assertSame([false, true], $this->freshFetches);
    }

    public function testGivesUpAfterOneRefetch(): void
    {
        $this->idp->published = [FakeProvider::keys()['rsa-2'][1]];
        $this->assertRejected($this->idp->sign($this->claims()), 'signature', 'n-1', $this->verifier(['RS256']));
        $this->assertSame([false, true], $this->freshFetches);
    }

    public function testRejectsWrongIssuer(): void
    {
        $this->assertRejected($this->idp->sign($this->claims(['iss' => 'https://evil.example'])), 'issuer');
    }

    public function testRejectsWrongAudience(): void
    {
        $this->assertRejected($this->idp->sign($this->claims(['aud' => 'other-client'])), 'different client');
    }

    /** OIDC Core 3.1.3.7 step 3 (errata 2): extra audiences must be trusted, azp or not. */
    public function testExtraAudienceMustBeTrusted(): void
    {
        $jwt = $this->idp->sign($this->claims(['aud' => ['client-123', 'api'], 'azp' => 'client-123']));
        $this->assertRejected($jwt, 'trust');
        $ok = $this->verifier()->verify($jwt, 'client-123', fn (string $iss) => $iss === $this->idp->issuer, 'n-1', ['api']);
        $this->assertSame('user-1', $ok['sub']);
    }

    public function testTrustedExtraAudienceNeedsNoAzp(): void
    {
        $jwt = $this->idp->sign($this->claims(['aud' => ['client-123', 'api']]));
        $this->assertSame('user-1', $this->verifier()->verify($jwt, 'client-123', fn (string $iss) => $iss === $this->idp->issuer, 'n-1', ['api'])['sub']);
    }

    public function testRejectsAzpForAnotherClient(): void
    {
        $this->assertRejected($this->idp->sign($this->claims(['azp' => 'other'])), 'authorized party');
    }

    public function testRejectsExpired(): void
    {
        $this->assertRejected($this->idp->sign($this->claims(['exp' => time() - 600])), 'expired');
    }

    public function testAllowsClockSkew(): void
    {
        $this->assertSame('user-1', $this->verify($this->idp->sign($this->claims(['exp' => time() - 60])))['sub']);
    }

    public function testRejectsIssuedInFuture(): void
    {
        $this->assertRejected($this->idp->sign($this->claims(['iat' => time() + 3600])), 'future');
    }

    public function testRejectsNotYetValid(): void
    {
        $this->assertRejected($this->idp->sign($this->claims(['nbf' => time() + 3600])), 'not valid yet');
    }

    public function testRejectsMissingExp(): void
    {
        $c = $this->claims();
        unset($c['exp']);
        $this->assertRejected($this->idp->sign($c), '"exp"');
    }

    public function testRejectsNonceMismatchOrMissing(): void
    {
        $this->assertRejected($this->idp->sign($this->claims(['nonce' => 'other'])), 'nonce');
        $c = $this->claims();
        unset($c['nonce']);
        $this->assertRejected($this->idp->sign($c), 'nonce');
    }

    public function testRejectsMissingSubject(): void
    {
        $this->assertRejected($this->idp->sign($this->claims(['sub' => ''])), 'subject');
    }

    public function testRejectsGarbage(): void
    {
        $this->assertRejected('not.a.jwt!', 'decoded');
        $this->assertRejected('onlyonepart', 'compact');
    }

    public function testRejectsTruncatedEcSignature(): void
    {
        [$h, $p, $s] = explode('.', $this->idp->sign($this->claims(), 'ES256', 'ec-256'));
        $short = Base64Url::encode(substr((string) Base64Url::decode($s), 0, 40));
        $this->assertRejected($h . '.' . $p . '.' . $short, 'length');
    }

    /* ---------------- audit regressions ---------------- */

    /** Signs any raw JSON payload with rsa-1 (for claim values json_encode can't produce). */
    private function signRaw(string $payloadJson, array $header = ['alg' => 'RS256', 'kid' => 'rsa-1']): string
    {
        $input = Base64Url::encode((string) json_encode($header)) . '.' . Base64Url::encode($payloadJson);
        openssl_sign($input, $sig, FakeProvider::keys()['rsa-1'][0], OPENSSL_ALGO_SHA256);

        return $input . '.' . Base64Url::encode($sig);
    }

    public function testAcceptsRs384Rs512AndEs512(): void
    {
        $rsaNoAlg = FakeProvider::keys()['rsa-1'][1];
        unset($rsaNoAlg['alg']);
        $this->idp->published = [$rsaNoAlg, FakeProvider::keys()['ec-521'][1]];
        $v = $this->verifier(['RS384', 'RS512', 'ES512']);
        $this->assertSame('user-1', $this->verify($this->idp->sign($this->claims(), 'RS384', 'rsa-1'), 'n-1', $v)['sub']);
        $this->assertSame('user-1', $this->verify($this->idp->sign($this->claims(), 'RS512', 'rsa-1'), 'n-1', $v)['sub']);
        $this->assertSame('user-1', $this->verify($this->idp->sign($this->claims(), 'ES512', 'ec-521'), 'n-1', $v)['sub']);
    }

    /** With e = 1 the "signature" is just the padded hash, so anyone could forge tokens. */
    public function testExponentOneKeyCannotBeUsedToForge(): void
    {
        $evil = ['kty' => 'RSA', 'kid' => 'e1', 'n' => FakeProvider::keys()['rsa-1'][1]['n'], 'e' => 'AQ'];
        $this->idp->published = [$evil];
        $input = Base64Url::encode((string) json_encode(['alg' => 'RS256', 'kid' => 'e1'])) . '.' . Base64Url::encode((string) json_encode($this->claims(['sub' => 'admin'])));
        $t     = hex2bin('3031300d060960864801650304020105000420') . hash('sha256', $input, true);
        $em    = "\x00\x01" . str_repeat("\xff", 256 - 3 - strlen($t)) . "\x00" . $t; // PKCS#1 v1.5, no private key needed
        $this->assertRejected($input . '.' . Base64Url::encode($em), 'signature');
    }

    public function testWeakOrMalformedRsaKeysAreIgnored(): void
    {
        $short = ['kty' => 'RSA', 'kid' => 'rsa-1', 'n' => Base64Url::encode("\xc1" . random_bytes(126) . "\x01"), 'e' => 'AQAB']; // 1024 bits
        $even  = ['kty' => 'RSA', 'kid' => 'rsa-1', 'n' => FakeProvider::keys()['rsa-1'][1]['n'], 'e' => 'AAI']; // e = 2
        $this->idp->published = [$short, $even];
        $this->assertRejected($this->idp->sign($this->claims()), 'signature');
    }

    /** Odd entries in a provider's key set must not crash sign-in or hide the good key. */
    public function testMalformedKeysBeforeTheGoodOneAreSkipped(): void
    {
        $this->idp->published = [
            ['kty' => 'EC', 'crv' => 'P-256', 'x' => Base64Url::encode(str_repeat("\x01", 32)), 'y' => Base64Url::encode(str_repeat("\x02", 32))], // not on the curve
            ['kty' => 'RSA', 'n' => ['x'], 'e' => 'AQAB'],
            ['kty' => 'EC', 'crv' => ['P-256'], 'x' => 1, 'y' => null],
            'not a key',
            FakeProvider::keys()['ec-256'][1],
        ];
        $this->assertSame('user-1', $this->verify($this->idp->sign($this->claims(), 'ES256', null))['sub']);
    }

    public function testKeyOpsMustAllowVerify(): void
    {
        $this->idp->published = [['key_ops' => ['encrypt']] + FakeProvider::keys()['rsa-1'][1]];
        $this->assertRejected($this->idp->sign($this->claims()), 'signature');
        $this->idp->published = [['key_ops' => ['verify']] + FakeProvider::keys()['rsa-1'][1]];
        $this->assertSame('user-1', $this->verify($this->idp->sign($this->claims()), 'n-1', $this->verifier())['sub']);
    }

    /** Entra's multi-tenant key set scopes keys to an issuer template. */
    public function testIssuerScopedKeysOnlyVouchForTheirIssuer(): void
    {
        $this->idp->published = [['issuer' => 'https://idp.example.test/{tenantid}/v2.0'] + FakeProvider::keys()['rsa-1'][1]];
        $token = $this->idp->sign($this->claims(['iss' => 'https://idp.example.test/t1/v2.0', 'tid' => 't1']));
        $ok    = (new IdTokenVerifier(fn () => ['keys' => $this->idp->published], ['RS256']))->verify($token, 'client-123', static fn () => true, 'n-1');
        $this->assertSame('user-1', $ok['sub']);

        $wrong = $this->idp->sign($this->claims(['iss' => 'https://idp.example.test/t1/v2.0', 'tid' => 't2']));
        $this->expectException(OidcException::class);
        (new IdTokenVerifier(fn () => ['keys' => $this->idp->published], ['RS256']))->verify($wrong, 'client-123', static fn () => true, 'n-1');
    }

    public function testRejectsNonCanonicalBase64(): void
    {
        [$h, $p, $s] = explode('.', $this->idp->sign($this->claims()));
        // 256-byte signature: the last base64url character carries 2 unused bits; set one.
        $last = $s[strlen($s) - 1];
        $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
        $tweaked = substr($s, 0, -1) . $alphabet[strpos($alphabet, $last) | 1];
        $this->assertNotSame($s, $tweaked);
        $this->assertRejected($h . '.' . $p . '.' . $tweaked, 'decoded');
        $this->assertNull(Base64Url::decode('QR'));
        $this->assertSame('A', Base64Url::decode('QQ'));
    }

    public function testRejectsNonFiniteOrStringTimes(): void
    {
        $base = '"iss":"https://idp.example.test","aud":"client-123","sub":"user-1","nonce":"n-1"';
        $now  = time();
        $this->assertRejected($this->signRaw('{' . $base . ',"iat":' . $now . ',"exp":1e400}'), '"exp"');
        $this->assertRejected($this->signRaw('{' . $base . ',"iat":' . $now . ',"exp":"' . ($now + 300) . '"}'), '"exp"');
        $this->assertRejected($this->signRaw('{' . $base . ',"iat":' . $now . ',"exp":' . ($now + 300) . ',"nbf":"0"}'), '"nbf"');
    }

    public function testRejectsOversizedOrNonAsciiSubject(): void
    {
        $this->assertRejected($this->idp->sign($this->claims(['sub' => str_repeat('a', 256)])), 'subject');
        $this->assertRejected($this->idp->sign($this->claims(['sub' => "user\n1"])), 'subject');
        $this->assertSame(str_repeat('a', 255), $this->verify($this->idp->sign($this->claims(['sub' => str_repeat('a', 255)])))['sub']);
    }

    public function testRejectsClaimsThatAreAList(): void
    {
        $this->assertRejected($this->signRaw('["iss","aud"]'), 'decoded');
    }

    /** A kid that's in the cached set and fails won't be fixed by refetching. */
    public function testNoRefetchWhenKnownKidFails(): void
    {
        $jwt = $this->idp->sign($this->claims(), 'RS256', 'rsa-2');
        [, $p, $s] = explode('.', $jwt);
        $h = Base64Url::encode((string) json_encode(['alg' => 'RS256', 'kid' => 'rsa-1']));
        $this->assertRejected($h . '.' . $p . '.' . $s, 'signature', 'n-1', $this->verifier(['RS256'], [FakeProvider::keys()['rsa-1'][1]]));
        $this->assertSame([false], $this->freshFetches);
    }

    public function testCapsKeysTriedForTokensWithoutKid(): void
    {
        $decoys = array_fill(0, 30, FakeProvider::keys()['rsa-2'][1]);
        $this->idp->published = array_merge($decoys, [FakeProvider::keys()['rsa-1'][1]]);
        // The right key is beyond the cap: a provider with many keys must send a kid.
        $this->assertRejected($this->idp->sign($this->claims(), 'RS256', null), 'signature');
    }
}
