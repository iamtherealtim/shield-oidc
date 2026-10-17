<?php

declare(strict_types=1);

namespace DaemonLabs\ShieldOidc\Jose;

/**
 * Turns a JSON Web Key into a PEM public key that openssl can verify with, without any
 * third-party JOSE library. Supports RSA keys and EC keys on P-256, P-384 and P-521.
 */
final class Jwk
{
    /** Curve name => [DER-encoded OID, coordinate length in bytes] */
    private const CURVES = [
        'P-256' => ["\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07", 32],
        'P-384' => ["\x06\x05\x2b\x81\x04\x00\x22", 48],
        'P-521' => ["\x06\x05\x2b\x81\x04\x00\x23", 66],
    ];

    /** RSA modulus bounds in bytes: at least 2048 bits (RFC 7518 3.3), at most 16384. */
    private const RSA_MIN = 256;

    private const RSA_MAX = 2048;

    /**
     * PEM for a JWK, or null for anything unusable: wrong types, unknown curves, weak RSA keys.
     *
     * @param array<string, mixed> $jwk
     */
    public static function toPem(array $jwk): ?string
    {
        $s = static fn (string $k): ?string => is_string($jwk[$k] ?? null) ? $jwk[$k] : null;

        return match ($jwk['kty'] ?? null) {
            'RSA'   => $s('n') !== null && $s('e') !== null ? self::rsa($s('n'), $s('e')) : null,
            'EC'    => $s('crv') !== null && $s('x') !== null && $s('y') !== null ? self::ec($s('crv'), $s('x'), $s('y')) : null,
            default => null,
        };
    }

    /** Coordinate length for an EC curve, or null when unsupported. */
    public static function curveLength(string $crv): ?int
    {
        return self::CURVES[$crv][1] ?? null;
    }

    /**
     * SubjectPublicKeyInfo for an RSA key from its base64url modulus and exponent.
     */
    private static function rsa(string $n, string $e): ?string
    {
        $nb = Base64Url::decode($n);
        $eb = Base64Url::decode($e);
        if ($nb === null || $eb === null) {
            return null;
        }
        $nb = ltrim($nb, "\0");
        $eb = ltrim($eb, "\0");
        // Refuse weak or absurd keys: short moduli, and exponents that are even, below 3
        // (e = 1 makes the "signature" equal the padded hash, so anyone could forge one) or
        // above 2^32.
        if (strlen($nb) < self::RSA_MIN || strlen($nb) > self::RSA_MAX || (ord($nb[strlen($nb) - 1]) & 1) === 0
            || $eb === '' || strlen($eb) > 4 || (ord($eb[strlen($eb) - 1]) & 1) === 0 || (strlen($eb) === 1 && ord($eb) < 3)) {
            return null;
        }
        $key   = self::seq(self::int($nb) . self::int($eb));
        $algId = self::seq("\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00"); // rsaEncryption, NULL

        return self::pem(self::seq($algId . self::bits($key)));
    }

    /**
     * SubjectPublicKeyInfo for an EC key: an uncompressed point (0x04 || x || y), coordinates
     * left-padded to the curve's size. openssl rejects points that aren't on the curve.
     */
    private static function ec(string $crv, string $x, string $y): ?string
    {
        if (! isset(self::CURVES[$crv])) {
            return null;
        }
        [$oid, $len] = self::CURVES[$crv];
        $xb = Base64Url::decode($x);
        $yb = Base64Url::decode($y);
        if ($xb === null || $yb === null || strlen($xb) > $len || strlen($yb) > $len || $xb === '' || $yb === '') {
            return null;
        }
        $point = "\x04" . str_pad($xb, $len, "\0", STR_PAD_LEFT) . str_pad($yb, $len, "\0", STR_PAD_LEFT);
        $algId = self::seq("\x06\x07\x2a\x86\x48\xce\x3d\x02\x01" . $oid); // id-ecPublicKey + curve

        return self::pem(self::seq($algId . self::bits($point)));
    }

    /**
     * JWS ECDSA signatures are r||s; openssl wants DER SEQUENCE { INTEGER r, INTEGER s }.
     * Returns null when the signature isn't exactly twice the curve length.
     */
    public static function ecSignatureToDer(string $raw, int $len): ?string
    {
        if (strlen($raw) !== 2 * $len) {
            return null;
        }

        return self::seq(self::int(substr($raw, 0, $len)) . self::int(substr($raw, $len)));
    }

    /**
     * Minimal DER helpers: INTEGER (unsigned big-endian, kept positive), SEQUENCE, BIT STRING,
     * length octets, and PEM armour.
     */
    private static function int(string $bytes): string
    {
        $bytes = ltrim($bytes, "\0");
        if ($bytes === '' || (ord($bytes[0]) & 0x80)) {
            $bytes = "\0" . $bytes; // keep it positive
        }

        return "\x02" . self::len(strlen($bytes)) . $bytes;
    }

    private static function seq(string $content): string
    {
        return "\x30" . self::len(strlen($content)) . $content;
    }

    private static function bits(string $content): string
    {
        return "\x03" . self::len(strlen($content) + 1) . "\0" . $content;
    }

    private static function len(int $len): string
    {
        if ($len < 0x80) {
            return chr($len);
        }
        $bytes = ltrim(pack('N', $len), "\0");

        return chr(0x80 | strlen($bytes)) . $bytes;
    }

    private static function pem(string $der): string
    {
        return "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END PUBLIC KEY-----\n";
    }
}
