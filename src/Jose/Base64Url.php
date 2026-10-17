<?php

declare(strict_types=1);

namespace DaemonLabs\ShieldOidc\Jose;

/** base64url without padding, as used throughout JOSE (JWS, JWK). Decoding is strict. */
final class Base64Url
{
    /**
     * Unpadded base64url (RFC 4648 section 5), as JOSE uses it.
     */
    public static function encode(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }

    /**
     * Strict decode: null for anything that isn't canonical, unpadded base64url
     * (padding, whitespace, other alphabets, or stray low bits in the last character).
     */
    public static function decode(string $value): ?string
    {
        if ($value === '') {
            return '';
        }
        if (preg_match('/[^A-Za-z0-9_-]/', $value) || strlen($value) % 4 === 1) {
            return null;
        }
        $out = base64_decode(strtr($value, '-_', '+/') . str_repeat('=', (4 - strlen($value) % 4) % 4), true);

        return $out !== false && self::encode($out) === $value ? $out : null;
    }
}
