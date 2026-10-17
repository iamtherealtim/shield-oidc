<?php

declare(strict_types=1);

namespace DaemonLabs\ShieldOidc\Config;

use CodeIgniter\Config\BaseConfig;
use DaemonLabs\ShieldOidc\Http\CurlHttpClient;
use DaemonLabs\ShieldOidc\UserResolver;

/**
 * Settings for Shield OIDC. Copy to app/Config/ShieldOidc.php with `php spark oidc:setup`
 * (or extend this class there) and add your providers.
 */
class ShieldOidc extends BaseConfig
{
    /**
     * Identity providers, keyed by a short name used in URLs: /oidc/<key>/login.
     *
     * Each entry needs `clientId` and either `issuer` (any OpenID Connect provider) or
     * `type` => 'entra' with a `tenant`. Everything else falls back to $defaults.
     * Keep secrets out of this file: use env('...') or .env overrides.
     *
     * @var array<string, array<string, mixed>>
     */
    public array $providers = [
        // 'entra' => [
        //     'type'         => 'entra',
        //     'label'        => 'Microsoft',
        //     'tenant'       => 'your-tenant-id',        // or 'organizations' for any work account
        //     'clientId'     => '...',
        //     'clientSecret' => '...',
        // ],
        // 'okta' => [
        //     'label'        => 'Okta',
        //     'issuer'       => 'https://your-org.okta.com',
        //     'clientId'     => '...',
        //     'clientSecret' => '...',
        // ],
    ];

    /**
     * Defaults for every provider. Any key can be overridden per provider.
     *
     * @var array<string, mixed>
     */
    public array $defaults = [
        // Shown on the sign-in button: "Sign in with <label>"
        'label' => 'SSO',

        // Requested scopes; "openid" is always added.
        'scopes' => ['openid', 'profile', 'email'],

        // Extra authorization parameters, e.g. ['prompt' => 'select_account'] or ['domain_hint' => 'example.com'].
        'authParams' => [],

        // Claim that identifies the person. "sub" is stable per provider; Entra defaults to "oid".
        'subjectClaim' => 'sub',

        // Create a Shield user on first sign-in when no account matches.
        'register' => true,

        // Only people whose trusted email is in these domains may sign in, e.g. ['example.com'].
        // Checked on every sign-in. Empty = any. (See linkByEmail for when an email is trusted.)
        'allowedDomains' => [],

        // Claims that must have one of the given values, checked on every sign-in,
        // e.g. ['hd' => 'example.com'] for Google Workspace.
        'requiredClaims' => [],

        /*
         * A provider's email is trusted only as that provider documents: Entra with the xms_edov
         * optional claim; Google for @gmail.com, or email_verified plus hd; others with
         * email_verified; any provider with 'trusted' below. Untrusted emails are never stored
         * on new accounts and never pass allowedDomains.
         *
         * Whether a first SSO sign-in may attach to an existing account with the same email:
         *   'verified' - when the provider's email is trusted and Shield verified the local
         *                account's (registration closed, or email activation done). Default.
         *   'trusted'  - treat every email from this provider as trusted. Only for a provider
         *                whose users cannot set their own address. Risky anywhere else.
         *   'never'    - never; people connect accounts from a signed-in session instead.
         */
        'linkByEmail' => 'verified',

        // Claim holding groups or roles (e.g. "groups" or "roles"), and how values map to Shield groups:
        // ['Admins' => 'admin', 'app-developers' => 'developer']. Empty map = don't touch groups.
        // With multi-tenant Entra this only applies to tenants listed in a provider's 'groupTenants'.
        'groupsClaim' => null,
        'groupMap'    => [],

        // true = on every sign-in also remove mapped Shield groups the person no longer has.
        // Groups not mentioned in groupMap are never removed.
        'syncGroups' => false,

        // Look up the userinfo endpoint for claims the ID token left out (off for Entra, whose
        // userinfo only repeats the ID token).
        'userinfo' => true,

        // Signing algorithms accepted for ID tokens (intersected with what the provider advertises).
        'algorithms' => ['RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512'],

        // Extra ID token audiences to accept besides the client id; any other is refused.
        'trustedAudiences' => [],

        // How the client secret is sent: 'auto' (Basic when offered), 'client_secret_basic' or
        // 'client_secret_post', for providers that enforce the method registered for the app.
        'tokenAuthMethod' => 'auto',

        // After signing out of this app, also end the session at the provider (RP-initiated logout).
        'logoutAtProvider' => false,

        // Run Shield's configured login action (e.g. Email2FA) for SSO sign-ins too.
        'loginActions' => false,

        // When a signed-in user connects a provider: parameters that force a fresh sign-in, and
        // whether a missing auth_time fails the check. Entra (prompt=login only) and Google
        // (prompt=select_account) get their own documented values unless set per provider.
        'reauthParams'    => ['prompt' => 'login', 'max_age' => '0'],
        'requireAuthTime' => true,
    ];

    /** URL prefix for the package's routes. */
    public string $routePrefix = 'oidc';

    /** Where to go after a failed sign-in (the error is flashed as session('error')). */
    public string $failureRedirect = '/login';

    /** Where to go after signing out when the provider doesn't redirect back. */
    public string $logoutRedirect = '/';

    /** Seconds of clock difference tolerated when checking token times. */
    public int $clockSkew = 120;

    /** Seconds to cache discovery documents and signing keys. */
    public int $cacheTtl = 3600;

    /** Seconds a sign-in may take between leaving for the provider and coming back. */
    public int $stateTtl = 600;

    /** Timeout for calls to the provider, in seconds. */
    public int $httpTimeout = 10;

    /**
     * Allow plain-http issuers. Only ever for a provider on localhost during development;
     * it is refused for any other host regardless of this setting.
     */
    public bool $allowLocalHttp = false;

    /** @var class-string<\DaemonLabs\ShieldOidc\Http\HttpClient> */
    public string $httpClient = CurlHttpClient::class;

    /** Extend UserResolver to change how claims become Shield users. @var class-string<UserResolver> */
    public string $userResolver = UserResolver::class;
}
