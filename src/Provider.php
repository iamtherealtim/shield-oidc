<?php

declare(strict_types=1);

namespace DaemonLabs\ShieldOidc;

use DaemonLabs\ShieldOidc\Config\ShieldOidc;
use DaemonLabs\ShieldOidc\Exceptions\OidcException;

/**
 * One configured identity provider, with defaults applied and Entra specifics worked out.
 *
 * Settings are validated strictly: an unknown key or a wrongly typed value is a configuration
 * error, never silently ignored. (A typo like "allowedTenant" must not quietly drop a restriction.)
 */
final class Provider
{
    /** Entra tenant aliases that accept accounts from many tenants. */
    public const ENTRA_MULTI = ['common', 'organizations', 'consumers'];

    /** The fixed tenant id Microsoft uses for personal accounts. */
    public const ENTRA_CONSUMERS_TID = '9188040d-6c67-4c5b-b112-36a304b66dad';

    /** Every setting a provider may have, and its type. */
    private const OPTIONS = [
        'type'             => 'string',
        'label'            => 'string',
        'issuer'           => 'string',
        'clientId'         => 'string',
        'clientSecret'     => 'string',
        'tenant'           => 'string',
        'authority'        => 'string',
        'allowedTenants'   => 'list',
        'groupTenants'     => 'list',
        'scopes'           => 'list',
        'authParams'       => 'map',
        'subjectClaim'     => 'string',
        'usernameClaim'    => '?string',
        'register'         => 'bool',
        'defaultGroup'     => 'bool',
        'allowedDomains'   => 'list',
        'requiredClaims'   => 'map',
        'linkByEmail'      => 'string',
        'groupsClaim'      => '?string',
        'groupMap'         => 'map',
        'syncGroups'       => 'bool',
        'userinfo'         => 'bool',
        'algorithms'       => 'list',
        'logoutAtProvider' => 'bool',
        'redirectUri'      => '?string',
        'trustedAudiences' => 'list',
        'tokenAuthMethod'  => 'string',
        'reauthParams'     => 'map',
        'requireAuthTime'  => 'bool',
        'loginActions'     => 'bool',
    ];

    /** Google's issuer (its ID tokens may also carry the scheme-less form). */
    public const GOOGLE_ISSUER = 'https://accounts.google.com';

    /** Authorization parameters only the package may set. */
    private const RESERVED_PARAMS = ['response_type', 'response_mode', 'client_id', 'redirect_uri', 'scope', 'state',
        'nonce', 'code_challenge', 'code_challenge_method', 'request', 'request_uri'];

    public readonly string $key;
    public readonly string $type;
    public readonly string $label;
    public readonly string $issuer;
    public readonly string $clientId;
    public readonly string $clientSecret;
    public readonly string $tenant;

    /** @var list<string> lowercase tenant ids */
    public readonly array $allowedTenants;

    /** @var array<string, mixed> */
    private array $o;

    /** @param array<string, mixed> $settings */
    public function __construct(string $key, array $settings, array $defaults = [])
    {
        if (! preg_match('/^[a-z0-9][a-z0-9_-]{0,31}$/', $key)) {
            throw OidcException::config('Provider key "' . $key . '" must be lowercase letters, digits, - or _.');
        }
        $this->key = $key;
        self::validate($key, $settings);
        self::validate($key . ' (defaults)', $defaults);

        $this->type = (string) ($settings['type'] ?? 'generic');
        if (! in_array($this->type, ['generic', 'entra'], true)) {
            throw OidcException::config('Provider "' . $key . '": type must be "generic" or "entra".');
        }

        // Defaults that differ by provider, each from that provider's documentation:
        //  - Entra identifies people by oid, puts app roles in "roles", and its userinfo
        //    endpoint only repeats ID token claims. It doesn't document max_age or send
        //    auth_time by default, so linking relies on prompt=login.
        //  - Google documents prompt values none/consent/select_account only (no login, no
        //    max_age) and sends auth_time only on request, so linking shows the account picker.
        //  - Everyone else gets the spec's prompt=login + max_age=0, which obliges the provider
        //    to send auth_time (OIDC Core 3.1.2.1), so its absence is treated as a failure.
        $isGoogle     = rtrim((string) ($settings['issuer'] ?? ''), '/') === self::GOOGLE_ISSUER;
        $typeDefaults = match (true) {
            $this->type === 'entra' => [
                'label' => 'Microsoft', 'subjectClaim' => 'oid', 'groupsClaim' => 'roles', 'userinfo' => false,
                'reauthParams' => ['prompt' => 'login'], 'requireAuthTime' => false,
            ],
            $isGoogle => [
                'label' => 'Google', 'reauthParams' => ['prompt' => 'select_account'], 'requireAuthTime' => false,
            ],
            default => [],
        };
        // The package's own defaults sit underneath, so an app that redeclares $defaults with
        // only a few keys doesn't silently lose the rest (scopes, algorithms, ...).
        $packageDefaults = (new \ReflectionClass(ShieldOidc::class))->getDefaultProperties()['defaults'] ?? [];
        $this->o = $settings + $typeDefaults + $defaults + $packageDefaults;

        if (! in_array($this->o['linkByEmail'] ?? 'verified', ['verified', 'trusted', 'never'], true)) {
            throw OidcException::config('Provider "' . $key . '": linkByEmail must be "verified", "trusted" or "never".');
        }
        if (! in_array($this->o['tokenAuthMethod'] ?? 'auto', ['auto', 'client_secret_basic', 'client_secret_post'], true)) {
            throw OidcException::config('Provider "' . $key . '": tokenAuthMethod must be "auto", "client_secret_basic" or "client_secret_post".');
        }
        // Parameters the package sets itself must not be supplied (or overridden) by config:
        // they carry the flow's security, or (response_mode) would break the GET callback.
        foreach (['authParams', 'reauthParams'] as $opt) {
            $clash = array_intersect(array_keys((array) ($this->o[$opt] ?? [])), self::RESERVED_PARAMS);
            if ($clash !== []) {
                throw OidcException::config('Provider "' . $key . '": ' . $opt . ' may not set ' . implode(', ', $clash) . '.');
            }
        }

        $this->label        = (string) ($this->o['label'] ?? $key);
        $this->clientId     = trim((string) ($this->o['clientId'] ?? ''));
        $this->clientSecret = (string) ($this->o['clientSecret'] ?? '');
        if ($this->clientId === '') {
            throw OidcException::config('Provider "' . $key . '" has no clientId.');
        }

        if ($this->type === 'entra') {
            $this->tenant = trim((string) ($this->o['tenant'] ?? ''));
            if ($this->tenant === '' || ! preg_match('/^[A-Za-z0-9.-]+$/', $this->tenant)) {
                throw OidcException::config('Entra provider "' . $key . '" needs a tenant (id, domain, "organizations" or "common").');
            }
            $authority      = (string) ($this->o['authority'] ?? 'https://login.microsoftonline.com');
            $this->issuer   = rtrim($authority, '/') . '/' . $this->tenant . '/v2.0';
            $this->allowedTenants = array_map('strtolower', (array) ($this->o['allowedTenants'] ?? []));
        } else {
            $this->tenant         = '';
            $this->allowedTenants = [];
            $this->issuer         = rtrim(trim((string) ($this->o['issuer'] ?? '')), '/');
            if ($this->issuer === '') {
                throw OidcException::config('Provider "' . $key . '" has no issuer URL.');
            }
        }
    }

    /** @param array<string, mixed> $settings */
    private static function validate(string $where, array $settings): void
    {
        foreach ($settings as $name => $value) {
            $type = self::OPTIONS[$name] ?? null;
            if ($type === null) {
                throw OidcException::config('Provider "' . $where . '": unknown setting "' . $name . '". Check the spelling against the README.');
            }
            $ok = match ($type) {
                'string'  => is_string($value),
                '?string' => $value === null || is_string($value),
                'bool'    => is_bool($value),
                'list'    => is_array($value) && array_is_list($value) && array_filter($value, 'is_string') === $value,
                'map'     => is_array($value),
            };
            if (! $ok) {
                throw OidcException::config('Provider "' . $where . '": setting "' . $name . '" must be ' . ($type === 'list' ? 'a list of strings' : ($type === 'map' ? 'an array' : 'a ' . ltrim($type, '?'))) . '.');
            }
        }
    }

    /**
     * The provider with this key from Config\ShieldOidc::$providers, with defaults applied.
     *
     * @throws OidcException When the key is unknown or the settings are invalid
     */
    public static function fromConfig(string $key, ?ShieldOidc $config = null): self
    {
        $config ??= config('ShieldOidc');
        if (! isset($config->providers[$key]) || ! is_array($config->providers[$key])) {
            throw new OidcException(lang('Oidc.unknownProvider'), 'No provider "' . $key . '" in Config\ShieldOidc::$providers.');
        }

        return new self($key, $config->providers[$key], $config->defaults);
    }

    /** True for Entra configured for more than one tenant (common/organizations/consumers). */
    public function isEntraMultiTenant(): bool
    {
        return $this->type === 'entra' && in_array(strtolower($this->tenant), self::ENTRA_MULTI, true);
    }

    /** True for Entra pinned to one organization's tenant. */
    public function isGoogle(): bool
    {
        return $this->type === 'generic' && $this->issuer === self::GOOGLE_ISSUER;
    }

    /** The configured tenant when it's a tenant id (GUID), lowercased; null for a domain or alias. */
    public function tenantGuid(): ?string
    {
        return $this->type === 'entra' && preg_match(self::GUID, $this->tenant) ? strtolower($this->tenant) : null;
    }

    /** Pattern for an Entra tenant id: 8-4-4-4-12 hex digits. */
    public const GUID = '/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i';

    /**
     * Extra authorization parameters sent when a signed-in user connects this provider, to
     * force a fresh sign-in. See the type defaults in the constructor.
     *
     * @return array<string, string>
     */
    public function reauthParams(): array
    {
        $p = (array) $this->option('reauthParams', ['prompt' => 'login', 'max_age' => '0']);

        return array_map('strval', array_filter($p, 'is_scalar'));
    }

    /** Whether a fresh-sign-in check must fail when the ID token has no auth_time. */
    public function requireAuthTime(): bool
    {
        return (bool) $this->option('requireAuthTime', true);
    }

    /** @return list<string> Extra ID token audiences accepted besides our client id */
    public function trustedAudiences(): array
    {
        return array_values((array) $this->option('trustedAudiences', []));
    }

    public function isEntraSingleTenant(): bool
    {
        return $this->type === 'entra' && ! $this->isEntraMultiTenant();
    }

    /** @return mixed */
    public function option(string $name, mixed $default = null)
    {
        return $this->o[$name] ?? $default;
    }

    /** @return list<string> */
    public function scopes(): array
    {
        return array_values(array_unique(array_merge(['openid'], (array) $this->option('scopes', []))));
    }

    /**
     * The claim that identifies a person: 'sub' (Entra: 'oid') unless configured otherwise.
     */
    public function subjectClaim(): string
    {
        return (string) $this->option('subjectClaim', 'sub');
    }

    /**
     * 'verified', 'trusted' or 'never' (validated in the constructor).
     */
    public function linkByEmail(): string
    {
        return (string) $this->option('linkByEmail', 'verified');
    }

    /** @return list<string> lowercase domains */
    public function allowedDomains(): array
    {
        return array_values(array_map(static fn (string $d) => strtolower(ltrim(trim($d), '@')), (array) $this->option('allowedDomains', [])));
    }

    /** @return list<string> lowercase tenant ids whose role/group claims are honoured (multi-tenant Entra) */
    public function groupTenants(): array
    {
        return array_map('strtolower', (array) $this->option('groupTenants', []));
    }

    /** @return array<string, list<string>> claim => accepted values */
    public function requiredClaims(): array
    {
        $out = [];
        foreach ((array) $this->option('requiredClaims', []) as $claim => $values) {
            $out[(string) $claim] = array_map('strval', is_array($values) ? array_values($values) : [$values]);
        }

        return $out;
    }

    /** @return array<string, string> claim value => Shield group */
    public function groupMap(): array
    {
        $map = [];
        foreach ((array) $this->option('groupMap', []) as $value => $group) {
            // Shield stores group names lowercased (Authorizable::addGroup), so compare that way.
            $map[(string) $value] = strtolower((string) $group);
        }

        return $map;
    }
}
