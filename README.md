# Shield OIDC

Single sign-on for [CodeIgniter Shield](https://github.com/codeigniter4/shield) with any OpenID Connect provider: **Microsoft Entra ID** (Azure AD), Okta, Google Workspace, Keycloak, Auth0, Authentik, Zitadel and the rest.

People click "Sign in with Microsoft", sign in at their organization's provider, and come back signed in to your app as a normal Shield user, with groups mapped from the provider's roles if you want.

```bash
composer require daemonlabs/shield-oidc
php spark oidc:setup
```

**[Read the full documentation](https://iamtherealtim.github.io/shield-oidc/)**: step-by-step provider guides, every option, account matching, the security model and troubleshooting. (Source in [`docs/`](docs/index.html); it's a single page that also works offline.)

## Why this package

Shield handles passwords, magic links and tokens. Organizations often want their own sign-in instead: one place to add and remove people, their MFA policies, no extra passwords. Doing that safely takes more than an OAuth redirect:

- **The ID token is verified, not just decoded**, following OpenID Connect Core 3.1.3.7: signature against the provider's published keys (RS256/384/512, ES256/384/512; weak RSA keys refused), issuer, audience (untrusted extra audiences refused), expiry, nonce and, when a fresh sign-in was asked for, `auth_time`. `alg: none`, HMAC tokens, `crit` headers and keys embedded in the token are never accepted.
- **Authorization code flow with PKCE (S256)**, single-use `state`, a per-sign-in `nonce`, and [RFC 9207](https://www.rfc-editor.org/rfc/rfc9207) issuer checks against mix-up attacks.
- **No account takeover by email.** People are matched on issuer + subject. An email only counts when the provider vouches for it in the way that provider documents (Entra's `xms_edov`, Google's `@gmail.com`/`hd` rule, `email_verified` elsewhere), and existing accounts are only linked when Shield verified their address too.
- **Entra ID done properly:** one tenant (by id or domain), any work account, personal accounts, or a list of allowed tenants; tokens checked against the tenant they came from; other organizations can't grant themselves your app's roles.
- **Works the way each provider documents**: Entra, Google, Okta, Keycloak and Auth0 behaviour was checked against their official documentation, and the per-provider differences (prompts, claims, logout parameters) are built in.
- **Follows Shield**: Shield's login, `register` and `logout` events fire, logins are recorded in `auth_logins`, pending Shield actions (Email2FA, activation) are completed on Shield's action page as with magic links, and bans are respected.
- **Keys rotate without downtime**, and a short provider outage doesn't stop sign-ins (last known good keys).
- **No new dependencies.** PHP's OpenSSL extension and CodeIgniter's HTTP client.
- `php spark oidc:check` tests each provider, prints the exact redirect URI to register, and warns about risky settings.

## Requirements

- PHP 8.1+ with the `curl`, `json` and `openssl` extensions
- CodeIgniter 4.5+ and Shield 1.1+, set up with `php spark shield:setup`
- HTTPS in production

## Setup

1. **Install:** `composer require daemonlabs/shield-oidc`, then `php spark oidc:setup` to create `app/Config/ShieldOidc.php`. Routes, commands, helper and messages are found by module discovery.
2. **Exempt the routes** from Shield's global `session` filter if you use it: add `'oidc/*'` to its `except` list in `app/Config/Filters.php`.
3. **Register your app** with the provider (see the [provider guides](https://iamtherealtim.github.io/shield-oidc/#entra)), add it to `app/Config/ShieldOidc.php`, and run `php spark oidc:check` for the redirect URI to register.
4. **Show the button** on your login page:

   ```php
   <?php helper('oidc') ?>
   <?= oidc_buttons() ?>
   ```

```php
namespace Config;

use DaemonLabs\ShieldOidc\Config\ShieldOidc as BaseShieldOidc;

class ShieldOidc extends BaseShieldOidc
{
    public array $providers = [];

    public function __construct()
    {
        parent::__construct();

        $this->providers['entra'] = [
            'type'         => 'entra',
            'tenant'       => env('ENTRA_TENANT'),        // your tenant id or domain
            'clientId'     => env('ENTRA_CLIENT_ID'),
            'clientSecret' => env('ENTRA_CLIENT_SECRET'),
        ];

        $this->providers['google'] = [
            'issuer'         => 'https://accounts.google.com',
            'clientId'       => env('GOOGLE_CLIENT_ID'),
            'clientSecret'   => env('GOOGLE_CLIENT_SECRET'),
            'requiredClaims' => ['hd' => 'yourcompany.com'],   // only your Workspace
        ];
    }
}
```

Settings are checked strictly: a misspelled or wrongly typed setting is an error, never silently ignored.

## Provider notes

These come from each provider's documentation; the [full guides](https://iamtherealtim.github.io/shield-oidc/#entra) have the click paths.

- **Microsoft Entra ID.** Keep the `profile` scope (Entra sends `oid` only with it). Add the `email` and `xms_edov` optional claims: without `xms_edov`, Entra emails aren't trusted, even in a single tenant. A Web app needs a client secret. National clouds: set `authority` (`https://login.microsoftonline.us`, `https://login.partner.microsoftonline.cn`).
- **Google.** Use `requiredClaims` `hd` (or an *Internal* OAuth audience) to limit sign-in to your Workspace. Google has no provider logout.
- **Okta.** For groups on the org authorization server, add the `groups` scope and a groups claim filter on the app's *Sign On* tab; on a custom server, add an ID-token groups claim. Register `$logoutRedirect` under *Sign-out redirect URIs*.
- **Keycloak.** Leave the client's *Exclude Issuer From Authentication Response* off. Use RS256/ES256 signatures. Groups need a *Group Membership* mapper (values like `/admins`); realm roles need a *User Realm Role* mapper added to the ID token.
- **Auth0.** Use RS256 (apps created by API default to HS256, which is refused). Turn on end-session discovery for provider logout. Roles go in a namespaced claim, e.g. `'groupsClaim' => 'https://example.com/roles'`.

## Options (summary)

| Option | What it does |
|---|---|
| `type`, `issuer`, `tenant`, `authority`, `clientId`, `clientSecret` | Which provider and app registration |
| `label`, `scopes`, `authParams`, `redirectUri` | The sign-in request and button |
| `register`, `allowedTenants`, `allowedDomains`, `requiredClaims` | Who may sign in or get an account |
| `linkByEmail` | `verified` (default), `trusted` or `never`: linking existing accounts by email |
| `subjectClaim`, `usernameClaim`, `defaultGroup` | How users are identified and created |
| `groupsClaim`, `groupMap`, `groupTenants`, `syncGroups` | Mapping roles/groups to Shield groups |
| `logoutAtProvider` | Also end the provider session on `/oidc/logout` |
| `loginActions` | Run Shield's login action (e.g. Email2FA) for SSO too |
| `tokenAuthMethod`, `trustedAudiences`, `algorithms`, `userinfo` | Protocol details for unusual setups |
| `reauthParams`, `requireAuthTime` | How a fresh sign-in is requested and checked when connecting an account |

See the [options reference](https://iamtherealtim.github.io/shield-oidc/#options) for defaults and details.

## Accounts and linking

- People are matched on issuer + subject (Entra: `oid`). First sign-in creates a Shield user if `register` is on, with the email only if it's trusted.
- An existing account is linked by email only when **both** addresses are verified: the provider's, and the local account's by Shield (registration closed, or completed email activation). Otherwise people connect the provider from their account with `oidc_link_form('entra', '/account')`, a POST form that asks the provider for a fresh sign-in.
- Users without an email identity sign in only through the provider and don't appear in Shield's `shield:user` commands.

## Security

Please report vulnerabilities privately via GitHub's "Report a vulnerability" (Security tab), not in public issues. See [SECURITY.md](SECURITY.md) and the documentation's [security section](https://iamtherealtim.github.io/shield-oidc/#security).

## Testing

```bash
composer install
composer test
```

The suite runs a fake identity provider with real RSA and EC keys: token forgeries, weak and malformed keys, key rotation and outages, the per-provider rules for Entra and Google, account takeover attempts, Shield actions and events, and the full browser round trip through Shield. The keys in `tests/Support/keys` are throwaway test keys and aren't part of the installed package.

## License

MIT. See [LICENSE](LICENSE).
