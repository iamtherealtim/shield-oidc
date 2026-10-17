# Changelog

## 1.0.0 (unreleased)

First release.

### Sign-in
- OpenID Connect authorization code flow with PKCE (S256), single-use state, nonce, and RFC 9207 issuer checks (made before anything else in the response, and required when the provider advertises them).
- ID token verification with PHP's OpenSSL extension, per OpenID Connect Core 1.0 (errata set 2): RS256/384/512 and ES256/384/512; weak RSA keys refused; `alg: none`, HMAC tokens and critical headers rejected; header-embedded keys never used; issuer-scoped keys honoured; untrusted extra audiences refused (`trustedAudiences` to allow); `auth_time` checked when a fresh sign-in was requested.
- Keys refetched only for a new key id, at most every 5 minutes; last-known-good discovery and keys used during provider outages.
- Userinfo only with a Bearer access token; an email's verification flags never come from a different source than the email.
- Client authentication with exactly one method, automatic or set with `tokenAuthMethod`.

### Providers (checked against each provider's documentation)
- Microsoft Entra ID: single tenant (id or domain, pinned), `organizations`, `common`, `consumers`, `allowedTenants`, national clouds via `authority`; users identified by `oid`; emails trusted only with `xms_edov`; roles from multi-tenant apps honoured only for `groupTenants`; linking uses `prompt=login`; logout uses `logout_hint`; userinfo off by default.
- Google: emails trusted only for `@gmail.com` or `email_verified` with `hd`; linking uses the account picker; scheme-less issuer accepted in ID tokens only.
- Generic providers (Okta, Keycloak, Auth0 and others): linking sends `prompt=login` and `max_age=0` and requires `auth_time` (configurable with `reauthParams` and `requireAuthTime`).

### Shield
- Users matched on issuer + subject; email linking only when the provider's email is trusted and Shield verified the local account's address (closed registration or email activation); explicit connect flow (`oidc_link_form()`, POST + session token).
- New users created with Shield's `createNewUser()` where available, in a transaction with their identity; Shield's `register` event fired.
- Pending Shield actions (Email2FA, activation) completed on Shield's action page, as with magic links; `loginActions` to start configured login actions for SSO too.
- Group names compared as Shield stores them (lowercase); `syncGroups` never strips groups when the claim is missing; `oidc:check` validates group names.
- Bans and activation respected; logins recorded in `auth_logins`; Shield's cookies kept on the redirect; `Referrer-Policy: no-referrer` on the callback.

### Tools
- Strict provider settings: unknown or mistyped options, and reserved `authParams`, are errors.
- `oidc:setup` and `oidc:check` (redirect URIs, risky-setting warnings, Entra `profile` scope and `xms_edov`, Shield group names).
- `oidc_buttons()`, `oidc_login_url()`, `oidc_link_form()` helpers; `oidcLogin`, `oidcRegister`, `oidcLink`, `oidcFailed` events; RP-initiated logout.
