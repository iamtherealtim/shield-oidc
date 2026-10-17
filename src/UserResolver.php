<?php

declare(strict_types=1);

namespace DaemonLabs\ShieldOidc;

use CodeIgniter\Events\Events;
use CodeIgniter\I18n\Time;
use CodeIgniter\Shield\Entities\User;
use CodeIgniter\Shield\Entities\UserIdentity;
use CodeIgniter\Shield\Models\UserIdentityModel;
use CodeIgniter\Shield\Models\UserModel;
use DaemonLabs\ShieldOidc\Exceptions\OidcException;
use Throwable;

/**
 * Turns verified claims into a Shield user: finds the account already linked to this identity,
 * links an existing account when that's safe, or creates a new one. Extend it and set
 * ShieldOidc::$userResolver to change any step (e.g. newUserData()).
 *
 * People are matched on issuer + subject, never on email alone. An email claim is only used
 * (to link an account, to check allowedDomains, or as a new account's email) when it can be
 * trusted: the provider verified it, it comes from a single Entra tenant you control, or you
 * opted in with linkByEmail => 'trusted'.
 */
class UserResolver
{
    public const IDENTITY_TYPE = 'oidc';

    /**
     * Built by the oidcUserResolver service; extend the class and set ShieldOidc::$userResolver
     * to use your own.
     */
    public function __construct(
        protected readonly UserModel $users,
        protected readonly UserIdentityModel $identities,
    ) {
        // Shield needs these; apps usually autoload them, but don't depend on it.
        helper(['auth', 'setting']);
    }

    /**
     * @param array<string, mixed> $claims     Verified claims
     * @param int|string|null      $linkUserId The signed-in user connecting this provider, if any
     *
     * @throws OidcException
     */
    public function resolve(Provider $provider, array $claims, int|string|null $linkUserId = null): User
    {
        $key      = $this->identityKey($provider, $claims);
        $identity = $this->findIdentity($key);
        $trusted  = $this->trustedEmail($provider, $claims);

        // Who may come in at all: checked on every sign-in and link, before anything is written.
        $this->checkRequiredClaims($provider, $claims);
        $this->checkDomain($provider, $trusted);

        // Connecting a provider to the account that's signed in right now.
        if ($linkUserId !== null) {
            if ($identity !== null && (string) $identity->user_id !== (string) $linkUserId) {
                throw new OidcException(lang('Oidc.alreadyLinked', [$provider->label]), 'Identity belongs to user ' . $identity->user_id . '.');
            }
            $user = $this->usableUser($linkUserId);
            if ($identity === null) {
                $this->addIdentity($user, $provider, $key, $claims);
                Events::trigger('oidcLink', $user, $claims, $provider->key);
            }

            return $this->finish($user, $provider, $claims, $key);
        }

        if ($identity !== null) {
            return $this->finish($this->usableUser($identity->user_id), $provider, $claims, $key);
        }

        // First sign-in with this identity. Look for an account with the same address, even if
        // the address isn't trusted, so we can explain rather than create a confusing duplicate.
        $email    = $this->email($claims);
        $existing = $email !== null ? $this->users->findByCredentials(['email' => $email]) : null;

        if ($existing !== null) {
            $localVerified = $this->localEmailVerified($existing);
            if ($trusted === null || $provider->linkByEmail() === 'never' || ! $localVerified) {
                // Both addresses must be verified: the provider's (see trustedEmail()) and the
                // local account's, or someone could pre-register a victim's address here and
                // wait for the victim's first SSO sign-in to be linked into it.
                throw new OidcException(
                    lang('Oidc.emailTaken', [$provider->label]),
                    'An account with ' . $email . ' exists; not linking (provider email ' . ($trusted === null ? 'not verified' : 'verified')
                        . ', linkByEmail "' . $provider->linkByEmail() . '", local email ' . ($localVerified ? 'verified' : 'not verified by Shield') . ').',
                );
            }
            $this->assertNotBanned($existing);
            $this->addIdentity($existing, $provider, $key, $claims);
            Events::trigger('oidcLink', $existing, $claims, $provider->key);

            return $this->finish($existing, $provider, $claims, $key);
        }

        if (! $provider->option('register', true)) {
            throw new OidcException(lang('Oidc.noAccount'), 'No account for this identity and register is off.');
        }

        // User and identity are created together or not at all: a failure in between (e.g. an
        // invalid default group) mustn't leave an orphan user that the next attempt duplicates.
        $db = $this->users->db;
        $db->transBegin();

        try {
            $user = $this->createUser($provider, $claims, $trusted);
            $this->addIdentity($user, $provider, $key, $claims);
            $db->transCommit();
        } catch (Throwable $e) {
            $db->transRollback();

            throw $e instanceof OidcException ? $e : new OidcException(lang('Oidc.registerFailed'), 'Creating the user failed: ' . $e->getMessage(), $e);
        }
        // Shield's own registration event, so the app's usual listeners (welcome mail, profile
        // rows) see SSO users too; then ours, with the claims.
        Events::trigger('register', $user);
        Events::trigger('oidcRegister', $user, $claims, $provider->key);

        return $this->finish($user, $provider, $claims, $key);
    }

    /**
     * Does Shield vouch for the local account's email address? Only then may a first SSO
     * sign-in attach to it by email. True when registration is closed (accounts were made by
     * an administrator), or when registration requires an email Activator and this account
     * completed it. With open registration and no activation, anyone could have registered
     * the address, and Shield's "active" flag doesn't prove otherwise.
     */
    protected function localEmailVerified(User $user): bool
    {
        if (! setting('Auth.allowRegistration')) {
            return true;
        }
        $registerAction = (string) (setting('Auth.actions')['register'] ?? '');

        return $registerAction !== '' && str_contains($registerAction, 'Activator') && (bool) $user->active;
    }

    /**
     * The value stored in auth_identities.secret: a hash of issuer + subject, so long issuers
     * fit the column and the pair stays unique across providers and Entra tenants.
     *
     * @param array<string, mixed> $claims
     */
    public function identityKey(Provider $provider, array $claims): string
    {
        $subject = $claims[$provider->subjectClaim()] ?? null;
        if (! is_string($subject) || $subject === '') {
            throw OidcException::token('ID token has no "' . $provider->subjectClaim() . '" claim to identify the user.');
        }

        // Normalize so "accounts.google.com" and "https://accounts.google.com" are one issuer.
        $iss = rtrim((string) $claims['iss'], '/');
        if (! str_contains($iss, '://')) {
            $iss = 'https://' . $iss;
        }

        return hash('sha256', $iss . '|' . $subject);
    }

    /**
     * The person's email, lowercased, if it's well-formed; null otherwise. Not necessarily trusted.
     *
     * @param array<string, mixed> $claims
     */
    protected function email(array $claims): ?string
    {
        $email = $claims['email'] ?? null;
        if (! is_string($email) || filter_var($email, FILTER_VALIDATE_EMAIL) === false) {
            return null;
        }

        return strtolower($email);
    }

    /**
     * The email if it can be trusted to belong to this person, else null. Each provider
     * documents what makes its email authoritative, and that's what is checked:
     *
     *  - Entra: only the xms_edov optional claim ("the email domain owner is verified").
     *    Entra doesn't document email_verified, and its email claim can hold an address an
     *    administrator typed in, even in a single-tenant app (MSRC, June 2023).
     *  - Google: an @gmail.com address, or email_verified together with the hd claim.
     *    Google warns email_verified alone can be stale for third-party addresses.
     *  - Everyone else: email_verified (OpenID Connect Core 5.1).
     *  - Any provider: linkByEmail => 'trusted' (the app owner vouches for the provider).
     *
     * @param array<string, mixed> $claims
     */
    protected function trustedEmail(Provider $provider, array $claims): ?string
    {
        $email = $this->email($claims);
        if ($email === null) {
            return null;
        }
        if ($provider->linkByEmail() === 'trusted') {
            return $email;
        }
        $trusted = match (true) {
            $provider->type === 'entra' => self::truthy($claims['xms_edov'] ?? null),
            $provider->isGoogle()       => str_ends_with($email, '@gmail.com')
                || (self::truthy($claims['email_verified'] ?? null) && is_string($claims['hd'] ?? null) && $claims['hd'] !== ''),
            default                     => self::truthy($claims['email_verified'] ?? null),
        };

        return $trusted ? $email : null;
    }

    /** @param array<string, mixed> $claims */
    protected function checkRequiredClaims(Provider $provider, array $claims): void
    {
        foreach ($provider->requiredClaims() as $claim => $accepted) {
            $value = $claims[$claim] ?? null;
            $values = is_array($value) ? array_map('strval', array_filter($value, 'is_scalar')) : (is_scalar($value) ? [(string) $value] : []);
            if (array_intersect($values, $accepted) === []) {
                throw new OidcException(lang('Oidc.domainNotAllowed'), 'Required claim "' . $claim . '" is missing or not one of the accepted values.');
            }
        }
    }

    /**
     * allowedDomains: the person's trusted email must be in one of the listed domains (exact
     * match, no subdomains). An untrusted or missing email never passes.
     *
     * @throws OidcException
     */
    protected function checkDomain(Provider $provider, ?string $trustedEmail): void
    {
        $domains = $provider->allowedDomains();
        if ($domains === []) {
            return;
        }
        $domain = $trustedEmail !== null ? substr($trustedEmail, strrpos($trustedEmail, '@') + 1) : '';
        if ($domain === '' || ! in_array($domain, $domains, true)) {
            throw new OidcException(
                lang('Oidc.domainNotAllowed'),
                $trustedEmail === null ? 'allowedDomains is set but the token has no verified email.' : 'Email domain "' . $domain . '" is not in allowedDomains.',
            );
        }
    }

    /**
     * The user with this id, refused when missing, banned or (when Shield requires activation)
     * not activated, so the session filter wouldn't bounce them straight back out.
     *
     * @throws OidcException
     */
    protected function usableUser(int|string $id): User
    {
        $user = $this->users->findById($id);
        if ($user === null) {
            throw new OidcException(lang('Oidc.noAccount'), 'User ' . $id . ' no longer exists.');
        }
        $this->assertNotBanned($user);
        if (! $user->isActivated()) {
            throw new OidcException(lang('Oidc.notActivated'), 'User ' . $id . ' is not activated.');
        }

        return $user;
    }

    /**
     * Banned users are refused with Shield's ban message, before anything about them changes.
     *
     * @throws OidcException
     */
    protected function assertNotBanned(User $user): void
    {
        if ($user->isBanned()) {
            throw new OidcException($user->getBanMessage() ?? lang('Auth.bannedUser'), 'User ' . $user->id . ' is banned.');
        }
    }

    /**
     * Fields for a brand-new user. Override to set a username or your own columns.
     *
     * @param array<string, mixed> $claims
     *
     * @return array<string, mixed>
     */
    protected function newUserData(Provider $provider, array $claims, ?string $trustedEmail): array
    {
        // Shield's docs: set username (null if none) so the insert never looks empty.
        $data = ['active' => 1, 'username' => null];
        if ($trustedEmail !== null) {
            // No usable password: this person signs in through the provider. A random hash
            // (never shown) keeps Shield's email identity intact without an empty secret.
            $data['email']         = $trustedEmail;
            $data['password_hash'] = service('passwords')->hash(bin2hex(random_bytes(32)));
        }
        // Without a trusted email there's no email identity at all (an unverified address
        // could squat someone else's; a blank one would collide with the next such user).
        // These people sign in only through the provider.

        $claim = $provider->option('usernameClaim');
        if (is_string($claim) && is_string($claims[$claim] ?? null)) {
            $username = $this->usableUsername($claims[$claim]);
            if ($username !== null) {
                $data['username'] = $username;
            }
        }

        return $data;
    }

    /** @param array<string, mixed> $claims */
    protected function createUser(Provider $provider, array $claims, ?string $trustedEmail): User
    {
        $data = $this->newUserData($provider, $claims, $trustedEmail);
        // Shield 1.2+ builds the app's own user entity class; 1.1 has only the default.
        $user = method_exists($this->users, 'createNewUser') ? $this->users->createNewUser($data) : new User($data);

        try {
            $this->users->save($user);
        } catch (Throwable $e) {
            throw new OidcException(lang('Oidc.registerFailed'), 'Creating the user failed: ' . $e->getMessage(), $e);
        }
        $user = $this->users->findById($this->users->getInsertID());
        if ($user === null) {
            throw new OidcException(lang('Oidc.registerFailed'), 'The new user could not be read back.');
        }
        if ($provider->option('defaultGroup', true) !== false) {
            $this->users->addToDefaultGroup($user);
        }

        return $user;
    }

    /**
     * The 'oidc' identity with this key (see identityKey()), or null.
     */
    protected function findIdentity(string $key): ?UserIdentity
    {
        $identity = $this->identities->where('type', self::IDENTITY_TYPE)->where('secret', $key)->first();

        return $identity instanceof UserIdentity ? $identity : null;
    }

    /** @param array<string, mixed> $claims */
    protected function addIdentity(User $user, Provider $provider, string $key, array $claims): void
    {
        try {
            $this->identities->create([
                'user_id' => $user->id,
                'type'    => self::IDENTITY_TYPE,
                'name'    => $provider->key,
                'secret'  => $key,
                'extra'   => $this->identityExtra($provider, $claims),
            ]);
        } catch (Throwable $e) {
            // Two first sign-ins at once: the other request may have just created it.
            $existing = $this->findIdentity($key);
            if ($existing === null || (string) $existing->user_id !== (string) $user->id) {
                throw new OidcException(lang('Oidc.registerFailed'), 'Saving the identity failed: ' . $e->getMessage(), $e);
            }
        }
    }

    /**
     * What we keep about the identity: enough to show "connected to Microsoft as pat@example.com"
     * and to debug, nothing more.
     *
     * @param array<string, mixed> $claims
     */
    protected function identityExtra(Provider $provider, array $claims): string
    {
        $keep = ['iss' => $claims['iss'] ?? null, 'sub' => $claims[$provider->subjectClaim()] ?? null];
        foreach (['email', 'name', 'tid'] as $k) {
            if (is_string($claims[$k] ?? null)) {
                $keep[$k] = mb_substr($claims[$k], 0, 255);
            }
        }

        return (string) json_encode($keep, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);
    }

    /** @param array<string, mixed> $claims */
    protected function finish(User $user, Provider $provider, array $claims, string $key): User
    {
        $identity = $this->findIdentity($key);
        if ($identity !== null) {
            // A plain array update: saving an unchanged entity throws "no data to update".
            $this->identities->update($identity->id, [
                'extra'        => $this->identityExtra($provider, $claims),
                'last_used_at' => Time::now()->format('Y-m-d H:i:s'),
            ]);
        }
        $this->syncGroups($user, $provider, $claims);

        return $user;
    }

    /**
     * Adds Shield groups mapped from the groups/roles claim; with syncGroups also removes
     * mapped groups the person no longer has. Unmapped groups are never touched, and nothing
     * is removed when the claim is absent (a scope or config slip shouldn't demote everyone).
     *
     * @param array<string, mixed> $claims
     */
    protected function syncGroups(User $user, Provider $provider, array $claims): void
    {
        $map   = $provider->groupMap();
        $claim = $provider->option('groupsClaim');
        if ($map === [] || ! is_string($claim) || $claim === '') {
            return;
        }
        // Multi-tenant Entra: app roles and groups are assigned by each user's own tenant, so
        // another organization's admin could grant themselves any mapped role. Only honour
        // tenants listed in groupTenants.
        if ($provider->isEntraMultiTenant() && ! in_array(strtolower((string) ($claims['tid'] ?? '')), $provider->groupTenants(), true)) {
            return;
        }
        if (isset($claims['_claim_names']) && is_array($claims['_claim_names']) && isset($claims['_claim_names'][$claim])) {
            log_message('warning', 'Shield OIDC: provider {p} sent a "{c}" overage reference instead of the list (too many groups). Use app roles instead.', ['p' => $provider->key, 'c' => $claim]);

            return; // don't remove groups based on a list we didn't get
        }
        if (! array_key_exists($claim, $claims)) {
            return;
        }

        $values = $claims[$claim];
        // A string claim is one value: splitting "Help Desk Admins" on spaces would match "Admins".
        $values = is_array($values) ? array_map('strval', array_filter($values, 'is_scalar')) : (is_scalar($values) ? [(string) $values] : []);

        $want = [];
        foreach ($map as $claimValue => $group) {
            if (in_array($claimValue, $values, true)) {
                $want[$group] = true;
            }
        }
        $current = $user->getGroups() ?? [];

        foreach (array_keys($want) as $group) {
            if (! in_array($group, $current, true)) {
                try {
                    $user->addGroup($group);
                } catch (Throwable $e) {
                    log_message('error', 'Shield OIDC: could not add group {g}: {m}', ['g' => $group, 'm' => $e->getMessage()]);
                }
            }
        }
        if ($provider->option('syncGroups', false)) {
            foreach (array_unique(array_values($map)) as $group) {
                if (! isset($want[$group]) && in_array($group, $current, true)) {
                    $user->removeGroup($group);
                }
            }
        }
    }

    /**
     * A Shield username derived from a claim (the part before any @, lowercased, a-z 0-9 . _ -),
     * or null when it's too short or long, or already taken. Note that whoever signs in first
     * gets a free username, so don't use this with claims people choose freely if names like
     * "admin" matter in your app.
     */
    protected function usableUsername(string $value): ?string
    {
        $value = strtolower(trim(explode('@', $value)[0]));
        $value = preg_replace('/[^a-z0-9._-]/', '', $value) ?? '';
        if (strlen($value) < 3 || strlen($value) > 30 || $this->users->where('username', $value)->first() !== null) {
            return null;
        }

        return $value;
    }

    /**
     * Providers send booleans as true, 1, "true" or "1".
     */
    private static function truthy(mixed $v): bool
    {
        return $v === true || $v === 1 || $v === 'true' || $v === '1';
    }
}
