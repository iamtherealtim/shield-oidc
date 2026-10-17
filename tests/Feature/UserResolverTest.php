<?php

declare(strict_types=1);

namespace Tests\Feature;

use CodeIgniter\Shield\Entities\User;
use CodeIgniter\Shield\Models\UserIdentityModel;
use CodeIgniter\Shield\Models\UserModel;
use DaemonLabs\ShieldOidc\Config\ShieldOidc;
use DaemonLabs\ShieldOidc\Exceptions\OidcException;
use DaemonLabs\ShieldOidc\Provider;
use DaemonLabs\ShieldOidc\UserResolver;
use Tests\Support\ShieldTestCase;

/**
 * @internal
 */
final class UserResolverTest extends ShieldTestCase
{
    private ShieldOidc $config;
    private UserResolver $resolver;
    private UserModel $users;

    protected function setUp(): void
    {
        parent::setUp();
        $this->config = new ShieldOidc();
        $this->config->providers = ['fake' => ['issuer' => 'https://idp.example.test', 'clientId' => 'c', 'label' => 'Fake']];
        $this->users    = model(UserModel::class);
        $this->resolver = new UserResolver($this->users, model(UserIdentityModel::class));
        // Most tests model accounts an administrator created (registration closed), which Shield
        // vouches for; the open-registration cases are tested explicitly below.
        config('Auth')->allowRegistration = false;
    }

    private function provider(array $override = []): Provider
    {
        $this->config->providers['fake'] = $override + $this->config->providers['fake'];

        return Provider::fromConfig('fake', $this->config);
    }

    private function claims(array $extra = []): array
    {
        return $extra + ['iss' => 'https://idp.example.test', 'sub' => 'sub-1', 'email' => 'pat@example.com', 'email_verified' => true];
    }

    private function existingUser(string $email = 'pat@example.com'): User
    {
        $user = new User(['username' => 'u' . substr(md5($email), 0, 10), 'email' => $email, 'password' => 'correct horse battery staple', 'active' => 1]);
        $this->users->save($user);

        return $this->users->findById($this->users->getInsertID());
    }

    private function assertFails(string $needle, callable $fn): void
    {
        try {
            $fn();
            $this->fail('Expected failure: ' . $needle);
        } catch (OidcException $e) {
            $this->assertStringContainsStringIgnoringCase($needle, $e->getMessage() . ' ' . $e->getDetail());
        }
    }

    public function testCreatesUserOnFirstSignIn(): void
    {
        $user = $this->resolver->resolve($this->provider(), $this->claims());
        $this->assertSame('pat@example.com', $user->email);
        $this->assertTrue($user->active);
        $this->assertContains('user', $user->getGroups(), 'added to Shield\'s default group');
        $this->seeInDatabase('auth_identities', ['user_id' => $user->id, 'type' => 'oidc', 'name' => 'fake']);
    }

    public function testNewUserHasNoUsablePassword(): void
    {
        $user = $this->resolver->resolve($this->provider(), $this->claims());
        $result = auth('session')->check(['email' => 'pat@example.com', 'password' => '']);
        $this->assertFalse($result->isOK());
        $this->assertNotEmpty($user->getEmailIdentity()->secret2);
    }

    public function testSameIdentitySignsIntoSameUser(): void
    {
        $first  = $this->resolver->resolve($this->provider(), $this->claims());
        $second = $this->resolver->resolve($this->provider(), $this->claims(['email' => 'changed@example.com']));
        $this->assertSame($first->id, $second->id);
        $this->assertSame(1, $this->users->countAllResults());
    }

    public function testDifferentIssuerSameSubjectIsADifferentPerson(): void
    {
        $a = $this->resolver->resolve($this->provider(), $this->claims(['email' => 'a@example.com']));
        $b = $this->resolver->resolve($this->provider(), $this->claims(['iss' => 'https://other.example.test', 'email' => 'b@example.com']));
        $this->assertNotSame($a->id, $b->id);
    }

    public function testLinksExistingAccountWhenEmailVerified(): void
    {
        $existing = $this->existingUser();
        $user = $this->resolver->resolve($this->provider(), $this->claims());
        $this->assertSame($existing->id, $user->id);
        $this->seeInDatabase('auth_identities', ['user_id' => $existing->id, 'type' => 'oidc']);
    }

    public function testEmailMatchIsCaseInsensitive(): void
    {
        $existing = $this->existingUser('Pat@Example.com');
        $this->assertSame($existing->id, $this->resolver->resolve($this->provider(), $this->claims(['email' => 'PAT@example.COM']))->id);
    }

    /** The "nOAuth" takeover: an unverified email claim must never unlock someone else's account. */
    public function testUnverifiedEmailDoesNotTakeOverAccount(): void
    {
        $this->existingUser();
        $this->assertFails('already exists', fn () => $this->resolver->resolve($this->provider(), $this->claims(['email_verified' => false])));
        $this->assertFails('already exists', fn () => $this->resolver->resolve($this->provider(), $this->claims(['email_verified' => null])));
        $this->dontSeeInDatabase('auth_identities', ['type' => 'oidc']);
    }

    public function testEntraEmailDomainOwnerVerifiedClaimCounts(): void
    {
        $existing = $this->existingUser();
        $claims = $this->claims(['xms_edov' => true]);
        unset($claims['email_verified']);
        $this->assertSame($existing->id, $this->resolver->resolve($this->entra('organizations'), $claims + ['oid' => 'o-1'])->id);
    }

    public function testXmsEdovMeansNothingOutsideEntra(): void
    {
        $this->existingUser();
        $claims = $this->claims(['xms_edov' => true]);
        unset($claims['email_verified']);
        $this->assertFails('already exists', fn () => $this->resolver->resolve($this->provider(), $claims));
    }

    private function entra(string $tenant, array $extra = []): Provider
    {
        $this->config->providers['ms'] = ['type' => 'entra', 'tenant' => $tenant, 'clientId' => 'c'] + $extra;

        return Provider::fromConfig('ms', $this->config);
    }

    public function testLinkByEmailNever(): void
    {
        $this->existingUser();
        $this->assertFails('already exists', fn () => $this->resolver->resolve($this->provider(['linkByEmail' => 'never']), $this->claims()));
    }

    public function testLinkByEmailTrusted(): void
    {
        $existing = $this->existingUser();
        $user = $this->resolver->resolve($this->provider(['linkByEmail' => 'trusted']), $this->claims(['email_verified' => false]));
        $this->assertSame($existing->id, $user->id);
    }

    public function testRegisterOffRefusesUnknownPeople(): void
    {
        $this->assertFails('no account', fn () => $this->resolver->resolve($this->provider(['register' => false]), $this->claims()));
        $this->assertSame(0, $this->users->countAllResults());
    }

    public function testRegisterOffStillLinksVerifiedExistingAccounts(): void
    {
        $existing = $this->existingUser();
        $this->assertSame($existing->id, $this->resolver->resolve($this->provider(['register' => false]), $this->claims())->id);
    }

    public function testAllowedDomains(): void
    {
        $p = $this->provider(['allowedDomains' => ['@Example.com']]);
        $this->assertSame('pat@example.com', $this->resolver->resolve($p, $this->claims())->email);
        $this->assertFails('organization', fn () => $this->resolver->resolve($p, $this->claims(['sub' => 'sub-2', 'email' => 'eve@evil.example'])));
        $noEmail = $this->claims(['sub' => 'sub-3']);
        unset($noEmail['email']);
        $this->assertFails('organization', fn () => $this->resolver->resolve($p, $noEmail));
    }

    public function testCreatesUserWithoutEmail(): void
    {
        $claims = $this->claims();
        unset($claims['email']);
        $user = $this->resolver->resolve($this->provider(), $claims);
        $this->assertNull($user->email);
        $this->seeInDatabase('auth_identities', ['user_id' => $user->id, 'type' => 'oidc']);
    }

    public function testUsernameFromClaim(): void
    {
        $user = $this->resolver->resolve($this->provider(['usernameClaim' => 'preferred_username']), $this->claims(['preferred_username' => 'Pat.Smith@example.com']));
        $this->assertSame('pat.smith', $user->username);
    }

    public function testEntraIdentifiesByOid(): void
    {
        $this->config->providers['ms'] = ['type' => 'entra', 'tenant' => 'organizations', 'clientId' => 'c'];
        $p = Provider::fromConfig('ms', $this->config);
        $base = ['iss' => 'https://login.microsoftonline.com/t1/v2.0', 'oid' => 'object-1', 'email' => 'x@example.com'];
        $a = $this->resolver->resolve($p, $base + ['sub' => 'pairwise-1']);
        $b = $this->resolver->resolve($p, $base + ['sub' => 'pairwise-2']); // sub differs per app; oid doesn't
        $this->assertSame($a->id, $b->id);
        $this->assertFails('oid', fn () => $this->resolver->resolve($p, ['iss' => 'https://login.microsoftonline.com/t1/v2.0', 'sub' => 's']));
    }

    public function testGroupMappingAddsMappedGroups(): void
    {
        $p = $this->provider(['groupsClaim' => 'groups', 'groupMap' => ['IT-Admins' => 'admin', 'Devs' => 'developer']]);
        $user = $this->resolver->resolve($p, $this->claims(['groups' => ['IT-Admins', 'Unmapped']]));
        $this->assertTrue($user->inGroup('admin'));
        $this->assertFalse($user->inGroup('developer'));
    }

    public function testStringGroupClaimIsOneValue(): void
    {
        // "Help Desk Admins" must not match a mapping for "Admins".
        $p = $this->provider(['groupsClaim' => 'roles', 'groupMap' => ['Admins' => 'admin', 'Help Desk Admins' => 'developer']]);
        $user = $this->resolver->resolve($p, $this->claims(['roles' => 'Help Desk Admins']));
        $this->assertFalse($user->inGroup('admin'));
        $this->assertTrue($user->inGroup('developer'));
    }

    public function testSyncGroupsRemovesOnlyMappedGroups(): void
    {
        $p = $this->provider(['groupsClaim' => 'groups', 'groupMap' => ['IT-Admins' => 'admin', 'Devs' => 'developer'], 'syncGroups' => true]);
        $user = $this->resolver->resolve($p, $this->claims(['groups' => ['IT-Admins', 'Devs']]));
        $user->addGroup('beta'); // granted inside the app, not by the provider

        $user = $this->resolver->resolve($p, $this->claims(['groups' => ['Devs']]));
        $user = $this->users->findById($user->id);
        $this->assertFalse($user->inGroup('admin'), 'removed: no longer in IT-Admins');
        $this->assertTrue($user->inGroup('developer'));
        $this->assertTrue($user->inGroup('beta'), 'unmapped groups are left alone');
        $this->assertTrue($user->inGroup('user'), 'default group left alone');
    }

    public function testWithoutSyncGroupsAreOnlyAdded(): void
    {
        $p = $this->provider(['groupsClaim' => 'groups', 'groupMap' => ['IT-Admins' => 'admin']]);
        $user = $this->resolver->resolve($p, $this->claims(['groups' => ['IT-Admins']]));
        $user = $this->resolver->resolve($p, $this->claims(['groups' => []]));
        $this->assertTrue($this->users->findById($user->id)->inGroup('admin'));
    }

    public function testGroupOverageDoesNotStripGroups(): void
    {
        $p = $this->provider(['groupsClaim' => 'groups', 'groupMap' => ['IT-Admins' => 'admin'], 'syncGroups' => true]);
        $user = $this->resolver->resolve($p, $this->claims(['groups' => ['IT-Admins']]));
        $user = $this->resolver->resolve($p, $this->claims(['_claim_names' => ['groups' => 'src1']]));
        $this->assertTrue($this->users->findById($user->id)->inGroup('admin'));
    }

    public function testLinkingToSignedInUser(): void
    {
        $existing = $this->existingUser('someone@else.example');
        $user = $this->resolver->resolve($this->provider(), $this->claims(['email_verified' => false]), $existing->id);
        $this->assertSame($existing->id, $user->id);
        // From now on, this identity signs in as that user
        $this->assertSame($existing->id, $this->resolver->resolve($this->provider(), $this->claims())->id);
    }

    public function testCannotLinkIdentityOwnedByAnotherUser(): void
    {
        $owner = $this->resolver->resolve($this->provider(), $this->claims());
        $other = $this->existingUser('other@example.com');
        $this->assertFails('different user', fn () => $this->resolver->resolve($this->provider(), $this->claims(), $other->id));
        $this->assertSame($owner->id, $this->resolver->resolve($this->provider(), $this->claims())->id);
    }

    public function testIdentityStoresOnlyWhatsNeeded(): void
    {
        $this->resolver->resolve($this->provider(), $this->claims(['name' => 'Pat', 'phone_number' => '555-0100', 'address' => ['x' => 1]]));
        $extra = json_decode((string) model(UserIdentityModel::class)->where('type', 'oidc')->first()->extra, true);
        $this->assertSame(['iss', 'sub', 'email', 'name'], array_keys($extra));
    }

    /* ---------------- audit regressions ---------------- */

    /** H1: an unverified email must not pass allowedDomains or become the new account's email. */
    public function testUnverifiedEmailCannotPassAllowedDomains(): void
    {
        $p = $this->provider(['allowedDomains' => ['victim.example']]);
        $this->assertFails('organization', fn () => $this->resolver->resolve($p, $this->claims(['email' => 'ceo@victim.example', 'email_verified' => false])));
        $this->assertSame(0, $this->users->countAllResults());
    }

    public function testUnverifiedEmailIsNotSquattedOnANewAccount(): void
    {
        $attacker = $this->resolver->resolve($this->provider(), $this->claims(['sub' => 'attacker', 'email' => 'ceo@victim.example', 'email_verified' => false]));
        $this->assertNull($attacker->email, 'no email identity from an unverified claim');
        // The real owner later signs in with a verified address: a separate, new account.
        $owner = $this->resolver->resolve($this->provider(), $this->claims(['sub' => 'owner', 'email' => 'ceo@victim.example']));
        $this->assertNotSame($attacker->id, $owner->id);
        $this->assertSame('ceo@victim.example', $owner->email);
    }

    public function testEntraMultiTenantAllowedDomainsNeedsXmsEdov(): void
    {
        $p = $this->entra('organizations', ['allowedDomains' => ['victim.example']]);
        $base = ['iss' => 'https://login.microsoftonline.com/t-evil/v2.0', 'tid' => 't-evil', 'sub' => 's', 'oid' => 'o-evil', 'email' => 'anyone@victim.example'];
        $this->assertFails('organization', fn () => $this->resolver->resolve($p, $base));
        $ok = $this->resolver->resolve($p, ['xms_edov' => true] + $base);
        $this->assertSame('anyone@victim.example', $ok->email);
    }

    /** Even a single tenant's email can be typed in by an admin (MSRC 2023): only xms_edov counts. */
    public function testEntraSingleTenantEmailNeedsXmsEdov(): void
    {
        $existing = $this->existingUser();
        $p = $this->entra('11111111-1111-1111-1111-111111111111');
        $claims = ['iss' => 'https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111/v2.0', 'sub' => 's', 'oid' => 'o-1', 'email' => 'pat@example.com'];
        $this->assertFails('already exists', fn () => $this->resolver->resolve($p, $claims));
        $this->assertFails('already exists', fn () => $this->resolver->resolve($p, $claims + ['email_verified' => true]));
        $this->assertSame($existing->id, $this->resolver->resolve($p, $claims + ['xms_edov' => true])->id);
    }

    /** H2: in multi-tenant Entra, another tenant's admin assigns roles; only trusted tenants count. */
    public function testEntraMultiTenantRolesNeedGroupTenants(): void
    {
        $claims = ['iss' => 'https://login.microsoftonline.com/t-evil/v2.0', 'tid' => 't-evil', 'sub' => 's', 'oid' => 'o-1', 'roles' => ['App.Admin']];
        $user = $this->resolver->resolve($this->entra('organizations', ['groupMap' => ['App.Admin' => 'admin']]), $claims);
        $this->assertFalse($user->inGroup('admin'), 'foreign tenant cannot grant admin');

        $p = $this->entra('organizations', ['groupMap' => ['App.Admin' => 'admin'], 'groupTenants' => ['T-HOME']]);
        $this->assertFalse($this->resolver->resolve($p, $claims)->inGroup('admin'));
        $home = ['iss' => 'https://login.microsoftonline.com/t-home/v2.0', 'tid' => 't-home', 'oid' => 'o-2'] + $claims;
        $this->assertTrue($this->resolver->resolve($p, $home)->inGroup('admin'));
    }

    public function testRequiredClaims(): void
    {
        $p = $this->provider(['requiredClaims' => ['hd' => 'example.com']]);
        $this->assertSame('pat@example.com', $this->resolver->resolve($p, $this->claims(['hd' => 'example.com']))->email);
        $this->assertFails('organization', fn () => $this->resolver->resolve($p, $this->claims(['sub' => 'consumer'])));
        $this->assertFails('organization', fn () => $this->resolver->resolve($p, $this->claims(['sub' => 'other', 'hd' => 'other.example'])));
    }

    /** L1: restrictions apply on every sign-in and when linking, not just registration. */
    public function testAllowedDomainsAppliesToReturningSignInsAndLinking(): void
    {
        $this->resolver->resolve($this->provider(), $this->claims(['email' => 'pat@gmail.example']));
        $p = $this->provider(['allowedDomains' => ['example.com']]);
        $this->assertFails('organization', fn () => $this->resolver->resolve($p, $this->claims(['email' => 'pat@gmail.example'])));

        $local = $this->existingUser('pat@example.com');
        $this->assertFails('organization', fn () => $this->resolver->resolve($p, $this->claims(['sub' => 'x', 'email' => 'p@gmail.example']), $local->id));
    }

    public function testBannedUserIsRefusedBeforeAnythingChanges(): void
    {
        $existing = $this->existingUser();
        $existing->ban('Gone');
        $this->assertFails('Gone', fn () => $this->resolver->resolve($this->provider(['groupsClaim' => 'groups', 'groupMap' => ['A' => 'admin']]), $this->claims(['groups' => ['A']])));
        $this->dontSeeInDatabase('auth_identities', ['type' => 'oidc']);
        $this->assertFalse($this->users->findById($existing->id)->inGroup('admin'));
    }

    public function testSchemelessIssuerIsTheSameIdentity(): void
    {
        $a = $this->resolver->identityKey($this->provider(), ['iss' => 'https://accounts.google.com', 'sub' => '1']);
        $b = $this->resolver->identityKey($this->provider(), ['iss' => 'accounts.google.com', 'sub' => '1']);
        $this->assertSame($a, $b);
    }

    public function testSyncDoesNotStripGroupsWhenClaimMissing(): void
    {
        $p = $this->provider(['groupsClaim' => 'groups', 'groupMap' => ['A' => 'admin'], 'syncGroups' => true]);
        $user = $this->resolver->resolve($p, $this->claims(['groups' => ['A']]));
        $this->resolver->resolve($p, $this->claims()); // e.g. the groups scope was dropped
        $this->assertTrue($this->users->findById($user->id)->inGroup('admin'));
    }

    /* ---------------- Shield conformance ---------------- */

    /** Open registration without email activation: Shield never verified the local address. */
    public function testNoAutoLinkWhenShieldNeverVerifiedTheLocalEmail(): void
    {
        config('Auth')->allowRegistration = true;
        config('Auth')->actions['register'] = null;
        $this->existingUser(); // e.g. someone who registered the victim's address first
        $this->assertFails('not verified by Shield', fn () => $this->resolver->resolve($this->provider(), $this->claims()));
        $this->dontSeeInDatabase('auth_identities', ['type' => 'oidc']);
    }

    public function testAutoLinkWhenShieldActivatedTheLocalEmail(): void
    {
        config('Auth')->allowRegistration = true;
        config('Auth')->actions['register'] = \CodeIgniter\Shield\Authentication\Actions\EmailActivator::class;
        $existing = $this->existingUser(); // active = 1: completed activation
        $this->assertSame($existing->id, $this->resolver->resolve($this->provider(), $this->claims())->id);

        $pending = new User(['username' => 'pending', 'email' => 'new@example.com', 'password' => 'correct horse battery staple', 'active' => 0]);
        $this->users->save($pending);
        $this->assertFails('not verified by Shield', fn () => $this->resolver->resolve($this->provider(), $this->claims(['sub' => 's-2', 'email' => 'new@example.com'])));
    }

    /** Shield stores group names lowercased; a mixed-case groupMap must still be removable. */
    public function testMixedCaseGroupMapSyncsCorrectly(): void
    {
        $p = $this->provider(['groupsClaim' => 'groups', 'groupMap' => ['app-admins' => 'Admin'], 'syncGroups' => true]);
        $user = $this->resolver->resolve($p, $this->claims(['groups' => ['app-admins']]));
        $this->assertTrue($this->users->findById($user->id)->inGroup('admin'));
        $this->resolver->resolve($p, $this->claims(['groups' => []]));
        $this->assertFalse($this->users->findById($user->id)->inGroup('admin'), 'role withdrawn, admin removed');
    }

    public function testFiresShieldRegisterEvent(): void
    {
        $seen = null;
        \CodeIgniter\Events\Events::on('register', static function ($u) use (&$seen): void {
            $seen = $u;
        });
        $user = $this->resolver->resolve($this->provider(), $this->claims());
        $this->assertSame($user->id, $seen?->id);
    }

    /**
     * Google: authoritative only for @gmail.com, or email_verified together with hd
     * (developers.google.com/identity/gsi/web/guides/verify-google-id-token).
     */
    public function testGoogleEmailTrustRules(): void
    {
        $this->config->providers['google'] = ['issuer' => 'https://accounts.google.com', 'clientId' => 'g'];
        $g    = Provider::fromConfig('google', $this->config);
        $base = ['iss' => 'https://accounts.google.com', 'email_verified' => true];

        // A consumer account with a third-party address: verified once, maybe not owned now.
        $existing = $this->existingUser('pat@company.example');
        $this->assertFails('already exists', fn () => $this->resolver->resolve($g, $base + ['sub' => '1', 'email' => 'pat@company.example']));
        // A Workspace account (hd present) is authoritative.
        $this->assertSame($existing->id, $this->resolver->resolve($g, $base + ['sub' => '2', 'email' => 'pat@company.example', 'hd' => 'company.example'])->id);
        // Gmail addresses are authoritative.
        $gmail = $this->existingUser('someone@gmail.com');
        $this->assertSame($gmail->id, $this->resolver->resolve($g, ['iss' => 'https://accounts.google.com', 'sub' => '3', 'email' => 'someone@gmail.com'])->id);
    }

    public function testFailedUserCreationLeavesNoOrphan(): void
    {
        config('AuthGroups')->defaultGroup = 'no-such-group';
        $this->assertFails('created', fn () => $this->resolver->resolve($this->provider(), $this->claims()));
        $this->assertSame(0, $this->users->countAllResults());
        $this->dontSeeInDatabase('auth_identities', ['type' => 'oidc']);
    }
}
