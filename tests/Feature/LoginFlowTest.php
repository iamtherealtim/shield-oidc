<?php

declare(strict_types=1);

namespace Tests\Feature;

use CodeIgniter\Config\Factories;
use CodeIgniter\Shield\Entities\User;
use CodeIgniter\Shield\Models\UserModel;
use CodeIgniter\Test\FeatureTestTrait;
use CodeIgniter\Test\Mock\MockCache;
use CodeIgniter\Test\TestResponse;
use Config\Services;
use DaemonLabs\ShieldOidc\Config\ShieldOidc;
use DaemonLabs\ShieldOidc\Controllers\OidcController;
use DaemonLabs\ShieldOidc\OidcClient;
use Tests\Support\FakeProvider;
use Tests\Support\ShieldTestCase;

/**
 * The whole browser round trip through the package's routes, ending in a real Shield login.
 *
 * @internal
 */
final class LoginFlowTest extends ShieldTestCase
{
    use FeatureTestTrait;

    private FakeProvider $idp;
    private ShieldOidc $config;

    protected function setUp(): void
    {
        parent::setUp();
        $this->idp    = new FakeProvider();
        $this->config = new ShieldOidc();
        $this->config->providers = [
            'fake' => ['label' => 'Fake IdP', 'issuer' => $this->idp->issuer, 'clientId' => 'client-123', 'clientSecret' => 's3cret', 'logoutAtProvider' => true],
        ];
        Factories::injectMock('config', 'ShieldOidc', $this->config);
        Services::injectMock('oidcClient', new OidcClient($this->config, $this->idp, new MockCache(), service('session')));
        Services::resetSingle('oidcUserResolver');
        $this->session = [];
    }

    /** GET (or POST) a path, carrying the session along like a browser would. */
    private function browse(string $path, array $params = [], string $method = 'get'): TestResponse
    {
        // Each real request builds a fresh authenticator; the shared test instance would
        // otherwise remember who was signed in regardless of the session.
        Services::resetSingle('auth');
        $result        = $this->withSession($this->session)->{$method}($path, $params);
        $this->session = $_SESSION;

        return $result;
    }

    private function assertRedirectsTo(string $path, TestResponse $result): void
    {
        $this->assertSame(rtrim(site_url($path), '/'), rtrim((string) $result->getRedirectUrl(), '/'));
    }

    /** Start at /oidc/fake/login, "sign in" at the provider, come back to the callback. */
    private function signIn(array $claims = [], string $start = 'oidc/fake/login', array $startQuery = [], string $method = 'get'): TestResponse
    {
        $result = $this->browse($start, $startQuery, $method);
        $result->assertRedirect();
        $q = $this->idp->sawAuthorizationUrl($result->getRedirectUrl());
        $this->idp->claims = $claims + ['email' => 'pat@example.com', 'email_verified' => true] + $this->idp->baseClaims();

        return $this->browse('oidc/fake/callback', ['code' => 'the-code', 'state' => $q['state']]);
    }

    private function signedInUserId(): int|string|null
    {
        return $this->session['user']['id'] ?? null;
    }

    public function testLoginRedirectsToProvider(): void
    {
        $result = $this->browse('oidc/fake/login');
        $result->assertRedirect();
        $this->assertStringStartsWith($this->idp->issuer . '/authorize?', $result->getRedirectUrl());
    }

    public function testFullSignInCreatesUserAndLogsIn(): void
    {
        $result = $this->signIn();
        $this->assertRedirectsTo('/', $result);

        $user = model(UserModel::class)->findByCredentials(['email' => 'pat@example.com']);
        $this->assertInstanceOf(User::class, $user);
        $this->assertSame((string) $user->id, (string) $this->signedInUserId());
        $this->seeInDatabase('auth_logins', ['id_type' => 'oidc', 'identifier' => 'fake:pat@example.com', 'success' => 1, 'user_id' => $user->id]);
    }

    public function testReturnPathIsHonoured(): void
    {
        $this->assertRedirectsTo('/reports?week=3', $this->signIn([], 'oidc/fake/login', ['return' => '/reports?week=3']));
    }

    public function testOffSiteReturnIsIgnored(): void
    {
        $this->assertRedirectsTo('/', $this->signIn([], 'oidc/fake/login', ['return' => '//evil.example/phish']));
    }

    public function testFailedSignInGoesBackToLoginWithMessage(): void
    {
        $this->browse('oidc/fake/login');
        $result = $this->browse('oidc/fake/callback', ['code' => 'x', 'state' => 'forged']);
        $this->assertRedirectsTo('/login', $result);
        $result->assertSessionHas('error', lang('Oidc.stateInvalid'));
        $this->assertNull($this->signedInUserId());
    }

    public function testProviderErrorIsShownKindly(): void
    {
        $result = $this->browse('oidc/fake/login');
        $q = $this->idp->sawAuthorizationUrl($result->getRedirectUrl());
        $result = $this->browse('oidc/fake/callback', ['error' => 'access_denied', 'error_description' => 'User cancelled', 'state' => $q['state']]);
        $result->assertSessionHas('error', lang('Oidc.accessDenied'));
    }

    public function testBannedUserCannotSignIn(): void
    {
        $this->signIn();
        $user = model(UserModel::class)->findByCredentials(['email' => 'pat@example.com']);
        $user->ban('Left the company');
        $this->session = [];

        $result = $this->signIn();
        $result->assertSessionHas('error', 'Left the company');
        $this->assertNull($this->signedInUserId());
        $this->seeInDatabase('auth_logins', ['id_type' => 'oidc', 'identifier' => 'fake:pat@example.com', 'success' => 0]);
    }

    public function testUnknownProviderIs404(): void
    {
        $this->expectException(\CodeIgniter\Exceptions\PageNotFoundException::class);
        $this->browse('oidc/nope/login');
    }

    public function testSignedInUserCanConnectProvider(): void
    {
        $user = new User(['username' => 'pat', 'email' => 'pat@company.example', 'password' => 'correct horse battery staple', 'active' => 1]);
        model(UserModel::class)->save($user);
        $id = model(UserModel::class)->getInsertID();
        $this->session = ['user' => ['id' => $id], OidcController::SESSION_LINK_TOKEN => 'form-token'];

        // The IdP's email differs and isn't verified: only the explicit connect flow can link it.
        $result = $this->signIn(['email' => 'p.smith@idp.example', 'email_verified' => false, 'auth_time' => time()], 'oidc/fake/link', ['oidc_link_token' => 'form-token', 'return' => '/account'], 'post');
        $this->assertRedirectsTo('/account', $result);
        $result->assertSessionHas('message', lang('Oidc.linked', ['Fake IdP']));
        $this->seeInDatabase('auth_identities', ['user_id' => $id, 'type' => 'oidc', 'name' => 'fake']);

        // Next time, the provider signs straight into that account.
        $this->session = [];
        $this->signIn(['email' => 'p.smith@idp.example', 'email_verified' => false]);
        $this->assertSame((string) $id, (string) $this->signedInUserId());
    }

    public function testConnectRequiresBeingSignedIn(): void
    {
        $this->session = [OidcController::SESSION_LINK_TOKEN => 'form-token'];
        $result = $this->browse('oidc/fake/link', ['oidc_link_token' => 'form-token'], 'post');
        $result->assertSessionHas('error', lang('Oidc.linkNeedsLogin'));
    }

    /** M1: another site must not be able to start linking for a signed-in visitor. */
    public function testLinkingCannotBeTriggeredCrossSite(): void
    {
        $this->signIn();
        $userId = $this->signedInUserId();

        // A plain link (GET) doesn't link anything: signed-in users are just sent onwards.
        $result = $this->browse('oidc/fake/login', ['link' => '1']);
        $this->assertStringStartsNotWith($this->idp->issuer, (string) $result->getRedirectUrl());

        // A cross-site form POST lacks the session's token.
        $this->session[OidcController::SESSION_LINK_TOKEN] = 'real-token';
        foreach ([[], ['oidc_link_token' => 'guessed'], ['oidc_link_token' => ['real-token']]] as $post) {
            $result = $this->browse('oidc/fake/link', $post, 'post');
            $result->assertSessionHas('error', lang('Oidc.stateInvalid'));
        }
        $this->assertSame($userId, $this->signedInUserId());
    }

    public function testLinkFormHelper(): void
    {
        helper('oidc');
        $html = html_entity_decode(oidc_link_form('fake', '/account'));
        $this->assertStringContainsString('method="post"', $html);
        $this->assertStringContainsString('/oidc/fake/link', $html);
        $this->assertStringContainsString('name="oidc_link_token" value="' . session(OidcController::SESSION_LINK_TOKEN) . '"', $html);
        $this->assertStringContainsString('Connect Fake IdP', $html);
    }

    public function testLogoutEndsSessionAtProvider(): void
    {
        $this->signIn();
        $this->assertNotNull($this->signedInUserId());
        $result = $this->browse('oidc/logout');
        $this->assertStringStartsWith($this->idp->issuer . '/logout?', $result->getRedirectUrl());
        $this->assertStringContainsString('id_token_hint=', $result->getRedirectUrl());
        $this->assertNull($this->signedInUserId());
        $this->assertArrayNotHasKey(OidcController::SESSION_LOGIN, $this->session);
    }

    public function testLogoutWithoutProviderLogout(): void
    {
        $this->config->providers['fake']['logoutAtProvider'] = false;
        $this->signIn();
        $this->assertRedirectsTo('/', $this->browse('oidc/logout'));
    }

    public function testButtonsHelper(): void
    {
        helper('oidc');
        $html = oidc_buttons('/after');
        $this->assertStringContainsString('Sign in with Fake IdP', $html);
        $this->assertStringContainsString('/oidc/fake/login?return=%2Fafter', html_entity_decode($html));
    }

    /* ---------------- Shield conformance ---------------- */

    /** RFC 9700 4.2.4: the page after the callback mustn't leak the code via Referer. */
    public function testCallbackSendsNoReferrer(): void
    {
        $this->assertSame('no-referrer', $this->signIn()->response()->getHeaderLine('Referrer-Policy'));
        $this->browse('oidc/fake/login');
        $this->assertSame('no-referrer', $this->browse('oidc/fake/callback', ['code' => 'x', 'state' => 'forged'])->response()->getHeaderLine('Referrer-Policy'));
    }

    /** A Shield action already waiting for the user goes to Shield's action page, as magic links do. */
    public function testPendingShieldActionGoesToActionPage(): void
    {
        config('Auth')->actions['login'] = \CodeIgniter\Shield\Authentication\Actions\Email2FA::class;
        $this->signIn();
        $user = model(UserModel::class)->findByCredentials(['email' => 'pat@example.com']);
        model(\CodeIgniter\Shield\Models\UserIdentityModel::class)->create([
            'user_id' => $user->id, 'type' => 'email_2fa', 'name' => 'login', 'secret' => '123456', 'extra' => lang('Auth.need2FA'),
        ]);
        $this->session = [];

        $result = $this->signIn();
        $this->assertRedirectsTo(route_to('auth-action-show'), $result);
        $this->assertSame((string) $user->id, (string) ($this->session['user']['id'] ?? null), 'pending, not refused');
    }

    /** With loginActions on, Shield's configured login action runs for SSO too. */
    public function testLoginActionsOptionStartsShieldAction(): void
    {
        config('Auth')->actions['login'] = \CodeIgniter\Shield\Authentication\Actions\Email2FA::class;
        $this->signIn(); // off by default: straight in
        $this->assertNotNull($this->signedInUserId());

        $this->config->providers['fake']['loginActions'] = true;
        $this->session = [];
        $result = $this->signIn();
        $this->assertRedirectsTo(route_to('auth-action-show'), $result);
        $this->seeInDatabase('auth_identities', ['type' => 'email_2fa']);
    }

    public function testLogoutShowsShieldMessage(): void
    {
        $this->config->providers['fake']['logoutAtProvider'] = false;
        $this->signIn();
        $this->browse('oidc/logout')->assertSessionHas('message', lang('Auth.successLogout'));
    }
}
