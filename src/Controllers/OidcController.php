<?php

declare(strict_types=1);

namespace DaemonLabs\ShieldOidc\Controllers;

use CodeIgniter\Controller;
use CodeIgniter\Events\Events;
use CodeIgniter\Exceptions\PageNotFoundException;
use CodeIgniter\HTTP\RedirectResponse;
use CodeIgniter\Shield\Authentication\Authenticators\Session;
use CodeIgniter\Shield\Models\LoginModel;
use DaemonLabs\ShieldOidc\Config\ShieldOidc;
use DaemonLabs\ShieldOidc\Exceptions\OidcException;
use DaemonLabs\ShieldOidc\OidcClient;
use DaemonLabs\ShieldOidc\Provider;
use DaemonLabs\ShieldOidc\UserResolver;
use LogicException;
use Throwable;

/**
 * GET  /oidc/<provider>/login     Send the browser to the provider (?return=/path)
 * POST /oidc/<provider>/link      Signed-in users connect a provider (form from oidc_link_form())
 * GET  /oidc/<provider>/callback  Where the provider sends the browser back
 * GET|POST /oidc/logout           Sign out here (and at the provider, if logoutAtProvider is on)
 */
class OidcController extends Controller
{
    /** Session key remembering which provider signed this session in, for logout. */
    public const SESSION_LOGIN = 'shield_oidc_login';

    /** Session key holding the token that proves a link request came from our own form. */
    public const SESSION_LINK_TOKEN = 'shield_oidc_link_token';

    protected $helpers = ['auth', 'setting', 'url'];

    /**
     * GET <prefix>/<provider>/login: send the browser to the provider. Someone already signed
     * in is sent to Shield's login redirect instead. ?return=/path is honoured if it's local.
     */
    public function login(string $key): RedirectResponse
    {
        $provider = $this->provider($key);
        if (auth('session')->loggedIn()) {
            return redirect()->to(config('Auth')->loginRedirect());
        }

        return $this->startSignIn($provider, null);
    }

    /**
     * Connecting a provider changes who can sign in to an account, so it must come from a
     * form on this site (POST + a session token), never from a link another site can trigger.
     */
    public function link(string $key): RedirectResponse
    {
        $provider = $this->provider($key);
        $auth     = auth('session');
        if (! $auth->loggedIn()) {
            return $this->fail($provider, new OidcException(lang('Oidc.linkNeedsLogin')));
        }
        $sent     = $this->request->getPost('oidc_link_token');
        $expected = session(self::SESSION_LINK_TOKEN);
        if (! is_string($sent) || ! is_string($expected) || $expected === '' || ! hash_equals($expected, $sent)) {
            return $this->fail($provider, new OidcException(lang('Oidc.stateInvalid'), 'Link request without a valid form token.'));
        }

        return $this->startSignIn($provider, $auth->id());
    }

    /**
     * GET <prefix>/<provider>/callback: the provider sends the browser back here. Verifies the
     * sign-in, resolves the Shield user, then logs them in (or finishes linking). Every failure
     * ends in a redirect with a short session('error') message; details go to the log.
     */
    public function callback(string $key): RedirectResponse
    {
        $provider = $this->provider($key);
        $auth     = auth('session');

        try {
            $result = $this->client()->handleCallback($provider, (array) $this->request->getGet());
            $linkId = $result['link'];
            if ($linkId !== null && (string) $auth->id() !== (string) $linkId) {
                throw new OidcException(lang('Oidc.linkNeedsLogin'), 'The signed-in user changed during linking.');
            }
            $user = $this->resolver()->resolve($provider, $result['claims'], $linkId);
        } catch (OidcException $e) {
            if (isset($result)) {
                $this->record($provider, $result['claims'], false, null);
            }

            return $this->noReferrer($this->fail($provider, $e));
        } catch (Throwable $e) {
            return $this->noReferrer($this->fail($provider, OidcException::config(get_class($e) . ': ' . $e->getMessage(), $e)));
        }

        if ($linkId !== null) {
            return $this->noReferrer(redirect()->to($result['return'] ?? config('Auth')->loginRedirect())
                ->with('message', lang('Oidc.linked', [$provider->label])));
        }

        if ($auth->loggedIn()) {
            $auth->logout(); // a different account was signed in in this browser
        }

        /** @var Session $session */
        $session = $auth->getAuthenticator();
        $login   = ['provider' => $provider->key, 'idToken' => $result['idToken']];
        if (is_string($result['claims']['login_hint'] ?? null)) {
            $login['loginHint'] = $result['claims']['login_hint']; // Entra's logout_hint
        }

        // Shield auth actions, handled the way Shield's own magic-link login does:
        //  - one already waiting for this user (an Email2FA code, an activation) is completed
        //    on Shield's action page instead of blocking the sign-in;
        //  - with loginActions on, the configured login action (e.g. Email2FA) runs for SSO too.
        // Shield finishes the login (and fires its 'login' event) when the action is done.
        $pending = $session->hasAction($user->id)
            || ($provider->option('loginActions', false) && $session->startUpAction('login', $user) && $session->hasAction($user->id));
        if ($pending) {
            $actionPage = route_to('auth-action-show');
            if (! is_string($actionPage) || $actionPage === '') {
                // Shield's routes aren't registered (service('auth')->routes($routes)), so the
                // action can't be completed here.
                return $this->noReferrer($this->fail($provider, new OidcException(lang('Oidc.loginBlocked'), 'User ' . $user->id . ' has a pending Shield action, but the auth-action-show route is missing.')));
            }
            if (ENVIRONMENT !== 'testing') {
                session()->regenerate(true); // the pending state is a privilege change too
            }
            $this->record($provider, $result['claims'], true, $user->id);
            session()->set(self::SESSION_LOGIN, $login);

            return $this->noReferrer(redirect()->to($actionPage));
        }

        try {
            $auth->login($user);
        } catch (LogicException $e) {
            return $this->noReferrer($this->fail($provider, new OidcException(lang('Oidc.loginBlocked'), $e->getMessage(), $e)));
        }
        $this->record($provider, $result['claims'], true, $user->id);
        session()->set(self::SESSION_LOGIN, $login);
        Events::trigger('oidcLogin', $user, $result['claims'], $provider->key);

        // withCookies(): Shield sets its cookies on the shared response (as its LoginController does).
        return $this->noReferrer(redirect()->to($result['return'] ?? config('Auth')->loginRedirect())->withCookies());
    }

    /**
     * GET|POST <prefix>/logout: sign out of the app and, when the provider that signed this
     * session in has logoutAtProvider on, end the session there too.
     */
    public function logout(): RedirectResponse
    {
        $config = $this->settings();
        $login  = session(self::SESSION_LOGIN);
        session()->remove(self::SESSION_LOGIN);
        auth('session')->logout();

        $target = site_url(ltrim($config->logoutRedirect, '/'));
        if (is_array($login) && is_string($login['provider'] ?? null) && isset($config->providers[$login['provider']])) {
            try {
                $provider = Provider::fromConfig($login['provider'], $config);
                if ($provider->option('logoutAtProvider', false)) {
                    $url = $this->client()->endSessionUrl(
                        $provider,
                        is_string($login['idToken'] ?? null) ? $login['idToken'] : null,
                        $target,
                        is_string($login['loginHint'] ?? null) ? $login['loginHint'] : null,
                    );
                    if ($url !== null) {
                        return redirect()->to($url);
                    }
                }
            } catch (Throwable $e) {
                log_message('warning', 'Shield OIDC: provider logout skipped: {d}', ['d' => $e instanceof OidcException ? $e->getDetail() : $e->getMessage()]);
            }
        }

        return redirect()->to($target)->with('message', lang('Auth.successLogout'));
    }

    /**
     * The callback URL carries the authorization code, so the page it leads to must not leak
     * it in a Referer header (RFC 9700 4.2.4).
     */
    protected function noReferrer(RedirectResponse $response): RedirectResponse
    {
        return $response->setHeader('Referrer-Policy', 'no-referrer');
    }

    /* ------------------------------------------------------------------ */

    /**
     * Builds the authorization URL (reading 'return' from POST or GET) and redirects to it.
     */
    protected function startSignIn(Provider $provider, int|string|null $linkUserId): RedirectResponse
    {
        $return = $this->request->getPost('return') ?? $this->request->getGet('return');

        try {
            $url = $this->client()->authorizationUrl($provider, is_string($return) ? $return : null, $linkUserId);
        } catch (OidcException $e) {
            return $this->fail($provider, $e);
        } catch (Throwable $e) {
            return $this->fail($provider, OidcException::config(get_class($e) . ': ' . $e->getMessage(), $e));
        }

        return redirect()->to($url);
    }

    /**
     * The provider for a route segment. Unknown or misconfigured providers are a 404 for the
     * visitor; misconfiguration is logged.
     */
    protected function provider(string $key): Provider
    {
        if (! isset($this->settings()->providers[$key])) {
            throw PageNotFoundException::forPageNotFound();
        }

        try {
            return Provider::fromConfig($key, $this->settings());
        } catch (OidcException $e) {
            log_message('error', 'Shield OIDC [{p}]: {d}', ['p' => $key, 'd' => $e->getDetail()]);

            throw PageNotFoundException::forPageNotFound();
        }
    }

    /**
     * Logs the detail, fires oidcFailed, and redirects with the safe message: to failureRedirect,
     * or to Shield's login redirect when someone is signed in (e.g. a failed link).
     */
    protected function fail(Provider $provider, OidcException $e): RedirectResponse
    {
        log_message('error', 'Shield OIDC [{p}]: {d}', ['p' => $provider->key, 'd' => $e->getDetail()]);
        Events::trigger('oidcFailed', $provider->key, $e);

        $to = auth('session')->loggedIn() ? config('Auth')->loginRedirect() : site_url(ltrim($this->settings()->failureRedirect, '/'));

        return redirect()->to($to)->with('error', $e->getMessage());
    }

    /** @param array<string, mixed> $claims */
    protected function record(Provider $provider, array $claims, bool $success, int|string|null $userId): void
    {
        $who = is_string($claims['email'] ?? null) ? $claims['email'] : (is_string($claims['sub'] ?? null) ? $claims['sub'] : '');
        model(LoginModel::class)->recordLoginAttempt(
            UserResolver::IDENTITY_TYPE,
            mb_substr($provider->key . ':' . $who, 0, 250),
            $success,
            $this->request->getIPAddress(),
            (string) $this->request->getUserAgent(),
            $userId,
        );
    }

    /**
     * Services, overridable in a subclass.
     */
    protected function client(): OidcClient
    {
        return service('oidcClient');
    }

    protected function resolver(): UserResolver
    {
        return service('oidcUserResolver');
    }

    protected function settings(): ShieldOidc
    {
        return config('ShieldOidc');
    }
}
