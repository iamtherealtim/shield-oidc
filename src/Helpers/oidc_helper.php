<?php

declare(strict_types=1);

use DaemonLabs\ShieldOidc\Controllers\OidcController;
use DaemonLabs\ShieldOidc\Exceptions\OidcException;
use DaemonLabs\ShieldOidc\Provider;

if (! function_exists('oidc_login_url')) {
    /**
     * URL that starts sign-in with a provider.
     *
     * @param string|null $returnTo Local path to land on afterwards
     */
    function oidc_login_url(string $provider, ?string $returnTo = null): string
    {
        $url = site_url(trim(config('ShieldOidc')->routePrefix, '/') . '/' . rawurlencode($provider) . '/login');

        return $returnTo !== null ? $url . '?' . http_build_query(['return' => $returnTo]) : $url;
    }
}

if (! function_exists('oidc_link_form')) {
    /**
     * A small form a signed-in user submits to connect a provider to their account.
     * It's a POST with a per-session token, so other sites can't start linking.
     *
     * @param string|null $label Button text; defaults to "Connect <provider label>"
     */
    function oidc_link_form(string $provider, ?string $returnTo = null, ?string $label = null): string
    {
        $token = session(OidcController::SESSION_LINK_TOKEN);
        if (! is_string($token) || $token === '') {
            $token = bin2hex(random_bytes(32));
            session()->set(OidcController::SESSION_LINK_TOKEN, $token);
        }

        try {
            $label ??= lang('Oidc.connect', [Provider::fromConfig($provider)->label]);
        } catch (OidcException) {
            return '';
        }
        $action = site_url(trim(config('ShieldOidc')->routePrefix, '/') . '/' . rawurlencode($provider) . '/link');

        return '<form method="post" action="' . esc($action, 'attr') . '" class="oidc-link-form">'
            . csrf_field()
            . '<input type="hidden" name="oidc_link_token" value="' . esc($token, 'attr') . '">'
            . ($returnTo !== null ? '<input type="hidden" name="return" value="' . esc($returnTo, 'attr') . '">' : '')
            . '<button type="submit" class="oidc-button btn btn-outline-secondary">' . esc($label) . '</button>'
            . '</form>';
    }
}

if (! function_exists('oidc_buttons')) {
    /**
     * "Sign in with …" buttons for every configured provider. Style them with the
     * .oidc-buttons / .oidc-button classes, or render your own with oidc_login_url().
     */
    function oidc_buttons(?string $returnTo = null): string
    {
        $providers = [];
        foreach (array_keys(config('ShieldOidc')->providers) as $key) {
            try {
                $providers[] = Provider::fromConfig((string) $key);
            } catch (OidcException) {
                // Misconfigured providers are skipped; `php spark oidc:check` explains why.
            }
        }

        return view('DaemonLabs\ShieldOidc\Views\buttons', ['providers' => $providers, 'returnTo' => $returnTo], ['saveData' => false, 'debug' => false]);
    }
}
