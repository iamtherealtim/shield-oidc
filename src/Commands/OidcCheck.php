<?php

declare(strict_types=1);

namespace DaemonLabs\ShieldOidc\Commands;

use CodeIgniter\CLI\BaseCommand;
use CodeIgniter\CLI\CLI;
use DaemonLabs\ShieldOidc\Config\ShieldOidc;
use DaemonLabs\ShieldOidc\Exceptions\OidcException;
use DaemonLabs\ShieldOidc\Jose\IdTokenVerifier;
use DaemonLabs\ShieldOidc\OidcClient;
use DaemonLabs\ShieldOidc\Provider;

/**
 * Checks each provider's settings against the real provider and prints what to register there.
 */
class OidcCheck extends BaseCommand
{
    protected $group       = 'Shield OIDC';
    protected $name        = 'oidc:check';
    protected $description = 'Checks your OpenID Connect providers and shows the redirect URIs to register.';
    protected $usage       = 'oidc:check [provider]';
    protected $arguments   = ['provider' => 'Check only this provider'];

    /**
     * Checks every provider (or the one named) and exits non-zero if any needs attention.
     */
    public function run(array $params)
    {
        helper(['setting', 'url']);

        /** @var ShieldOidc $config */
        $config = config('ShieldOidc');
        $keys   = isset($params[0]) ? [$params[0]] : array_keys($config->providers);
        if ($keys === []) {
            CLI::error('No providers configured. Run `php spark oidc:setup`, then add one to app/Config/ShieldOidc.php.');

            return EXIT_ERROR;
        }

        /** @var OidcClient $client */
        $client = service('oidcClient');
        $failed = 0;
        foreach ($keys as $key) {
            CLI::newLine();
            CLI::write('Provider: ' . $key, 'yellow');
            if (! $this->check((string) $key, $config, $client)) {
                $failed++;
            }
        }
        CLI::newLine();
        if ($failed > 0) {
            CLI::error($failed . ' provider(s) need attention.');

            return EXIT_ERROR;
        }
        CLI::write('All providers look good.', 'green');

        return EXIT_SUCCESS;
    }

    /**
     * Fetches the provider's live metadata (bypassing the cache), prints a summary, the URIs
     * to register, and warnings for risky settings. Returns false on errors.
     */
    private function check(string $key, ShieldOidc $config, OidcClient $client): bool
    {
        try {
            $p   = Provider::fromConfig($key, $config);
            $doc = $client->discovery($p, true);
            $set = $client->jwks($doc, true);
        } catch (OidcException $e) {
            CLI::error('  ' . $e->getDetail());

            return false;
        }

        $ok   = true;
        $algs = array_values(array_intersect((array) ($doc['id_token_signing_alg_values_supported'] ?? ['RS256']), IdTokenVerifier::supportedAlgs()));
        $this->row('Type', $p->type === 'entra' ? 'Microsoft Entra ID (tenant ' . $p->tenant . ')' : 'OpenID Connect');
        $this->row('Issuer', (string) $doc['issuer']);
        $this->row('Signing keys', count($set['keys']) . ' published; algorithms ' . ($algs !== [] ? implode(', ', $algs) : 'none we support'));
        $this->row('Client', $p->clientId . ($p->clientSecret !== '' ? ' (with secret)' : ' (public client, PKCE only)'));
        $this->row('Scopes', implode(' ', $p->scopes()));
        $this->row('Identifies users by', 'iss + ' . $p->subjectClaim());
        $this->row('New accounts', $p->option('register', true) ? 'created on first sign-in' : 'not created (existing accounts only)');
        $this->row('Link by email', $p->linkByEmail());
        if ($p->allowedDomains() !== []) {
            $this->row('Allowed domains', implode(', ', $p->allowedDomains()));
        }
        if ($p->groupMap() !== []) {
            $this->row('Groups', 'claim "' . $p->option('groupsClaim') . '" -> ' . implode(', ', array_unique($p->groupMap())) . ($p->option('syncGroups') ? ' (synced)' : ' (added only)'));
        }

        CLI::newLine();
        CLI::write('  Register this redirect URI with the provider:', 'cyan');
        CLI::write('    ' . $client->redirectUri($p));
        if ($p->option('logoutAtProvider', false)) {
            if (isset($doc['end_session_endpoint'])) {
                CLI::write('  and this post-logout redirect URI:', 'cyan');
                CLI::write('    ' . site_url(ltrim($config->logoutRedirect, '/')));
            } else {
                CLI::write('  logoutAtProvider is on, but this provider has no end_session_endpoint.', 'light_red');
            }
        }

        if ($algs === []) {
            CLI::error('  The provider signs ID tokens with an algorithm this package does not support.');
            $ok = false;
        }
        if ($p->linkByEmail() === 'trusted') {
            CLI::write('  Warning: linkByEmail "trusted" lets anyone who can set their email at this provider (users, or administrators in their directory) take over the matching account here.', 'light_red');
        }
        if ($p->isEntraMultiTenant() && $p->allowedTenants === [] && $p->option('register', true)) {
            $who = match (strtolower($p->tenant)) {
                'consumers' => 'personal',
                'common'    => 'work, school or personal',
                default     => 'work or school',
            };
            CLI::write('  Note: any Microsoft ' . $who . ' account can create an account here. Set allowedTenants to limit it.', 'light_red');
        }
        if ($p->type === 'entra') {
            if ($p->subjectClaim() === 'oid' && ! in_array('profile', $p->scopes(), true)) {
                CLI::error('  Entra only sends the oid claim with the "profile" scope; add it to scopes.');
                $ok = false;
            }
            if ($p->linkByEmail() !== 'trusted' && ($p->allowedDomains() !== [] || $p->linkByEmail() === 'verified')) {
                CLI::write('  Note: Entra emails count only with the xms_edov optional claim (Token configuration > Add optional claim > ID: email, xms_edov).'
                    . ($p->allowedDomains() !== [] ? ' Without it, allowedDomains admits no one.' : ''));
            }
        }
        if ($p->groupMap() !== []) {
            $known   = array_map('strtolower', array_keys((array) setting('AuthGroups.groups')));
            $unknown = array_diff(array_unique($p->groupMap()), $known);
            if ($unknown !== []) {
                CLI::error('  groupMap names Shield groups that don\'t exist in Config\AuthGroups: ' . implode(', ', $unknown) . '.');
                $ok = false;
            }
        }
        if ($p->linkByEmail() !== 'never' && setting('Auth.allowRegistration') && ! str_contains((string) (setting('Auth.actions')['register'] ?? ''), 'Activator')) {
            CLI::write('  Note: Shield registration is open without email activation, so existing accounts are never linked by email'
                . ' (anyone could have registered an address). People connect the provider from their account instead.');
        }
        if ($p->isEntraMultiTenant() && $p->groupMap() !== [] && $p->groupTenants() === []) {
            CLI::write('  Note: groupMap is ignored. With more than one tenant, each tenant\'s admins assign roles, so list the tenants you trust to do that in groupTenants.', 'light_red');
        }
        if (! in_array($p->subjectClaim(), ['sub', 'oid'], true)) {
            CLI::write('  Warning: users are identified by "' . $p->subjectClaim() . '". If people can change that value at the provider, they can sign in as someone else here.', 'light_red');
        }
        if (str_starts_with($client->redirectUri($p), 'http://') && ! str_contains($client->redirectUri($p), '://localhost')) {
            CLI::write('  Warning: the redirect URI is not https. Set app.baseURL to your https address.', 'light_red');
        }

        return $ok;
    }

    /**
     * One aligned "label   value" line.
     */
    private function row(string $label, string $value): void
    {
        CLI::write('  ' . str_pad($label, 20) . $value);
    }
}
