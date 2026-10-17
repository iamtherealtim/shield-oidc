<?php

declare(strict_types=1);

namespace Tests\Feature;

use CodeIgniter\Config\Factories;
use CodeIgniter\Test\Mock\MockCache;
use CodeIgniter\Test\StreamFilterTrait;
use Config\Services;
use DaemonLabs\ShieldOidc\Config\ShieldOidc;
use DaemonLabs\ShieldOidc\OidcClient;
use Tests\Support\FakeProvider;
use Tests\Support\ShieldTestCase;

/**
 * @internal
 */
final class CheckCommandTest extends ShieldTestCase
{
    use StreamFilterTrait;

    private ShieldOidc $config;
    private FakeProvider $idp;

    protected function setUp(): void
    {
        parent::setUp();
        $this->idp    = new FakeProvider();
        $this->config = new ShieldOidc();
        Factories::injectMock('config', 'ShieldOidc', $this->config);
        Services::injectMock('oidcClient', new OidcClient($this->config, $this->idp, new MockCache(), service('session')));
    }

    public function testShowsRedirectUriAndSettings(): void
    {
        $this->config->providers = ['fake' => ['issuer' => $this->idp->issuer, 'clientId' => 'client-123', 'groupsClaim' => 'roles', 'groupMap' => ['admin' => 'admin']]];
        command('oidc:check');
        $out = $this->getStreamFilterBuffer();
        $this->assertStringContainsString('https://app.example.test/oidc/fake/callback', $out);
        $this->assertStringContainsString('public client, PKCE only', $out);
        $this->assertStringContainsString('claim "roles" -> admin (added only)', $out);
        $this->assertStringContainsString('All providers look good.', $out);
    }

    public function testReportsBrokenProvider(): void
    {
        $this->config->providers = ['broken' => ['issuer' => 'https://idp.example.test', 'clientId' => 'c']];
        $this->idp->discoveryOverrides['issuer'] = 'https://someone-else.example';
        command('oidc:check');
        $out = $this->getStreamFilterBuffer();
        $this->assertStringContainsString('does not match the configured issuer', $out);
        $this->assertStringContainsString('1 provider(s) need attention', $out);
    }

    public function testWarnsAboutOpenMultiTenantEntra(): void
    {
        $ms = new FakeProvider('https://login.microsoftonline.com/organizations/v2.0');
        $ms->discoveryOverrides['issuer'] = 'https://login.microsoftonline.com/{tenantid}/v2.0';
        Services::injectMock('oidcClient', new OidcClient($this->config, $ms, new MockCache(), service('session')));
        $this->config->providers = ['ms' => ['type' => 'entra', 'tenant' => 'organizations', 'clientId' => 'app', 'linkByEmail' => 'trusted']];
        command('oidc:check');
        $out = $this->getStreamFilterBuffer();
        $this->assertStringContainsString('any Microsoft work or school account can create an account here', $out);
        $this->assertStringContainsString('take over the matching account', $out);
    }

    public function testRejectsUnknownShieldGroupsAndMissingProfileScope(): void
    {
        $ms = new FakeProvider('https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/v2.0');
        Services::injectMock('oidcClient', new OidcClient($this->config, $ms, new MockCache(), service('session')));
        $this->config->providers = ['ms' => [
            'type' => 'entra', 'tenant' => '11111111-2222-3333-4444-555555555555', 'clientId' => 'app',
            'scopes' => ['openid', 'email'], 'groupMap' => ['App.Admin' => 'admin', 'App.Boss' => 'bosses'],
        ]];
        command('oidc:check');
        $out = $this->getStreamFilterBuffer();
        $this->assertStringContainsString('"profile" scope', $out);
        $this->assertStringContainsString("don't exist in Config\\AuthGroups: bosses", $out);
        $this->assertStringContainsString('need attention', $out);
    }
}
