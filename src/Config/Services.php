<?php

declare(strict_types=1);

namespace DaemonLabs\ShieldOidc\Config;

use CodeIgniter\Config\BaseService;
use CodeIgniter\Shield\Models\UserIdentityModel;
use DaemonLabs\ShieldOidc\OidcClient;
use DaemonLabs\ShieldOidc\UserResolver;

/**
 * The package services. Call them as service('oidcClient') and service('oidcUserResolver');
 * tests replace them with Services::injectMock().
 */
class Services extends BaseService
{
    /**
     * service('oidcClient'): the OidcClient, wired with the configured HttpClient, the cache
     * and the session.
     */
    public static function oidcClient(bool $getShared = true): OidcClient
    {
        if ($getShared) {
            return static::getSharedInstance('oidcClient');
        }

        /** @var ShieldOidc $config */
        $config = config('ShieldOidc');
        $http   = new ($config->httpClient)($config->httpTimeout);

        return new OidcClient($config, $http, service('cache'), service('session'));
    }

    /**
     * service('oidcUserResolver'): the configured UserResolver class, with Shield's user and
     * identity models.
     */
    public static function oidcUserResolver(bool $getShared = true): UserResolver
    {
        if ($getShared) {
            return static::getSharedInstance('oidcUserResolver');
        }

        /** @var ShieldOidc $config */
        $config = config('ShieldOidc');

        helper('auth');

        return new ($config->userResolver)(auth()->getProvider(), model(UserIdentityModel::class));
    }
}
