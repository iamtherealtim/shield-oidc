<?php

declare(strict_types=1);

/**
 * Discovered automatically when module route discovery is on (the default).
 * If you turned it off, copy these lines into app/Config/Routes.php.
 *
 * @var CodeIgniter\Router\RouteCollection $routes
 */
$prefix = trim(config('ShieldOidc')->routePrefix, '/');

$routes->group($prefix, ['namespace' => 'DaemonLabs\ShieldOidc\Controllers'], static function ($routes): void {
    $routes->match(['get', 'post'], 'logout', 'OidcController::logout', ['as' => 'oidc-logout']);
    $routes->get('(:segment)/login', 'OidcController::login/$1', ['as' => 'oidc-login']);
    $routes->post('(:segment)/link', 'OidcController::link/$1', ['as' => 'oidc-link']);
    $routes->get('(:segment)/callback', 'OidcController::callback/$1', ['as' => 'oidc-callback']);
});
