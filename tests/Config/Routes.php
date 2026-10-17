<?php

declare(strict_types=1);

/**
 * Test-only routes: Shield's own routes, as `php spark shield:setup` adds them to a real app
 * (the package's tests need Shield's auth action page).
 *
 * @var CodeIgniter\Router\RouteCollection $routes
 */
service('auth')->routes($routes);
