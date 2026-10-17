<?php

declare(strict_types=1);

namespace Tests\Support;

use CodeIgniter\Test\CIUnitTestCase;
use CodeIgniter\Test\DatabaseTestTrait;

/**
 * A database test with Shield's tables and the settings `php spark shield:setup` would make.
 */
abstract class ShieldTestCase extends CIUnitTestCase
{
    use DatabaseTestTrait;

    protected $namespace = null; // run every namespace's migrations, Shield's included
    protected $refresh   = true;

    protected function setUp(): void
    {
        parent::setUp();
        helper(['auth', 'setting']);
        config('Security')->csrfProtection = 'session'; // Shield refuses cookie-based CSRF
    }
}
