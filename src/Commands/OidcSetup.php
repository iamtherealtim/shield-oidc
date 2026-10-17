<?php

declare(strict_types=1);

namespace DaemonLabs\ShieldOidc\Commands;

use CodeIgniter\CLI\BaseCommand;
use CodeIgniter\CLI\CLI;

/**
 * Creates app/Config/ShieldOidc.php, extending the package config, ready for providers.
 */
class OidcSetup extends BaseCommand
{
    protected $group       = 'Shield OIDC';
    protected $name        = 'oidc:setup';
    protected $description = 'Creates app/Config/ShieldOidc.php for your OpenID Connect providers.';
    protected $options     = ['-f' => 'Overwrite an existing file'];

    /**
     * Writes app/Config/ShieldOidc.php unless it exists (use -f to overwrite).
     */
    public function run(array $params)
    {
        $path = APPPATH . 'Config/ShieldOidc.php';
        if (is_file($path) && ! array_key_exists('f', $params) && ! CLI::getOption('f')) {
            CLI::error('app/Config/ShieldOidc.php already exists. Use -f to overwrite it.');

            return EXIT_ERROR;
        }

        $template = <<<'PHP'
            <?php

            declare(strict_types=1);

            namespace Config;

            use DaemonLabs\ShieldOidc\Config\ShieldOidc as BaseShieldOidc;

            class ShieldOidc extends BaseShieldOidc
            {
                /**
                 * Providers are set in the constructor so secrets can come from .env with env().
                 * Never commit client secrets.
                 */
                public array $providers = [];

                public function __construct()
                {
                    parent::__construct();

                    // $this->providers['entra'] = [
                    //     'type'         => 'entra',
                    //     'tenant'       => env('OIDC_ENTRA_TENANT', 'organizations'),
                    //     'clientId'     => env('OIDC_ENTRA_CLIENT_ID', ''),
                    //     'clientSecret' => env('OIDC_ENTRA_CLIENT_SECRET', ''),
                    // ];

                    // $this->providers['okta'] = [
                    //     'label'        => 'Okta',
                    //     'issuer'       => env('OIDC_OKTA_ISSUER', ''),
                    //     'clientId'     => env('OIDC_OKTA_CLIENT_ID', ''),
                    //     'clientSecret' => env('OIDC_OKTA_CLIENT_SECRET', ''),
                    // ];
                }
            }

            PHP;

        if (file_put_contents($path, $template) === false) {
            CLI::error('Could not write ' . $path);

            return EXIT_ERROR;
        }
        CLI::write('Created app/Config/ShieldOidc.php', 'green');
        CLI::write('Add a provider there, then run `php spark oidc:check`.');

        return EXIT_SUCCESS;
    }
}
