<?php

namespace VendorShield\Shield\Tests;

use Orchestra\Testbench\TestCase as OrchestraTestCase;
use VendorShield\Shield\Facades\Shield;
use VendorShield\Shield\ShieldServiceProvider;

abstract class TestCase extends OrchestraTestCase
{
    protected function getPackageProviders($app): array
    {
        return [
            ShieldServiceProvider::class,
        ];
    }

    protected function getPackageAliases($app): array
    {
        return [
            'Shield' => Shield::class,
        ];
    }

    protected function defineEnvironment($app): void
    {
        $app['config']->set('app.key', 'base64:'.base64_encode(str_repeat('a', 32)));
        $app['config']->set('shield.enabled', true);
        $app['config']->set('shield.mode', 'monitor');
        $app['config']->set('shield.audit.driver', 'null');
        $app['config']->set('shield.async.enabled', false);
    }
}
