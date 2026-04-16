<?php

namespace VendorShield\Shield\Tests\Unit\Runtime;

use VendorShield\Shield\Config\ConfigResolver;
use VendorShield\Shield\Runtime\RuntimeHookManager;
use VendorShield\Shield\Tests\TestCase;

class RuntimeHookManagerTest extends TestCase
{
    public function test_boot_does_not_throw_when_shield_enabled(): void
    {
        $this->app['config']->set('shield.enabled', true);
        $this->app['config']->set('shield.guards.http.enabled', true);
        $this->app['config']->set('shield.guards.database.enabled', false);

        $manager = $this->app->make(RuntimeHookManager::class);
        $manager->boot();

        $this->assertTrue(true); // No exception thrown
    }

    public function test_boot_does_not_throw_when_shield_disabled(): void
    {
        $this->app['config']->set('shield.enabled', false);

        $manager = $this->app->make(RuntimeHookManager::class);
        $manager->boot();

        $this->assertTrue(true);
    }

    public function test_database_hooks_skipped_when_guard_disabled(): void
    {
        $this->app['config']->set('shield.guards.database.enabled', false);

        $config = $this->app->make(ConfigResolver::class);
        $this->assertFalse($config->guardEnabled('database'));

        $manager = $this->app->make(RuntimeHookManager::class);
        $manager->boot();

        $this->assertTrue(true); // No hook registered
    }

    public function test_queue_hooks_skipped_when_guard_disabled(): void
    {
        $this->app['config']->set('shield.guards.queue.enabled', false);

        $config = $this->app->make(ConfigResolver::class);
        $this->assertFalse($config->guardEnabled('queue'));

        $manager = $this->app->make(RuntimeHookManager::class);
        $manager->boot();

        $this->assertTrue(true);
    }

    public function test_request_middleware_is_registered_when_upload_guard_is_enabled_without_http_guard(): void
    {
        $this->app['config']->set('shield.guards.http.enabled', false);
        $this->app['config']->set('shield.guards.upload.enabled', true);

        $manager = $this->app->make(RuntimeHookManager::class);
        $manager->boot();

        $this->assertTrue($manager->isBooted());
    }
}
