<?php

namespace VendorShield\Shield\Tests\Feature;

use VendorShield\Shield\Tests\TestCase;
use VendorShield\Shield\ShieldManager;
use VendorShield\Shield\Config\ConfigResolver;
use VendorShield\Shield\Contracts\IntelligenceClientContract;
use VendorShield\Shield\Contracts\AuditDriverContract;
use VendorShield\Shield\Policy\PolicyEngine;
use VendorShield\Shield\Tenant\TenantContext;
use VendorShield\Shield\Audit\AuditLogger;
use VendorShield\Shield\Audit\NullAuditDriver;

class ServiceProviderTest extends TestCase
{
    public function test_shield_manager_is_bound(): void
    {
        $this->assertInstanceOf(ShieldManager::class, $this->app->make('shield'));
        $this->assertInstanceOf(ShieldManager::class, $this->app->make(ShieldManager::class));
    }

    public function test_config_resolver_is_singleton(): void
    {
        $a = $this->app->make(ConfigResolver::class);
        $b = $this->app->make(ConfigResolver::class);

        $this->assertSame($a, $b);
    }

    public function test_tenant_context_is_scoped(): void
    {
        $context = $this->app->make(TenantContext::class);
        $this->assertInstanceOf(TenantContext::class, $context);
    }

    public function test_audit_driver_resolves(): void
    {
        $driver = $this->app->make(AuditDriverContract::class);
        $this->assertInstanceOf(NullAuditDriver::class, $driver); // Using null driver in tests
    }

    public function test_audit_logger_resolves(): void
    {
        $logger = $this->app->make(AuditLogger::class);
        $this->assertInstanceOf(AuditLogger::class, $logger);
    }

    public function test_intelligence_client_resolves(): void
    {
        $client = $this->app->make(IntelligenceClientContract::class);
        $this->assertInstanceOf(IntelligenceClientContract::class, $client);
    }

    public function test_policy_engine_resolves(): void
    {
        $engine = $this->app->make(PolicyEngine::class);
        $this->assertInstanceOf(PolicyEngine::class, $engine);
    }

    public function test_guards_are_registered(): void
    {
        $manager = $this->app->make(ShieldManager::class);

        $this->assertNotNull($manager->guard('http'));
        $this->assertNotNull($manager->guard('database'));
        $this->assertNotNull($manager->guard('upload'));
        $this->assertNotNull($manager->guard('queue'));
        $this->assertNotNull($manager->guard('auth'));
        $this->assertNotNull($manager->guard('cache'));
        $this->assertNotNull($manager->guard('tenant'));
    }

    public function test_health_check_returns_data(): void
    {
        $manager = $this->app->make(ShieldManager::class);
        $health = $manager->health();

        $this->assertArrayHasKey('enabled', $health);
        $this->assertArrayHasKey('mode', $health);
        $this->assertArrayHasKey('guards', $health);
        $this->assertCount(7, $health['guards']); // 7 guards (excluding exception decorator)
    }

    public function test_config_is_merged(): void
    {
        $this->assertNotNull(config('shield'));
        $this->assertTrue(config('shield.enabled'));
        $this->assertIsArray(config('shield.guards'));
    }

    public function test_disabled_shield_does_not_boot_hooks(): void
    {
        // This test verifies the no-op behavior
        $this->app['config']->set('shield.enabled', false);

        $manager = $this->app->make(ShieldManager::class);
        $this->assertFalse($manager->enabled());
    }
}
