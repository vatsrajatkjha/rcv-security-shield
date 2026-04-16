<?php

namespace VendorShield\Shield\Tests\Unit\Config;

use VendorShield\Shield\Tests\TestCase;
use VendorShield\Shield\Config\ConfigResolver;

class ConfigResolverTest extends TestCase
{
    protected ConfigResolver $resolver;

    protected function setUp(): void
    {
        parent::setUp();
        $this->resolver = $this->app->make(ConfigResolver::class);
    }

    public function test_reads_default_config(): void
    {
        $this->assertTrue($this->resolver->enabled());
        $this->assertEquals('monitor', $this->resolver->mode());
    }

    public function test_guard_enabled_check(): void
    {
        $this->assertTrue($this->resolver->guardEnabled('http'));
        $this->assertTrue($this->resolver->guardEnabled('database'));
    }

    public function test_guard_mode_inherits_global(): void
    {
        // Guard mode is null — should inherit global
        $this->assertEquals('monitor', $this->resolver->guardMode('http'));
    }

    public function test_runtime_override_takes_priority(): void
    {
        $this->resolver->override('mode', 'enforce');
        $this->assertEquals('enforce', $this->resolver->get('mode'));
    }

    public function test_clear_overrides(): void
    {
        $this->resolver->override('mode', 'enforce');
        $this->resolver->clearOverrides();

        $this->assertEquals('monitor', $this->resolver->get('mode'));
    }

    public function test_tenant_context(): void
    {
        $this->assertNull($this->resolver->tenant());

        $this->resolver->setTenant('tenant-123');
        $this->assertEquals('tenant-123', $this->resolver->tenant());
    }

    public function test_reset_clears_state(): void
    {
        $this->resolver->setTenant('tenant-123');
        $this->resolver->override('mode', 'enforce');

        $this->resolver->reset();

        $this->assertNull($this->resolver->tenant());
        $this->assertEquals('monitor', $this->resolver->get('mode'));
    }

    public function test_disabled_shield_disables_all_guards(): void
    {
        $this->app['config']->set('shield.enabled', false);

        $resolver = $this->app->make(ConfigResolver::class);

        $this->assertFalse($resolver->enabled());
        $this->assertFalse($resolver->guardEnabled('http'));
        $this->assertFalse($resolver->guardEnabled('database'));
    }
}
