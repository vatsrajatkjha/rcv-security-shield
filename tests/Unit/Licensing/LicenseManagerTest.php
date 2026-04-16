<?php

namespace VendorShield\Shield\Tests\Unit\Licensing;

use VendorShield\Shield\Tests\TestCase;
use VendorShield\Shield\Contracts\LicenseManagerContract;

class LicenseManagerTest extends TestCase
{
    public function test_no_key_defaults_to_oss(): void
    {
        $this->app['config']->set('shield.licensing.key', null);

        $license = $this->app->make(LicenseManagerContract::class);

        $this->assertEquals('oss', $license->tier());
    }

    public function test_oss_features_always_available(): void
    {
        $license = $this->app->make(LicenseManagerContract::class);

        $this->assertTrue($license->check('http_guard'));
        $this->assertTrue($license->check('upload_guard'));
        $this->assertTrue($license->check('database_guard'));
    }

    public function test_pro_features_blocked_on_oss(): void
    {
        $this->app['config']->set('shield.licensing.key', null);

        $license = $this->app->make(LicenseManagerContract::class);

        $this->assertFalse($license->check('advanced_detection'));
        $this->assertFalse($license->check('tenant_isolation'));
    }

    public function test_enterprise_features_blocked_on_oss(): void
    {
        $this->app['config']->set('shield.licensing.key', null);

        $license = $this->app->make(LicenseManagerContract::class);

        $this->assertFalse($license->check('cloud_intelligence'));
        $this->assertFalse($license->check('compliance_reports'));
    }

    public function test_pro_key_enables_pro_features(): void
    {
        $this->app['config']->set('shield.licensing.key', 'SHIELD-PRO-test12345678');

        // Clear cache
        $this->app['cache']->forget('shield:license:tier');

        $license = $this->app->make(LicenseManagerContract::class);

        $this->assertEquals('pro', $license->tier());
        $this->assertTrue($license->check('advanced_detection'));
    }
}
