<?php

namespace VendorShield\Shield\Tests\Unit\Intelligence;

use VendorShield\Shield\Config\ConfigResolver;
use VendorShield\Shield\Intelligence\IntelligenceClient;
use VendorShield\Shield\Intelligence\NullIntelligenceClient;
use VendorShield\Shield\Tests\TestCase;

class IntelligenceClientTest extends TestCase
{
    public function test_null_client_is_not_available(): void
    {
        $client = new NullIntelligenceClient;
        $this->assertFalse($client->available());
    }

    public function test_null_client_sync_is_noop(): void
    {
        $client = new NullIntelligenceClient;
        $client->sync();
        $this->assertTrue(true); // No exception
    }

    public function test_null_client_pull_policies_returns_empty(): void
    {
        $client = new NullIntelligenceClient;
        $result = $client->pullPolicies();
        $this->assertIsArray($result);
        $this->assertEmpty($result);
    }

    public function test_real_client_unavailable_without_config(): void
    {
        $this->app['config']->set('shield.intelligence.enabled', false);
        $this->app['config']->set('shield.intelligence.api_key', null);

        $config = $this->app->make(ConfigResolver::class);
        $client = new IntelligenceClient($config);

        $this->assertFalse($client->available());
    }

    public function test_real_client_sync_is_noop_when_unavailable(): void
    {
        $this->app['config']->set('shield.intelligence.enabled', false);

        $config = $this->app->make(ConfigResolver::class);
        $client = new IntelligenceClient($config);

        // Should not throw even though there's no endpoint
        $client->sync();
        $this->assertTrue(true);
    }

    public function test_real_client_pull_policies_returns_empty_when_unavailable(): void
    {
        $this->app['config']->set('shield.intelligence.enabled', false);

        $config = $this->app->make(ConfigResolver::class);
        $client = new IntelligenceClient($config);

        $result = $client->pullPolicies();
        $this->assertIsArray($result);
        $this->assertEmpty($result);
    }
}
