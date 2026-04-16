<?php

namespace VendorShield\Shield\Tests\Unit\Policy;

use VendorShield\Shield\Policy\PolicyDecision;
use VendorShield\Shield\Policy\PolicyEngine;
use VendorShield\Shield\Policy\PolicyLoader;
use VendorShield\Shield\Tests\TestCase;

class PolicyEngineTest extends TestCase
{
    public function test_empty_policies_allow(): void
    {
        $engine = $this->app->make(PolicyEngine::class);

        $decision = $engine->evaluate('http', ['test' => 'data']);

        $this->assertTrue($decision->isAllowed());
    }

    public function test_policy_engine_respects_disabled_config(): void
    {
        $this->app['config']->set('shield.policy.enabled', false);

        $engine = $this->app->make(PolicyEngine::class);
        $decision = $engine->evaluate('http', ['test' => 'data']);

        $this->assertTrue($decision->isAllowed());
        $this->assertStringContainsString('disabled', $decision->reason);
    }

    public function test_deny_policy_blocks(): void
    {
        $this->app['config']->set('shield.policy.rules', [
            ['guard' => 'http', 'condition' => '', 'action' => 'deny', 'priority' => 0],
        ]);

        // Clear policy cache
        $this->app->make(PolicyLoader::class)->clearCache();
        $engine = $this->app->make(PolicyEngine::class);

        $decision = $engine->evaluate('http', []);

        $this->assertTrue($decision->isDenied());
    }

    public function test_policy_decision_factory_methods(): void
    {
        $allow = PolicyDecision::allow('test');
        $this->assertTrue($allow->isAllowed());
        $this->assertFalse($allow->isDenied());

        $deny = PolicyDecision::deny('test');
        $this->assertTrue($deny->isDenied());
        $this->assertFalse($deny->isAllowed());

        $escalate = PolicyDecision::escalate('test');
        $this->assertTrue($escalate->shouldEscalate());
    }
}
