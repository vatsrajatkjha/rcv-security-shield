<?php

namespace VendorShield\Shield\Policy;

use VendorShield\Shield\Contracts\PolicyLoaderContract;
use VendorShield\Shield\Config\ConfigResolver;
use Illuminate\Support\Collection;

class PolicyEngine
{
    public function __construct(
        protected PolicyLoaderContract $loader,
        protected ConfigResolver $config,
    ) {}

    /**
     * Evaluate all applicable policies for a guard context.
     */
    public function evaluate(string $guard, mixed $context): PolicyDecision
    {
        if (! $this->config->get('policy.enabled', true)) {
            return PolicyDecision::allow('Policy engine disabled');
        }

        $policies = $this->loader->forGuard($guard);

        if ($policies->isEmpty()) {
            return PolicyDecision::allow('No policies defined for guard');
        }

        // Evaluate in priority order (lowest priority number first)
        $sorted = $policies->sortBy(fn ($policy) => $policy->priority());

        foreach ($sorted as $policy) {
            $decision = $policy->evaluate($context);

            // First deny wins
            if ($decision->isDenied()) {
                return $decision;
            }

            // Escalation is captured but evaluation continues
            if ($decision->shouldEscalate()) {
                return $decision;
            }
        }

        return PolicyDecision::allow('All policies passed');
    }

    /**
     * Evaluate policies for all guards.
     *
     * @return array<string, PolicyDecision>
     */
    public function evaluateAll(mixed $context): array
    {
        $results = [];
        $policies = $this->loader->load();

        $groupedByGuard = $policies->groupBy(fn ($policy) => $policy->guard());

        foreach ($groupedByGuard as $guard => $guardPolicies) {
            $results[$guard] = $this->evaluate($guard, $context);
        }

        return $results;
    }

    /**
     * Get all loaded policies.
     */
    public function policies(): Collection
    {
        return $this->loader->load();
    }
}
