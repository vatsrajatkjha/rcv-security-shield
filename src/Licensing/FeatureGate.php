<?php

namespace VendorShield\Shield\Licensing;

class FeatureGate
{
    /** @var array<string, string> Feature → required tier */
    protected array $gates = [];

    /**
     * Register a feature gate.
     */
    public function register(string $feature, string $requiredTier): void
    {
        $this->gates[$feature] = $requiredTier;
    }

    /**
     * Get the required tier for a feature.
     */
    public function requiredTier(string $feature): string
    {
        return $this->gates[$feature] ?? 'oss';
    }

    /**
     * Get all registered gates.
     */
    public function all(): array
    {
        return $this->gates;
    }

    /**
     * Check if a feature is registered.
     */
    public function has(string $feature): bool
    {
        return isset($this->gates[$feature]);
    }
}
