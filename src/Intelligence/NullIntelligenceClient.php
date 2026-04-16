<?php

namespace VendorShield\Shield\Intelligence;

use VendorShield\Shield\Contracts\IntelligenceClientContract;

/**
 * Null intelligence client — used when cloud intelligence is disabled.
 * Implements fail-open pattern.
 */
class NullIntelligenceClient implements IntelligenceClientContract
{
    public function available(): bool
    {
        return false;
    }

    public function sync(): void
    {
        // No-op
    }

    public function report(ThreatFingerprint $fingerprint): void
    {
        // No-op
    }

    public function pullPolicies(): array
    {
        return [];
    }
}
