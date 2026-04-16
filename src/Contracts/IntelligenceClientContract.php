<?php

namespace VendorShield\Shield\Contracts;

use VendorShield\Shield\Intelligence\ThreatFingerprint;

interface IntelligenceClientContract
{
    /**
     * Synchronize threat intelligence from the cloud.
     */
    public function sync(): void;

    /**
     * Report a threat fingerprint to the cloud intelligence network.
     */
    public function report(ThreatFingerprint $fingerprint): void;

    /**
     * Pull latest policy updates from the cloud.
     *
     * @return array<string, mixed>
     */
    public function pullPolicies(): array;

    /**
     * Check if the intelligence client is available.
     */
    public function available(): bool;
}
