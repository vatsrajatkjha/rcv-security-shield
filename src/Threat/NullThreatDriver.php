<?php

namespace VendorShield\Shield\Threat;

use VendorShield\Shield\Contracts\ThreatDriverContract;

class NullThreatDriver implements ThreatDriverContract
{
    public function log(ThreatEntry $entry): void
    {
        // No-op
    }

    public function query(array $filters = []): array
    {
        return [];
    }

    public function prune(int $days): int
    {
        return 0;
    }
}
