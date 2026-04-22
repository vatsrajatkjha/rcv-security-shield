<?php

namespace VendorShield\Shield\Contracts;

use VendorShield\Shield\Threat\ThreatEntry;

interface ThreatDriverContract
{
    /**
     * Persist a threat entry.
     */
    public function log(ThreatEntry $entry): void;

    /**
     * Query persisted threat entries.
     *
     * @param  array<string, mixed>  $filters
     * @return array<int, object>
     */
    public function query(array $filters = []): array;

    /**
     * Prune persisted threat entries older than the given number of days.
     */
    public function prune(int $days): int;
}
