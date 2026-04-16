<?php

namespace VendorShield\Shield\Audit;

use VendorShield\Shield\Contracts\AuditDriverContract;

/**
 * Null audit driver — discards all audit entries.
 * Used when audit logging is disabled.
 */
class NullAuditDriver implements AuditDriverContract
{
    public function log(AuditEntry $entry): void
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
