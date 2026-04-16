<?php

namespace VendorShield\Shield\Contracts;

use VendorShield\Shield\Audit\AuditEntry;

interface AuditDriverContract
{
    /**
     * Log an audit entry.
     */
    public function log(AuditEntry $entry): void;

    /**
     * Query audit entries with filters.
     *
     * @param array<string, mixed> $filters
     * @return array<int, AuditEntry>
     */
    public function query(array $filters = []): array;

    /**
     * Prune entries older than the given number of days.
     */
    public function prune(int $days): int;
}
