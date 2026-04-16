<?php

namespace VendorShield\Shield\Audit;

use VendorShield\Shield\Contracts\AuditDriverContract;
use Illuminate\Support\Facades\Log;

class LogAuditDriver implements AuditDriverContract
{
    public function __construct(
        protected ?string $channel = null,
    ) {}

    public function log(AuditEntry $entry): void
    {
        $logger = $this->channel ? Log::channel($this->channel) : Log::getFacadeRoot();

        $logger->info('[Shield Audit]', $entry->toArray());
    }

    public function query(array $filters = []): array
    {
        // Log driver does not support querying — readonly
        return [];
    }

    public function prune(int $days): int
    {
        // Log pruning is handled by the log rotation system
        return 0;
    }
}
