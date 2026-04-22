<?php

namespace VendorShield\Shield\Threat;

use Illuminate\Support\Facades\Log;
use VendorShield\Shield\Contracts\ThreatDriverContract;

class LogThreatDriver implements ThreatDriverContract
{
    public function __construct(
        protected ?string $channel = null,
    ) {}

    public function log(ThreatEntry $entry): void
    {
        $logger = $this->channel ? Log::channel($this->channel) : Log::getFacadeRoot();

        $logger->warning('[Shield Threat]', $entry->toArray());
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
