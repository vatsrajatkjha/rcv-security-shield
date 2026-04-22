<?php

namespace VendorShield\Shield\Threat;

use Illuminate\Support\Facades\DB;
use VendorShield\Shield\Config\ConfigResolver;
use VendorShield\Shield\Contracts\ThreatDriverContract;

class DatabaseThreatDriver implements ThreatDriverContract
{
    public function __construct(
        protected ConfigResolver $config,
    ) {}

    public function log(ThreatEntry $entry): void
    {
        $table = $this->config->get('threats.table', 'shield_threat_logs');

        try {
            DB::table($table)->insert($entry->toArray());
        } catch (\Throwable) {
            // Gracefully handle missing table or transient DB failures
        }
    }

    public function query(array $filters = []): array
    {
        $table = $this->config->get('threats.table', 'shield_threat_logs');
        $query = DB::table($table);

        if (isset($filters['guard'])) {
            $query->where('guard', $filters['guard']);
        }

        if (isset($filters['tenant_id'])) {
            $query->where('tenant_id', $filters['tenant_id']);
        }

        if (isset($filters['threat_type'])) {
            $query->where('threat_type', $filters['threat_type']);
        }

        if (isset($filters['fingerprint'])) {
            $query->where('fingerprint', $filters['fingerprint']);
        }

        if (isset($filters['resolved'])) {
            $query->where('resolved', (bool) $filters['resolved']);
        }

        if (isset($filters['since'])) {
            $query->where('created_at', '>=', $filters['since']);
        }

        if (isset($filters['limit'])) {
            $query->limit($filters['limit']);
        } else {
            $query->limit(100);
        }

        return $query->orderByDesc('created_at')->get()->toArray();
    }

    public function prune(int $days): int
    {
        $table = $this->config->get('threats.table', 'shield_threat_logs');

        return DB::table($table)
            ->where('created_at', '<', now()->subDays($days))
            ->delete();
    }
}
