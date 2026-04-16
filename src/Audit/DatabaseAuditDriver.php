<?php

namespace VendorShield\Shield\Audit;

use VendorShield\Shield\Contracts\AuditDriverContract;
use VendorShield\Shield\Config\ConfigResolver;
use Illuminate\Support\Facades\DB;

class DatabaseAuditDriver implements AuditDriverContract
{
    public function __construct(
        protected ConfigResolver $config,
    ) {}

    public function log(AuditEntry $entry): void
    {
        $table = $this->config->get('audit.table', 'shield_audit_logs');

        try {
            DB::table($table)->insert($entry->toArray());
        } catch (\Throwable) {
            // Gracefully handle missing table (migration not yet run)
        }
    }

    public function query(array $filters = []): array
    {
        $table = $this->config->get('audit.table', 'shield_audit_logs');
        $query = DB::table($table);

        if (isset($filters['guard'])) {
            $query->where('guard', $filters['guard']);
        }

        if (isset($filters['tenant_id'])) {
            $query->where('tenant_id', $filters['tenant_id']);
        }

        if (isset($filters['severity'])) {
            $query->where('severity', $filters['severity']);
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
        $table = $this->config->get('audit.table', 'shield_audit_logs');

        return DB::table($table)
            ->where('created_at', '<', now()->subDays($days))
            ->delete();
    }
}
