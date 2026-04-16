<?php

namespace VendorShield\Shield\Guards;

use Illuminate\Database\Events\QueryExecuted;
use VendorShield\Shield\Audit\AuditLogger;
use VendorShield\Shield\Config\ConfigResolver;
use VendorShield\Shield\Contracts\GuardContract;
use VendorShield\Shield\Events\GuardTriggered;
use VendorShield\Shield\Events\ThreatDetected;
use VendorShield\Shield\Support\FailSafe;
use VendorShield\Shield\Support\GuardResult;
use VendorShield\Shield\Support\Severity;

class DatabaseGuard implements GuardContract
{
    /** @var array<string> SQL injection indicators — tuned to minimise ORM false positives */
    protected const INJECTION_PATTERNS = [
        '/\bUNION\b.*\bSELECT\b/i',
        '/\bINSERT\b.*\bINTO\b.*\bSELECT\b/i',
        '/\bDROP\b\s+\b(TABLE|DATABASE|INDEX)\b/i',
        '/\bALTER\b\s+\bTABLE\b/i',
        '/\b(LOAD_FILE|INTO\s+OUTFILE|INTO\s+DUMPFILE)\b/i',
        '/\bEXEC(UTE)?\b\s*\(/i',
        '/\bxp_cmdshell\b/i',
        '/\bSLEEP\s*\(\s*\d+\s*\)/i',
        '/\bBENCHMARK\s*\(/i',
        '/\bWAITFOR\b\s+\bDELAY\b/i',
        // Context-aware: only flag CHAR/CONCAT when paired with injection context
        '/\bUNION\b.*\b(CHAR|CONCAT)\s*\(/i',
        '/\bSELECT\b.*\bFROM\b.*\bINFORMATION_SCHEMA\b/i',
    ];

    public function __construct(
        protected ConfigResolver $config,
        protected AuditLogger $audit,
    ) {}

    public function name(): string
    {
        return 'database';
    }

    public function enabled(): bool
    {
        return $this->config->guardEnabled('database');
    }

    public function mode(): string
    {
        return $this->config->guardMode('database');
    }

    /**
     * Analyze an executed query for security concerns.
     */
    public function handle(mixed $context): GuardResult
    {
        if (! $context instanceof QueryExecuted) {
            return GuardResult::pass($this->name());
        }

        $results = [];

        // 1. SQL injection detection
        if ($this->config->guard('database', 'detect_sql_injection', true)) {
            $results[] = $this->detectInjection($context);
        }

        // 2. Raw query detection
        if ($this->config->guard('database', 'detect_raw_queries', true)) {
            $results[] = $this->detectRawQuery($context);
        }

        // 3. Slow query detection
        $threshold = $this->config->guard('database', 'slow_query_threshold_ms', 5000);
        if ($context->time > $threshold) {
            $results[] = GuardResult::fail(
                guard: $this->name(),
                message: 'Slow query detected',
                severity: Severity::Low,
                metadata: [
                    'execution_time_ms' => $context->time,
                    'threshold_ms' => $threshold,
                    'sql_preview' => substr($context->sql, 0, 200),
                ],
            );
        }

        // 4. Query length check
        $maxLength = $this->config->guard('database', 'max_query_length', 10000);
        if (strlen($context->sql) > $maxLength) {
            $results[] = GuardResult::fail(
                guard: $this->name(),
                message: 'Query exceeds maximum allowed length',
                severity: Severity::Medium,
                metadata: [
                    'query_length' => strlen($context->sql),
                    'max_length' => $maxLength,
                ],
            );
        }

        // 5. Tenant boundary check
        if ($this->config->guard('database', 'tenant_boundary_check', true)) {
            $results[] = $this->checkTenantBoundary($context);
        }

        // Aggregate results — fail on first failure
        foreach ($results as $result) {
            if (! $result->passed) {
                $this->handleResult($result);

                return $result;
            }
        }

        return GuardResult::pass($this->name());
    }

    /**
     * Detect SQL injection patterns in the query.
     */
    protected function detectInjection(QueryExecuted $query): GuardResult
    {
        foreach (self::INJECTION_PATTERNS as $pattern) {
            if (preg_match($pattern, $query->sql)) {
                return GuardResult::fail(
                    guard: $this->name(),
                    message: 'Potential SQL injection detected',
                    severity: Severity::Critical,
                    metadata: [
                        'sql_preview' => substr($query->sql, 0, 500),
                        'connection' => $query->connectionName,
                    ],
                );
            }
        }

        return GuardResult::pass($this->name());
    }

    /**
     * Detect raw queries (not using bindings).
     */
    protected function detectRawQuery(QueryExecuted $query): GuardResult
    {
        // Queries with no bindings that contain user input indicators
        if (empty($query->bindings) && $this->looksLikeUserInput($query->sql)) {
            return GuardResult::fail(
                guard: $this->name(),
                message: 'Potential raw query with unbound parameters',
                severity: Severity::High,
                metadata: [
                    'sql_preview' => substr($query->sql, 0, 500),
                    'connection' => $query->connectionName,
                ],
            );
        }

        return GuardResult::pass($this->name());
    }

    /**
     * Check for queries that may be crossing tenant boundaries.
     */
    protected function checkTenantBoundary(QueryExecuted $query): GuardResult
    {
        $tenantId = $this->config->tenant();

        if ($tenantId === null) {
            return GuardResult::pass($this->name());
        }

        // Check for queries that modify all records without tenant scope
        $dangerousPatterns = [
            '/\bUPDATE\b.*\bSET\b(?!.*\btenant_id\b)/i',
            '/\bDELETE\b\s+\bFROM\b(?!.*\btenant_id\b)/i',
        ];

        foreach ($dangerousPatterns as $pattern) {
            if (preg_match($pattern, $query->sql)) {
                return GuardResult::fail(
                    guard: $this->name(),
                    message: 'Query may cross tenant boundary — missing tenant scope',
                    severity: Severity::Critical,
                    metadata: [
                        'tenant_id' => $tenantId,
                        'sql_preview' => substr($query->sql, 0, 500),
                    ],
                );
            }
        }

        return GuardResult::pass($this->name());
    }

    /**
     * Heuristic: does this SQL look like it contains inline user input?
     */
    protected function looksLikeUserInput(string $sql): bool
    {
        // Simple heuristic: quoted strings in WHERE/SET clauses
        return (bool) preg_match('/\b(WHERE|SET|VALUES)\b.*\'[^\']+\'/i', $sql);
    }

    /**
     * Handle a guard result (dispatch events, audit).
     */
    protected function handleResult(GuardResult $result): void
    {
        FailSafe::dispatch(function () use ($result) {
            if ($this->mode() === 'enforce') {
                event(new ThreatDetected($this->name(), $result));
            } else {
                event(new GuardTriggered($this->name(), $result));
            }
        });

        FailSafe::dispatch(fn () => $this->audit->guardEvent($this->name(), 'query_threat', $result));
    }
}
