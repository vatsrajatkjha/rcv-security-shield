<?php

namespace VendorShield\Shield\Audit;

use VendorShield\Shield\Async\AnalysisResult;
use VendorShield\Shield\Config\ConfigResolver;
use VendorShield\Shield\Contracts\AuditDriverContract;
use VendorShield\Shield\Support\GuardResult;
use VendorShield\Shield\Support\Severity;
use VendorShield\Shield\Threat\ThreatLogger;

class AuditLogger
{
    public function __construct(
        protected AuditDriverContract $driver,
        protected ConfigResolver $config,
        protected ThreatLogger $threats,
    ) {}

    /**
     * Check if audit logging is enabled.
     */
    public function enabled(): bool
    {
        return (bool) $this->config->get('audit.enabled', true);
    }

    /**
     * Log a guard event.
     */
    public function guardEvent(string $guard, string $eventType, GuardResult $result): void
    {
        $fingerprint = $this->isThreatEventType($eventType)
            ? $this->threats->fingerprintForGuardThreat($guard, $eventType, $result)
            : null;

        if ($this->enabled()) {
            $entry = new AuditEntry(
                guard: $guard,
                eventType: $eventType,
                severity: $result->severity,
                tenantId: $this->config->tenant(),
                payload: $this->augmentGuardPayload($result, $fingerprint),
                context: [
                    'mode' => $this->config->guardMode($guard),
                ],
            );

            try {
                $this->driver->log($entry);
            } catch (\Throwable) {
                // Never block application due to audit failure
            }
        }

        if ($this->isThreatEventType($eventType)) {
            $this->threats->logGuardThreat($guard, $eventType, $result, $fingerprint);
        }
    }

    /**
     * Log an analysis result.
     */
    public function analysisEvent(string $guard, AnalysisResult $result): void
    {
        $fingerprint = ! $result->clean
            ? $this->threats->fingerprintForAnalysisThreat($guard, $result)
            : null;

        if ($this->enabled()) {
            $entry = new AuditEntry(
                guard: $guard,
                eventType: 'analysis_complete',
                severity: $result->severity,
                tenantId: $this->config->tenant(),
                payload: $this->augmentAnalysisPayload($result, $fingerprint),
            );

            try {
                $this->driver->log($entry);
            } catch (\Throwable) {
                // Silent failure
            }
        }

        if (! $result->clean) {
            $this->threats->logAnalysisThreat($guard, $result, $fingerprint);
        }
    }

    /**
     * Log an analysis error.
     */
    public function analysisError(string $guard, string $errorMessage): void
    {
        if (! $this->enabled()) {
            return;
        }

        $entry = new AuditEntry(
            guard: $guard,
            eventType: 'analysis_error',
            severity: Severity::Medium,
            tenantId: $this->config->tenant(),
            payload: ['error' => $errorMessage],
        );

        try {
            $this->driver->log($entry);
        } catch (\Throwable) {
            // Silent failure
        }
    }

    /**
     * Log a custom event.
     */
    public function log(string $guard, string $eventType, Severity $severity = Severity::Low, array $payload = []): void
    {
        if (! $this->enabled()) {
            return;
        }

        $entry = new AuditEntry(
            guard: $guard,
            eventType: $eventType,
            severity: $severity,
            tenantId: $this->config->tenant(),
            payload: $payload,
        );

        try {
            $this->driver->log($entry);
        } catch (\Throwable) {
            // Silent failure
        }
    }

    /**
     * Access the underlying driver.
     */
    public function driver(): AuditDriverContract
    {
        return $this->driver;
    }

    protected function augmentGuardPayload(GuardResult $result, ?string $fingerprint): array
    {
        $payload = $result->toArray();
        $metadata = $payload['metadata'] ?? [];
        $metadata['shield_fingerprint'] = $fingerprint;
        $payload['metadata'] = $metadata;

        return $payload;
    }

    protected function augmentAnalysisPayload(AnalysisResult $result, ?string $fingerprint): array
    {
        $payload = $result->toArray();
        $metadata = $payload['metadata'] ?? [];
        $metadata['shield_fingerprint'] = $fingerprint;
        $payload['metadata'] = $metadata;

        return $payload;
    }

    protected function isThreatEventType(string $eventType): bool
    {
        return in_array($eventType, [
            'threat_detected',
            'threat_blocked',
            'query_threat',
            'upload_threat',
            'auth_threat',
            'tenant_violation',
            'queue_threat',
            'cache_threat',
            'cache_size_anomaly',
            'security_exception',
            'job_failed',
            'analysis_error',
        ], true);
    }
}
