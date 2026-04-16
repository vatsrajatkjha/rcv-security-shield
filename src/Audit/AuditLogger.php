<?php

namespace VendorShield\Shield\Audit;

use VendorShield\Shield\Async\AnalysisResult;
use VendorShield\Shield\Config\ConfigResolver;
use VendorShield\Shield\Contracts\AuditDriverContract;
use VendorShield\Shield\Support\GuardResult;
use VendorShield\Shield\Support\Severity;

class AuditLogger
{
    public function __construct(
        protected AuditDriverContract $driver,
        protected ConfigResolver $config,
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
        if (! $this->enabled()) {
            return;
        }

        $entry = new AuditEntry(
            guard: $guard,
            eventType: $eventType,
            severity: $result->severity,
            tenantId: $this->config->tenant(),
            payload: $result->toArray(),
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

    /**
     * Log an analysis result.
     */
    public function analysisEvent(string $guard, AnalysisResult $result): void
    {
        if (! $this->enabled()) {
            return;
        }

        $entry = new AuditEntry(
            guard: $guard,
            eventType: 'analysis_complete',
            severity: $result->severity,
            tenantId: $this->config->tenant(),
            payload: $result->toArray(),
        );

        try {
            $this->driver->log($entry);
        } catch (\Throwable) {
            // Silent failure
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
}
