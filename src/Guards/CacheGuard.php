<?php

namespace VendorShield\Shield\Guards;

use VendorShield\Shield\Audit\AuditLogger;
use VendorShield\Shield\Config\ConfigResolver;
use VendorShield\Shield\Contracts\GuardContract;
use VendorShield\Shield\Events\GuardTriggered;
use VendorShield\Shield\Support\FailSafe;
use VendorShield\Shield\Support\GuardResult;
use VendorShield\Shield\Support\Severity;

class CacheGuard implements GuardContract
{
    public function __construct(
        protected ConfigResolver $config,
        protected AuditLogger $audit,
    ) {}

    public function name(): string
    {
        return 'cache';
    }

    public function enabled(): bool
    {
        return $this->config->guardEnabled('cache');
    }

    public function mode(): string
    {
        return $this->config->guardMode('cache');
    }

    /**
     * Analyze cache operations.
     *
     * @param  mixed  $context  Array with keys: operation, key, value, ttl
     */
    public function handle(mixed $context): GuardResult
    {
        if (! is_array($context)) {
            return GuardResult::pass($this->name());
        }

        $key = $context['key'] ?? '';
        $value = $context['value'] ?? null;

        // 1. Key pattern validation
        if ($this->config->guard('cache', 'key_pattern_validation', true)) {
            $result = $this->validateKeyPattern($key);
            if (! $result->passed) {
                return $result;
            }
        }

        // 2. Serialization attack detection
        if ($this->config->guard('cache', 'serialization_check', true) && $value !== null) {
            $result = $this->checkSerialization($key, $value);
            if (! $result->passed) {
                FailSafe::dispatch(fn () => $this->audit->guardEvent($this->name(), 'cache_threat', $result));
                FailSafe::dispatch(fn () => event(new GuardTriggered($this->name(), $result)));

                return $result;
            }
        }

        // 3. Size anomaly detection
        if ($value !== null) {
            $result = $this->checkSizeAnomaly($key, $value);
            if (! $result->passed) {
                FailSafe::dispatch(fn () => $this->audit->guardEvent($this->name(), 'cache_size_anomaly', $result));

                return $result;
            }
        }

        return GuardResult::pass($this->name());
    }

    protected function validateKeyPattern(string $key): GuardResult
    {
        // Detect path traversal in cache keys
        if (preg_match('/\.\.[\/\\\\]/', $key)) {
            return GuardResult::fail(
                guard: $this->name(),
                message: 'Path traversal detected in cache key',
                severity: Severity::High,
                metadata: ['key' => $key],
            );
        }

        // Detect null bytes
        if (str_contains($key, "\x00")) {
            return GuardResult::fail(
                guard: $this->name(),
                message: 'Null byte detected in cache key',
                severity: Severity::High,
                metadata: ['key' => $key],
            );
        }

        // Detect excessively long keys
        if (strlen($key) > 250) {
            return GuardResult::fail(
                guard: $this->name(),
                message: 'Cache key exceeds maximum length',
                severity: Severity::Low,
                metadata: ['key_length' => strlen($key)],
            );
        }

        return GuardResult::pass($this->name());
    }

    protected function checkSerialization(string $key, mixed $value): GuardResult
    {
        if (! is_string($value)) {
            return GuardResult::pass($this->name());
        }

        // Detect PHP serialized objects (potential deserialization attack)
        if (preg_match('/^O:\d+:"[^"]+"/i', $value)) {
            return GuardResult::fail(
                guard: $this->name(),
                message: 'Serialized PHP object detected in cache value',
                severity: Severity::Critical,
                metadata: ['key' => $key],
            );
        }

        return GuardResult::pass($this->name());
    }

    protected function checkSizeAnomaly(string $key, mixed $value): GuardResult
    {
        $threshold = $this->config->guard('cache', 'size_anomaly_threshold', 1048576);
        $serialized = is_string($value) ? $value : json_encode($value);
        $size = strlen($serialized ?: '');

        if ($size > $threshold) {
            return GuardResult::fail(
                guard: $this->name(),
                message: 'Cache value exceeds size threshold',
                severity: Severity::Medium,
                metadata: [
                    'key' => $key,
                    'size' => $size,
                    'threshold' => $threshold,
                ],
            );
        }

        return GuardResult::pass($this->name());
    }
}
