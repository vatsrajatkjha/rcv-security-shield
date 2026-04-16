<?php

namespace VendorShield\Shield\Support;

class GuardResult
{
    public function __construct(
        public readonly bool $passed,
        public readonly string $message = '',
        public readonly Severity $severity = Severity::Low,
        public readonly array $metadata = [],
        public readonly ?string $guard = null,
    ) {}

    /**
     * Create a passing result.
     */
    public static function pass(string $guard = '', string $message = ''): static
    {
        return new static(
            passed: true,
            message: $message,
            guard: $guard,
        );
    }

    /**
     * Create a failing result.
     */
    public static function fail(
        string $guard = '',
        string $message = '',
        Severity $severity = Severity::Medium,
        array $metadata = [],
    ): static {
        return new static(
            passed: false,
            message: $message,
            severity: $severity,
            metadata: $metadata,
            guard: $guard,
        );
    }

    /**
     * Create a monitoring-only result (detected but not blocking).
     */
    public static function monitor(
        string $guard = '',
        string $message = '',
        Severity $severity = Severity::Low,
        array $metadata = [],
    ): static {
        return new static(
            passed: true,
            message: $message,
            severity: $severity,
            metadata: $metadata,
            guard: $guard,
        );
    }

    /**
     * Convert to array for serialization.
     */
    public function toArray(): array
    {
        return [
            'passed' => $this->passed,
            'message' => $this->message,
            'severity' => $this->severity->value,
            'metadata' => $this->metadata,
            'guard' => $this->guard,
        ];
    }
}
