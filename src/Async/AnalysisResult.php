<?php

namespace VendorShield\Shield\Async;

use VendorShield\Shield\Support\Severity;

class AnalysisResult
{
    public function __construct(
        public readonly bool $clean,
        public readonly string $driver,
        public readonly Severity $severity = Severity::Low,
        public readonly string $summary = '',
        public readonly array $findings = [],
        public readonly array $metadata = [],
    ) {}

    public static function clean(string $driver): static
    {
        return new static(clean: true, driver: $driver);
    }

    public static function threat(
        string $driver,
        string $summary,
        Severity $severity = Severity::High,
        array $findings = [],
    ): static {
        return new static(
            clean: false,
            driver: $driver,
            severity: $severity,
            summary: $summary,
            findings: $findings,
        );
    }

    public function toArray(): array
    {
        return [
            'clean' => $this->clean,
            'driver' => $this->driver,
            'severity' => $this->severity->value,
            'summary' => $this->summary,
            'findings' => $this->findings,
            'metadata' => $this->metadata,
        ];
    }
}
