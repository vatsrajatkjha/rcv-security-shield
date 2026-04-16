<?php

namespace VendorShield\Shield\Intelligence;

use VendorShield\Shield\Support\Severity;

class ThreatFingerprint
{
    public function __construct(
        public readonly string $type,
        public readonly string $signature,
        public readonly Severity $severity = Severity::Medium,
        public readonly string $guard = '',
        public readonly array $indicators = [],
        public readonly ?string $tenantId = null,
        public readonly ?\DateTimeInterface $detectedAt = null,
    ) {}

    public function toArray(): array
    {
        return [
            'type' => $this->type,
            'signature' => $this->signature,
            'severity' => $this->severity->value,
            'guard' => $this->guard,
            'indicators' => $this->indicators,
            'tenant_id' => $this->tenantId,
            'detected_at' => ($this->detectedAt ?? now())->toIso8601String(),
        ];
    }

    public static function fromArray(array $data): static
    {
        return new static(
            type: $data['type'] ?? 'unknown',
            signature: $data['signature'] ?? '',
            severity: Severity::tryFrom($data['severity'] ?? 'medium') ?? Severity::Medium,
            guard: $data['guard'] ?? '',
            indicators: $data['indicators'] ?? [],
            tenantId: $data['tenant_id'] ?? null,
        );
    }
}
