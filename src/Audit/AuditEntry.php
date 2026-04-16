<?php

namespace VendorShield\Shield\Audit;

use VendorShield\Shield\Support\Severity;

class AuditEntry
{
    public function __construct(
        public readonly string $guard,
        public readonly string $eventType,
        public readonly Severity $severity = Severity::Low,
        public readonly ?string $tenantId = null,
        public readonly array $payload = [],
        public readonly array $context = [],
        public readonly ?\DateTimeInterface $createdAt = null,
    ) {}

    public function toArray(): array
    {
        return [
            'tenant_id' => $this->tenantId,
            'guard' => $this->guard,
            'event_type' => $this->eventType,
            'severity' => $this->severity->value,
            'payload' => json_encode($this->payload),
            'context' => json_encode($this->context),
            'created_at' => ($this->createdAt ?? now())->format('Y-m-d H:i:s'),
        ];
    }
}
