<?php

namespace VendorShield\Shield\Threat;

class ThreatEntry
{
    public function __construct(
        public readonly string $guard,
        public readonly string $threatType,
        public readonly ?string $tenantId = null,
        public readonly ?string $fingerprint = null,
        public readonly array $requestData = [],
        public readonly bool $resolved = false,
        public readonly ?\DateTimeInterface $createdAt = null,
        public readonly ?\DateTimeInterface $resolvedAt = null,
    ) {}

    public function toArray(): array
    {
        return [
            'tenant_id' => $this->tenantId,
            'guard' => $this->guard,
            'threat_type' => $this->threatType,
            'fingerprint' => $this->fingerprint,
            'request_data' => json_encode($this->requestData),
            'resolved' => $this->resolved,
            'created_at' => ($this->createdAt ?? now())->format('Y-m-d H:i:s'),
            'resolved_at' => $this->resolvedAt?->format('Y-m-d H:i:s'),
        ];
    }
}
