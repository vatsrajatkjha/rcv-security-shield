<?php

namespace VendorShield\Shield\Policy;

class PolicyDecision
{
    public const ALLOW = 'allow';

    public const DENY = 'deny';

    public const MONITOR = 'monitor';

    public const ESCALATE = 'escalate';

    public function __construct(
        public readonly string $action,
        public readonly string $reason = '',
        public readonly array $metadata = [],
    ) {}

    public static function allow(string $reason = ''): static
    {
        return new static(self::ALLOW, $reason);
    }

    public static function deny(string $reason = '', array $metadata = []): static
    {
        return new static(self::DENY, $reason, $metadata);
    }

    public static function monitor(string $reason = '', array $metadata = []): static
    {
        return new static(self::MONITOR, $reason, $metadata);
    }

    public static function escalate(string $reason = '', array $metadata = []): static
    {
        return new static(self::ESCALATE, $reason, $metadata);
    }

    public function isAllowed(): bool
    {
        return $this->action === self::ALLOW;
    }

    public function isDenied(): bool
    {
        return $this->action === self::DENY;
    }

    public function shouldEscalate(): bool
    {
        return $this->action === self::ESCALATE;
    }

    public function toArray(): array
    {
        return [
            'action' => $this->action,
            'reason' => $this->reason,
            'metadata' => $this->metadata,
        ];
    }
}
