<?php

namespace VendorShield\Shield\Support;

class AccessDecision
{
    public function __construct(
        public readonly bool $block,
        public readonly string $message,
        public readonly int $statusCode = 403,
        public readonly array $metadata = [],
        public readonly string $code = 'shield_blocked',
    ) {}

    public static function block(
        string $message,
        int $statusCode = 403,
        array $metadata = [],
        string $code = 'shield_blocked',
    ): self {
        return new self(
            block: true,
            message: $message,
            statusCode: $statusCode,
            metadata: $metadata,
            code: $code,
        );
    }
}
