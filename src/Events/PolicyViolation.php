<?php

namespace VendorShield\Shield\Events;

use VendorShield\Shield\Policy\PolicyDecision;

class PolicyViolation
{
    public function __construct(
        public readonly string $guard,
        public readonly PolicyDecision $decision,
        public readonly mixed $context = null,
    ) {}
}
