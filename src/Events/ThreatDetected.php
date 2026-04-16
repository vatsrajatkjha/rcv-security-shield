<?php

namespace VendorShield\Shield\Events;

use VendorShield\Shield\Support\GuardResult;

class ThreatDetected
{
    public function __construct(
        public readonly string $guard,
        public readonly GuardResult $result,
    ) {}
}
