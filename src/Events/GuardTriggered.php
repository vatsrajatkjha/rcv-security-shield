<?php

namespace VendorShield\Shield\Events;

use VendorShield\Shield\Support\GuardResult;

class GuardTriggered
{
    public function __construct(
        public readonly string $guard,
        public readonly GuardResult $result,
    ) {}
}
