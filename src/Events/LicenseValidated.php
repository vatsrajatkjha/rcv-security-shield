<?php

namespace VendorShield\Shield\Events;

class LicenseValidated
{
    public function __construct(
        public readonly string $tier,
        public readonly bool $valid,
    ) {}
}
