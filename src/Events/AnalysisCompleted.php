<?php

namespace VendorShield\Shield\Events;

use VendorShield\Shield\Async\AnalysisResult;

class AnalysisCompleted
{
    public function __construct(
        public readonly string $guard,
        public readonly AnalysisResult $result,
    ) {}
}
