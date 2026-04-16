<?php

namespace VendorShield\Shield\Contracts;

use VendorShield\Shield\Async\AnalysisResult;

interface AnalysisDriverContract
{
    /**
     * Perform deep analysis on the given payload.
     *
     * @param  array<string, mixed>  $payload
     */
    public function analyze(array $payload): AnalysisResult;

    /**
     * Get the driver's identifier.
     */
    public function name(): string;
}
