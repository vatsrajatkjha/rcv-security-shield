<?php

namespace VendorShield\Shield\Contracts;

use Illuminate\Support\Collection;
use VendorShield\Shield\Policy\PolicyDecision;

interface PolicyContract
{
    /**
     * Evaluate the policy against the given context.
     */
    public function evaluate(mixed $context): PolicyDecision;

    /**
     * Get the policy's guard scope.
     */
    public function guard(): string;

    /**
     * Get the policy's priority (lower = evaluated first).
     */
    public function priority(): int;
}
