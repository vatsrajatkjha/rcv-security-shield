<?php

namespace VendorShield\Shield\Contracts;

use VendorShield\Shield\Support\GuardResult;

interface GuardContract
{
    /**
     * Determine if this guard is enabled.
     */
    public function enabled(): bool;

    /**
     * Get the guard's operating mode.
     *
     * @return string One of: enforce, monitor, learning, disabled
     */
    public function mode(): string;

    /**
     * Execute the guard against the given context.
     */
    public function handle(mixed $context): GuardResult;

    /**
     * Get the guard's unique identifier.
     */
    public function name(): string;
}
