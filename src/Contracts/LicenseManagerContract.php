<?php

namespace VendorShield\Shield\Contracts;

interface LicenseManagerContract
{
    /**
     * Check if a specific feature is available under the current license.
     */
    public function check(string $feature): bool;

    /**
     * Get the current license tier.
     *
     * @return string One of: oss, pro, enterprise
     */
    public function tier(): string;

    /**
     * Validate the license (local + remote).
     */
    public function validate(): bool;

    /**
     * Determine if the license is valid (cached).
     */
    public function isValid(): bool;
}
