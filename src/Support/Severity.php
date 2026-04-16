<?php

namespace VendorShield\Shield\Support;

enum Severity: string
{
    case Low = 'low';
    case Medium = 'medium';
    case High = 'high';
    case Critical = 'critical';

    /**
     * Determine if this severity is at or above the given threshold.
     */
    public function isAtLeast(self $threshold): bool
    {
        return $this->numericValue() >= $threshold->numericValue();
    }

    public function numericValue(): int
    {
        return match ($this) {
            self::Low => 1,
            self::Medium => 2,
            self::High => 3,
            self::Critical => 4,
        };
    }
}
