<?php

namespace VendorShield\Shield\Contracts;

interface ContentDisarmContract
{
    /**
     * Disarm a file or return the original file path.
     *
     * @return array{success: bool, path?: string, detail?: string}
     */
    public function disarm(string $path, array $context = []): array;
}
