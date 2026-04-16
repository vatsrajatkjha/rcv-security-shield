<?php

namespace VendorShield\Shield\Contracts;

use Illuminate\Support\Collection;

interface PolicyLoaderContract
{
    /**
     * Load all security policies.
     *
     * @return Collection<int, PolicyContract>
     */
    public function load(): Collection;

    /**
     * Load policies scoped to a specific guard.
     *
     * @return Collection<int, PolicyContract>
     */
    public function forGuard(string $guard): Collection;
}
