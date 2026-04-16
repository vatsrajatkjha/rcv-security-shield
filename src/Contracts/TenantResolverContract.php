<?php

namespace VendorShield\Shield\Contracts;

use Illuminate\Http\Request;

interface TenantResolverContract
{
    /**
     * Resolve the current tenant identifier from the request context.
     *
     * @return string|null Returns null if no tenant context is available.
     */
    public function resolve(Request $request): ?string;

    /**
     * Resolve tenant from CLI/queue context.
     */
    public function resolveFromContext(array $context = []): ?string;
}
