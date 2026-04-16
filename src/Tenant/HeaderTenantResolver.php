<?php

namespace VendorShield\Shield\Tenant;

use Illuminate\Http\Request;
use VendorShield\Shield\Config\ConfigResolver;
use VendorShield\Shield\Contracts\TenantResolverContract;

/**
 * Default tenant resolver using header-based resolution.
 * Applications can replace this with their own implementation.
 */
class HeaderTenantResolver implements TenantResolverContract
{
    public function __construct(
        protected ConfigResolver $config,
    ) {}

    public function resolve(Request $request): ?string
    {
        $header = $this->config->guard('tenant', 'header', 'X-Tenant-ID');

        return $request->header($header);
    }

    public function resolveFromContext(array $context = []): ?string
    {
        return $context['tenant_id'] ?? null;
    }
}
