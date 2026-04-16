<?php

namespace VendorShield\Shield\Tenant;

class TenantContext
{
    protected ?string $tenantId = null;
    protected array $metadata = [];

    /**
     * Set the current tenant.
     */
    public function set(string $tenantId, array $metadata = []): void
    {
        $this->tenantId = $tenantId;
        $this->metadata = $metadata;
    }

    /**
     * Get the current tenant ID.
     */
    public function id(): ?string
    {
        return $this->tenantId;
    }

    /**
     * Check if a tenant context is active.
     */
    public function active(): bool
    {
        return $this->tenantId !== null;
    }

    /**
     * Get tenant metadata.
     */
    public function metadata(string $key = null, mixed $default = null): mixed
    {
        if ($key === null) {
            return $this->metadata;
        }

        return $this->metadata[$key] ?? $default;
    }

    /**
     * Clear the tenant context. Octane-safe reset.
     */
    public function clear(): void
    {
        $this->tenantId = null;
        $this->metadata = [];
    }

    /**
     * Enforce the current tenant context.
     * Returns the TenantContext for fluent API: Shield::tenant($id)->enforce()
     */
    public function enforce(): static
    {
        return $this;
    }
}
