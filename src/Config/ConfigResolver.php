<?php

namespace VendorShield\Shield\Config;

use Illuminate\Contracts\Config\Repository;

class ConfigResolver
{
    protected ?string $tenantId = null;
    protected array $runtimeOverrides = [];

    public function __construct(
        protected Repository $config,
    ) {}

    /**
     * Resolve a Shield configuration value with full layering:
     * global → env → tenant → runtime
     */
    public function get(string $key, mixed $default = null): mixed
    {
        // Runtime overrides take highest priority
        if (array_key_exists($key, $this->runtimeOverrides)) {
            return $this->runtimeOverrides[$key];
        }

        // Tenant-scoped overrides
        if ($this->tenantId !== null) {
            $tenantKey = "shield.tenants.{$this->tenantId}.{$key}";
            if ($this->config->has($tenantKey)) {
                return $this->config->get($tenantKey);
            }
        }

        // Standard config (includes env() resolution from config file)
        return $this->config->get("shield.{$key}", $default);
    }

    /**
     * Check if Shield is globally enabled.
     */
    public function enabled(): bool
    {
        return (bool) $this->get('enabled', true);
    }

    /**
     * Get the global operating mode.
     */
    public function mode(): string
    {
        return $this->get('mode', 'monitor');
    }

    /**
     * Get guard-specific configuration.
     */
    public function guard(string $guard, ?string $key = null, mixed $default = null): mixed
    {
        if ($key === null) {
            return $this->get("guards.{$guard}", []);
        }

        return $this->get("guards.{$guard}.{$key}", $default);
    }

    /**
     * Determine if a specific guard is enabled.
     */
    public function guardEnabled(string $guard): bool
    {
        return $this->enabled() && (bool) $this->guard($guard, 'enabled', true);
    }

    /**
     * Resolve the effective mode for a guard.
     * Guard-level mode overrides global mode when set.
     */
    public function guardMode(string $guard): string
    {
        return $this->guard($guard, 'mode') ?? $this->mode();
    }

    /**
     * Set the current tenant context for configuration resolution.
     */
    public function setTenant(?string $tenantId): void
    {
        $this->tenantId = $tenantId;
    }

    /**
     * Get the current tenant context.
     */
    public function tenant(): ?string
    {
        return $this->tenantId;
    }

    /**
     * Set a runtime override (highest priority).
     */
    public function override(string $key, mixed $value): void
    {
        $this->runtimeOverrides[$key] = $value;
    }

    /**
     * Clear all runtime overrides.
     */
    public function clearOverrides(): void
    {
        $this->runtimeOverrides = [];
    }

    /**
     * Reset state for Octane worker reuse.
     */
    public function reset(): void
    {
        $this->tenantId = null;
        $this->runtimeOverrides = [];
    }

    /**
     * Get the full resolved configuration as an array.
     */
    public function all(): array
    {
        return $this->config->get('shield', []);
    }
}
