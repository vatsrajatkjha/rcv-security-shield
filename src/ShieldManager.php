<?php

namespace VendorShield\Shield;

use VendorShield\Shield\Config\ConfigResolver;
use VendorShield\Shield\Contracts\GuardContract;
use VendorShield\Shield\Contracts\IntelligenceClientContract;
use VendorShield\Shield\Policy\PolicyEngine;
use VendorShield\Shield\Tenant\TenantContext;
use VendorShield\Shield\Audit\AuditLogger;
use Illuminate\Contracts\Foundation\Application;

class ShieldManager
{
    /** @var array<string, GuardContract> */
    protected array $guards = [];

    /** @var array<string, string> Guard name → class for lazy resolution */
    protected array $lazyGuards = [];

    public function __construct(
        protected Application $app,
        protected ConfigResolver $config,
    ) {}

    /**
     * Check if Shield is enabled.
     */
    public function enabled(): bool
    {
        return $this->config->enabled();
    }

    /**
     * Get the current operating mode.
     */
    public function mode(): string
    {
        return $this->config->mode();
    }

    /**
     * Register a guard instance.
     */
    public function registerGuard(string $name, GuardContract $guard): void
    {
        $this->guards[$name] = $guard;
    }

    /**
     * Register a guard class for lazy resolution.
     */
    public function registerLazyGuard(string $name, string $class): void
    {
        $this->lazyGuards[$name] = $class;
    }

    /**
     * Get a registered guard by name (resolves lazily if needed).
     */
    public function guard(string $name): ?GuardContract
    {
        if (isset($this->guards[$name])) {
            return $this->guards[$name];
        }

        // Lazy resolution: construct on first access
        if (isset($this->lazyGuards[$name])) {
            $this->guards[$name] = $this->app->make($this->lazyGuards[$name]);
            return $this->guards[$name];
        }

        return null;
    }

    /**
     * Get all registered guards (resolves any lazy guards).
     *
     * @return array<string, GuardContract>
     */
    public function guards(): array
    {
        // Resolve any remaining lazy guards
        foreach ($this->lazyGuards as $name => $class) {
            if (! isset($this->guards[$name])) {
                $this->guards[$name] = $this->app->make($class);
            }
        }

        return $this->guards;
    }

    /**
     * Access the policy engine.
     */
    public function policy(): PolicyEngine
    {
        return $this->app->make(PolicyEngine::class);
    }

    /**
     * Access the tenant context.
     */
    public function tenant(?string $tenantId = null): TenantContext
    {
        $context = $this->app->make(TenantContext::class);

        if ($tenantId !== null) {
            $context->set($tenantId);
        }

        return $context;
    }

    /**
     * Access the intelligence client.
     */
    public function intelligence(): IntelligenceClientContract
    {
        return $this->app->make(IntelligenceClientContract::class);
    }

    /**
     * Access the audit logger.
     */
    public function audit(): AuditLogger
    {
        return $this->app->make(AuditLogger::class);
    }

    /**
     * Access the config resolver.
     */
    public function config(): ConfigResolver
    {
        return $this->config;
    }

    /**
     * Get health status of all guards.
     */
    public function health(): array
    {
        $status = [
            'enabled' => $this->enabled(),
            'mode' => $this->mode(),
            'guards' => [],
        ];

        foreach ($this->guards() as $name => $guard) {
            $status['guards'][$name] = [
                'enabled' => $guard->enabled(),
                'mode' => $guard->mode(),
            ];
        }

        return $status;
    }

    /**
     * Reset state for Octane worker reuse.
     */
    public function reset(): void
    {
        $this->config->reset();
    }
}
