<?php

namespace VendorShield\Shield\Guards;

use VendorShield\Shield\Config\ConfigResolver;
use VendorShield\Shield\Contracts\GuardContract;
use VendorShield\Shield\Support\GuardResult;
use VendorShield\Shield\Support\Severity;
use VendorShield\Shield\Audit\AuditLogger;
use VendorShield\Shield\Events\ThreatDetected;
use VendorShield\Shield\Events\GuardTriggered;
use VendorShield\Shield\Support\FailSafe;

class TenantGuard implements GuardContract
{
    public function __construct(
        protected ConfigResolver $config,
        protected AuditLogger $audit,
    ) {}

    public function name(): string
    {
        return 'tenant';
    }

    public function enabled(): bool
    {
        return $this->config->guardEnabled('tenant');
    }

    public function mode(): string
    {
        return $this->config->guardMode('tenant');
    }

    /**
     * Validate tenant context and enforce boundaries.
     *
     * @param mixed $context Array with keys: tenant_id, resource_tenant_id, action, resource
     */
    public function handle(mixed $context): GuardResult
    {
        if (! is_array($context)) {
            return GuardResult::pass($this->name());
        }

        $tenantId = $context['tenant_id'] ?? $this->config->tenant();
        $resourceTenantId = $context['resource_tenant_id'] ?? null;

        // 1. Verify tenant context exists
        if ($tenantId === null) {
            $isolationLevel = $this->config->guard('tenant', 'isolation_level', 'strict');

            if ($isolationLevel === 'strict') {
                $result = GuardResult::fail(
                    guard: $this->name(),
                    message: 'No tenant context available in strict isolation mode',
                    severity: Severity::High,
                    metadata: ['action' => $context['action'] ?? 'unknown'],
                );

                $this->handleResult($result);
                return $result;
            }

            return GuardResult::pass($this->name());
        }

        // 2. Cross-tenant access check
        if ($resourceTenantId !== null && $resourceTenantId !== $tenantId) {
            $result = GuardResult::fail(
                guard: $this->name(),
                message: 'Cross-tenant access attempt detected',
                severity: Severity::Critical,
                metadata: [
                    'current_tenant' => $tenantId,
                    'target_tenant' => $resourceTenantId,
                    'action' => $context['action'] ?? 'unknown',
                    'resource' => $context['resource'] ?? 'unknown',
                ],
            );

            $this->handleResult($result);
            return $result;
        }

        return GuardResult::pass($this->name());
    }

    protected function handleResult(GuardResult $result): void
    {
        FailSafe::dispatch(function () use ($result) {
            if ($this->mode() === 'enforce') {
                event(new ThreatDetected($this->name(), $result));
            } else {
                event(new GuardTriggered($this->name(), $result));
            }
        });

        FailSafe::dispatch(fn () => $this->audit->guardEvent($this->name(), 'tenant_violation', $result));
    }
}
