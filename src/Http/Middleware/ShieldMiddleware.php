<?php

namespace VendorShield\Shield\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Http\UploadedFile;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\RateLimiter;
use Symfony\Component\HttpFoundation\Response;
use VendorShield\Shield\Audit\AuditLogger;
use VendorShield\Shield\Config\ConfigResolver;
use VendorShield\Shield\Context\RequestContextStore;
use VendorShield\Shield\Contracts\AccessControlDeciderContract;
use VendorShield\Shield\Contracts\RequestContextResolverContract;
use VendorShield\Shield\Contracts\TenantResolverContract;
use VendorShield\Shield\Guards\HttpGuard;
use VendorShield\Shield\Guards\UploadGuard;
use VendorShield\Shield\Support\GuardResult;
use VendorShield\Shield\Support\Severity;
use VendorShield\Shield\Tenant\TenantContext;

class ShieldMiddleware
{
    public function __construct(
        protected HttpGuard $httpGuard,
        protected UploadGuard $uploadGuard,
        protected ConfigResolver $config,
        protected TenantContext $tenantContext,
        protected AuditLogger $auditLogger,
        protected RequestContextStore $requestContext,
        protected RequestContextResolverContract $requestContextResolver,
        protected AccessControlDeciderContract $accessControlDecider,
        protected ?TenantResolverContract $tenantResolver = null,
    ) {}

    public function handle(Request $request, Closure $next): Response
    {
        if (! $this->config->enabled()) {
            return $next($request);
        }

        // Fail-open: any internal Shield error must never crash the application
        try {
            // Resolve tenant context
            $this->resolveTenant($request);
            $this->requestContext->set($this->requestContextResolver->resolve($request));

            if ($response = $this->enforceAccessDecision($request)) {
                return $response;
            }

            // HTTP Guard — fast-path validation
            if ($this->httpGuard->enabled()) {
                $result = $this->httpGuard->handle($request);

                if (! $result->passed && $this->httpGuard->mode() === 'enforce') {
                    return response()->json([
                        'error' => 'Request blocked by security policy',
                        'reference' => uniqid('shield_'),
                    ], 403);
                }
            }

            // Upload Guard — validate uploaded files
            if ($this->uploadGuard->enabled() && count($request->allFiles()) > 0) {
                if ($rateLimitResponse = $this->enforceUploadRateLimit($request)) {
                    return $rateLimitResponse;
                }

                foreach ($this->extractFiles($request->allFiles()) as $file) {
                    $result = $this->uploadGuard->handle($file);

                    if (! $result->passed && $this->uploadGuard->mode() === 'enforce') {
                        return response()->json([
                            'error' => 'File upload blocked by security policy',
                            'reference' => uniqid('shield_'),
                        ], 422);
                    }
                }
            }
        } catch (\Throwable $e) {
            // Fail-open: log the error but never block the request
            try {
                Log::warning('Shield middleware error (fail-open)', [
                    'exception' => $e->getMessage(),
                    'file' => $e->getFile(),
                    'line' => $e->getLine(),
                ]);
            } catch (\Throwable) {
                // Even logging failed — silently continue
            }
        }

        return $next($request);
    }

    protected function enforceAccessDecision(Request $request): ?Response
    {
        $decision = $this->accessControlDecider->decide($request, $this->requestContext->all());

        if ($decision === null || ! $decision->block) {
            return null;
        }

        try {
            $this->auditLogger->guardEvent('http', 'threat_blocked', GuardResult::fail(
                guard: 'http',
                message: $decision->message,
                severity: Severity::Critical,
                metadata: array_merge($decision->metadata, [
                    'check' => 'access_control',
                    'decision_code' => $decision->code,
                ]),
            ));
        } catch (\Throwable) {
            // Never fail closed because logging failed
        }

        return response()->json([
            'error' => 'Request blocked by security policy',
            'message' => $decision->message,
            'reference' => $this->requestContext->all()['request_id'] ?? uniqid('shield_'),
        ], $decision->statusCode);
    }

    /**
     * Resolve the tenant context for the current request.
     */
    protected function resolveTenant(Request $request): void
    {
        if (! $this->config->guardEnabled('tenant') || $this->tenantResolver === null) {
            return;
        }

        $tenantId = $this->tenantResolver->resolve($request);

        if ($tenantId !== null) {
            $this->tenantContext->set($tenantId);
            $this->config->setTenant($tenantId);
        }
    }

    /**
     * @param  array<mixed>  $files
     * @return array<int, UploadedFile>
     */
    protected function extractFiles(array $files): array
    {
        $flattened = [];

        foreach ($files as $file) {
            if ($file instanceof UploadedFile) {
                $flattened[] = $file;

                continue;
            }

            if (is_array($file)) {
                array_push($flattened, ...$this->extractFiles($file));
            }
        }

        return $flattened;
    }

    protected function enforceUploadRateLimit(Request $request): ?Response
    {
        if (! $this->config->guard('upload', 'rate_limit.enabled', true)) {
            return null;
        }

        $maxAttempts = (int) $this->config->guard('upload', 'rate_limit.max_attempts', 10);
        $decaySeconds = (int) $this->config->guard('upload', 'rate_limit.decay_seconds', 60);
        $key = $this->uploadRateLimitKey($request);

        if (RateLimiter::tooManyAttempts($key, $maxAttempts)) {
            return response()->json([
                'error' => 'Upload rate limit exceeded',
                'retry_after' => RateLimiter::availableIn($key),
                'reference' => uniqid('shield_'),
            ], 429);
        }

        RateLimiter::hit($key, $decaySeconds);

        return null;
    }

    protected function uploadRateLimitKey(Request $request): string
    {
        $actor = $request->user()?->getAuthIdentifier()
            ?? $this->tenantContext->id()
            ?? $request->ip()
            ?? 'unknown';

        return 'shield:upload:'.sha1($actor.'|'.$request->path());
    }
}
