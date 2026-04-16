<?php

namespace VendorShield\Shield\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Http\UploadedFile;
use Illuminate\Support\Facades\RateLimiter;
use Symfony\Component\HttpFoundation\Response;
use VendorShield\Shield\Guards\HttpGuard;
use VendorShield\Shield\Guards\UploadGuard;
use VendorShield\Shield\Tenant\TenantContext;
use VendorShield\Shield\Config\ConfigResolver;
use VendorShield\Shield\Contracts\TenantResolverContract;

class ShieldMiddleware
{
    public function __construct(
        protected HttpGuard $httpGuard,
        protected UploadGuard $uploadGuard,
        protected ConfigResolver $config,
        protected TenantContext $tenantContext,
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
                \Illuminate\Support\Facades\Log::warning('Shield middleware error (fail-open)', [
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
     * @param array<mixed> $files
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

        return 'shield:upload:' . sha1($actor . '|' . $request->path());
    }
}
