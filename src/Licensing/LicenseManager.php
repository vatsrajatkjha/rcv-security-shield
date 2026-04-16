<?php

namespace VendorShield\Shield\Licensing;

use VendorShield\Shield\Contracts\LicenseManagerContract;
use VendorShield\Shield\Config\ConfigResolver;
use Illuminate\Contracts\Cache\Repository as CacheRepository;
use Illuminate\Support\Facades\Http;

class LicenseManager implements LicenseManagerContract
{
    protected ?string $resolvedTier = null;

    /** @var array<string, string> Feature → required tier mapping */
    protected array $featureGates = [
        // OSS features (always available)
        'http_guard' => 'oss',
        'upload_guard' => 'oss',
        'database_guard' => 'oss',
        'queue_guard' => 'oss',
        'basic_audit' => 'oss',

        // Pro features
        'advanced_detection' => 'pro',
        'tenant_isolation' => 'pro',
        'policy_engine' => 'pro',
        'audit_trails' => 'pro',
        'auth_guard' => 'pro',
        'cache_guard' => 'pro',

        // Enterprise features
        'cloud_intelligence' => 'enterprise',
        'compliance_reports' => 'enterprise',
        'centralized_policy' => 'enterprise',
        'threat_analytics' => 'enterprise',
    ];

    /** @var array<string, int> Tier hierarchy */
    protected const TIER_LEVELS = [
        'oss' => 0,
        'pro' => 1,
        'enterprise' => 2,
    ];

    public function __construct(
        protected ConfigResolver $config,
        protected CacheRepository $cache,
    ) {}

    /**
     * Check if a feature is available under the current license.
     */
    public function check(string $feature): bool
    {
        $requiredTier = $this->featureGates[$feature] ?? 'oss';
        $currentTier = $this->tier();

        $requiredLevel = self::TIER_LEVELS[$requiredTier] ?? 0;
        $currentLevel = self::TIER_LEVELS[$currentTier] ?? 0;

        return $currentLevel >= $requiredLevel;
    }

    /**
     * Get the current license tier.
     */
    public function tier(): string
    {
        if ($this->resolvedTier !== null) {
            return $this->resolvedTier;
        }

        $key = $this->config->get('licensing.key');

        if (empty($key)) {
            $this->resolvedTier = 'oss';
            return $this->resolvedTier;
        }

        // Check cache first
        $cacheKey = 'shield:license:tier';
        $cached = $this->cache->get($cacheKey);

        if ($cached !== null) {
            $this->resolvedTier = $cached;
            return $this->resolvedTier;
        }

        // Validate and resolve tier
        $this->resolvedTier = $this->resolveTier($key);

        // Cache the result
        $cacheTtl = $this->config->get('licensing.cache_ttl', 86400);
        $this->cache->put($cacheKey, $this->resolvedTier, $cacheTtl);

        return $this->resolvedTier;
    }

    /**
     * Validate the license (local + remote).
     */
    public function validate(): bool
    {
        $key = $this->config->get('licensing.key');

        if (empty($key)) {
            return false;
        }

        // Local validation (format check)
        if (! $this->validateFormat($key)) {
            return false;
        }

        // Remote validation (graceful failure)
        try {
            return $this->validateRemote($key);
        } catch (\Throwable) {
            // Fail open — never block on license server failure
            if ($this->config->get('licensing.fail_open', true)) {
                return true;
            }
            return false;
        }
    }

    /**
     * Determine if the license is valid (cached check).
     */
    public function isValid(): bool
    {
        $key = $this->config->get('licensing.key');

        if (empty($key)) {
            return false; // No license key = OSS mode (still valid, just no premium features)
        }

        $cacheKey = 'shield:license:valid';
        $cached = $this->cache->get($cacheKey);

        if ($cached !== null) {
            return $cached;
        }

        $valid = $this->validate();
        $this->cache->put($cacheKey, $valid, $this->config->get('licensing.cache_ttl', 86400));

        return $valid;
    }

    /**
     * Register a custom feature gate.
     */
    public function registerFeature(string $feature, string $requiredTier): void
    {
        $this->featureGates[$feature] = $requiredTier;
    }

    /**
     * Resolve the tier from a license key.
     */
    protected function resolveTier(string $key): string
    {
        // Local tier extraction from key format: SHIELD-{TIER}-{UUID}
        if (preg_match('/^SHIELD-(OSS|PRO|ENTERPRISE)-/i', $key, $matches)) {
            return strtolower($matches[1]);
        }

        // Try remote resolution
        try {
            $server = $this->config->get('licensing.server', 'https://license.shield.dev');
            $response = Http::timeout(5)->post("{$server}/api/v1/resolve", [
                'key' => $key,
            ]);

            if ($response->successful()) {
                return $response->json('tier', 'oss');
            }
        } catch (\Throwable) {
            // Fail gracefully
        }

        return 'oss';
    }

    /**
     * Validate license key format.
     */
    protected function validateFormat(string $key): bool
    {
        return (bool) preg_match('/^SHIELD-\w+-[\w-]{8,}$/', $key);
    }

    /**
     * Validate license key remotely.
     */
    protected function validateRemote(string $key): bool
    {
        $server = $this->config->get('licensing.server', 'https://license.shield.dev');

        // CLI-safe: use config app.url instead of request() which crashes in artisan/queue
        $domain = parse_url(config('app.url', 'localhost'), PHP_URL_HOST) ?? 'localhost';

        $response = Http::timeout(5)->post("{$server}/api/v1/validate", [
            'key' => $key,
            'domain' => $domain,
        ]);

        return $response->successful() && ($response->json('valid') === true);
    }
}
