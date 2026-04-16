<?php

namespace VendorShield\Shield\Policy;

use VendorShield\Shield\Contracts\PolicyLoaderContract;
use VendorShield\Shield\Config\ConfigResolver;
use Illuminate\Support\Collection;
use Illuminate\Contracts\Cache\Repository as CacheRepository;

class PolicyLoader implements PolicyLoaderContract
{
    protected ?Collection $cached = null;

    public function __construct(
        protected ConfigResolver $config,
        protected CacheRepository $cache,
    ) {}

    /**
     * Load all policies from the configured source.
     */
    public function load(): Collection
    {
        if ($this->cached !== null) {
            return $this->cached;
        }

        $shouldCache = $this->config->get('policy.cache', true);
        $cacheKey = 'shield:policies';

        if ($shouldCache) {
            $data = $this->cache->get($cacheKey);
            if ($data !== null) {
                $this->cached = $this->hydratePolicies($data);
                return $this->cached;
            }
        }

        $source = $this->config->get('policy.loader', 'config');

        $policies = match ($source) {
            'config' => $this->loadFromConfig(),
            'file' => $this->loadFromFile(),
            default => collect(),
        };

        if ($shouldCache) {
            $this->cache->put($cacheKey, $policies->map->toArray()->toArray(), $this->config->get('performance.cache_ttl', 3600));
        }

        $this->cached = $policies;
        return $policies;
    }

    /**
     * Load policies scoped to a specific guard.
     */
    public function forGuard(string $guard): Collection
    {
        return $this->load()->filter(fn (ConfigPolicy $policy) => $policy->guard() === $guard || $policy->guard() === '*');
    }

    /**
     * Load policies from shield config.
     */
    protected function loadFromConfig(): Collection
    {
        $rules = $this->config->get('policy.rules', []);

        return collect($rules)->map(fn (array $rule, int $index) => new ConfigPolicy(
            guard: $rule['guard'] ?? '*',
            condition: $rule['condition'] ?? '',
            action: $rule['action'] ?? 'monitor',
            priority: $rule['priority'] ?? ($index * 10),
        ));
    }

    /**
     * Load policies from a file path.
     */
    protected function loadFromFile(): Collection
    {
        $path = $this->config->get('policy.path');

        if (! $path || ! file_exists($path)) {
            return collect();
        }

        $extension = pathinfo($path, PATHINFO_EXTENSION);

        if ($extension === 'php') {
            $rules = require $path;
        } elseif ($extension === 'json') {
            $rules = json_decode(file_get_contents($path), true) ?? [];
        } else {
            return collect();
        }

        return collect($rules)->map(fn (array $rule, int $index) => new ConfigPolicy(
            guard: $rule['guard'] ?? '*',
            condition: $rule['condition'] ?? '',
            action: $rule['action'] ?? 'monitor',
            priority: $rule['priority'] ?? ($index * 10),
        ));
    }

    /**
     * Hydrate policy objects from cached array data.
     */
    protected function hydratePolicies(array $data): Collection
    {
        return collect($data)->map(fn (array $rule) => new ConfigPolicy(
            guard: $rule['guard'] ?? '*',
            condition: $rule['condition'] ?? '',
            action: $rule['action'] ?? 'monitor',
            priority: $rule['priority'] ?? 0,
        ));
    }

    /**
     * Clear the policy cache.
     */
    public function clearCache(): void
    {
        $this->cache->forget('shield:policies');
        $this->cached = null;
    }
}
