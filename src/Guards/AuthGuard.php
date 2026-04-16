<?php

namespace VendorShield\Shield\Guards;

use Illuminate\Support\Facades\Cache;
use VendorShield\Shield\Audit\AuditLogger;
use VendorShield\Shield\Config\ConfigResolver;
use VendorShield\Shield\Contracts\GuardContract;
use VendorShield\Shield\Events\GuardTriggered;
use VendorShield\Shield\Events\ThreatDetected;
use VendorShield\Shield\Support\FailSafe;
use VendorShield\Shield\Support\GuardResult;
use VendorShield\Shield\Support\Severity;

class AuthGuard implements GuardContract
{
    public function __construct(
        protected ConfigResolver $config,
        protected AuditLogger $audit,
    ) {}

    public function name(): string
    {
        return 'auth';
    }

    public function enabled(): bool
    {
        return $this->config->guardEnabled('auth');
    }

    public function mode(): string
    {
        return $this->config->guardMode('auth');
    }

    /**
     * Analyze authentication context for anomalies.
     *
     * @param  mixed  $context  Array with keys: ip, email, user_agent, event_type
     */
    public function handle(mixed $context): GuardResult
    {
        if (! is_array($context)) {
            return GuardResult::pass($this->name());
        }

        $eventType = $context['event_type'] ?? 'unknown';

        if ($eventType === 'failed_login') {
            return $this->checkBruteForce($context);
        }

        if ($eventType === 'login' && $this->config->guard('auth', 'impossible_travel', true)) {
            return $this->checkImpossibleTravel($context);
        }

        if ($eventType === 'session' && $this->config->guard('auth', 'session_anomaly', true)) {
            return $this->checkSessionAnomaly($context);
        }

        return GuardResult::pass($this->name());
    }

    /**
     * Detect brute force login attempts.
     */
    protected function checkBruteForce(array $context): GuardResult
    {
        $ip = $context['ip'] ?? 'unknown';
        $threshold = $this->config->guard('auth', 'brute_force_threshold', 5);
        $window = $this->config->guard('auth', 'brute_force_window', 300);

        $cacheKey = "shield:auth:failed:{$ip}";

        // Atomic increment — race-condition safe
        $attempts = Cache::increment($cacheKey);

        // Set TTL on first attempt only
        if ($attempts === 1) {
            Cache::put($cacheKey, $attempts, $window);
        }

        if ($attempts >= $threshold) {
            $result = GuardResult::fail(
                guard: $this->name(),
                message: "Brute force detected from IP: {$ip}",
                severity: Severity::High,
                metadata: [
                    'ip' => $ip,
                    'attempts' => $attempts,
                    'threshold' => $threshold,
                    'email' => $context['email'] ?? null,
                ],
            );

            $this->handleResult($result);

            return $result;
        }

        return GuardResult::pass($this->name());
    }

    /**
     * Detect impossible travel (login from distant locations in short time).
     */
    protected function checkImpossibleTravel(array $context): GuardResult
    {
        $userId = $context['user_id'] ?? null;
        $ip = $context['ip'] ?? null;

        if (! $userId || ! $ip) {
            return GuardResult::pass($this->name());
        }

        $cacheKey = "shield:auth:last_login:{$userId}";
        $lastLogin = Cache::get($cacheKey);

        Cache::put($cacheKey, [
            'ip' => $ip,
            'timestamp' => now()->timestamp,
        ], 86400);

        if ($lastLogin && $lastLogin['ip'] !== $ip) {
            $timeDiff = now()->timestamp - ($lastLogin['timestamp'] ?? 0);

            // If different IP within 5 minutes — suspicious
            if ($timeDiff < 300) {
                $result = GuardResult::fail(
                    guard: $this->name(),
                    message: 'Impossible travel detected — login from different IP in short timeframe',
                    severity: Severity::High,
                    metadata: [
                        'user_id' => $userId,
                        'current_ip' => $ip,
                        'previous_ip' => $lastLogin['ip'],
                        'time_diff_seconds' => $timeDiff,
                    ],
                );

                $this->handleResult($result);

                return $result;
            }
        }

        return GuardResult::pass($this->name());
    }

    /**
     * Detect session anomalies (user agent changes, etc.).
     */
    protected function checkSessionAnomaly(array $context): GuardResult
    {
        $sessionId = $context['session_id'] ?? null;
        $userAgent = $context['user_agent'] ?? null;

        if (! $sessionId || ! $userAgent) {
            return GuardResult::pass($this->name());
        }

        $cacheKey = "shield:auth:session:{$sessionId}";
        $storedAgent = Cache::get($cacheKey);

        if ($storedAgent === null) {
            Cache::put($cacheKey, $userAgent, 86400);

            return GuardResult::pass($this->name());
        }

        if ($storedAgent !== $userAgent) {
            $result = GuardResult::fail(
                guard: $this->name(),
                message: 'Session anomaly — User-Agent changed during session',
                severity: Severity::High,
                metadata: [
                    'session_id' => substr($sessionId, 0, 8).'...',
                    'expected_agent' => substr($storedAgent, 0, 50),
                    'actual_agent' => substr($userAgent, 0, 50),
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

        FailSafe::dispatch(fn () => $this->audit->guardEvent($this->name(), 'auth_threat', $result));
    }
}
