<?php

namespace VendorShield\Shield\Threat;

use VendorShield\Shield\Async\AnalysisResult;
use VendorShield\Shield\Config\ConfigResolver;
use VendorShield\Shield\Context\RequestContextStore;
use VendorShield\Shield\Contracts\ThreatDriverContract;
use VendorShield\Shield\Support\GuardResult;

class ThreatLogger
{
    public function __construct(
        protected ThreatDriverContract $driver,
        protected ConfigResolver $config,
        protected RequestContextStore $requestContext,
    ) {}

    public function enabled(): bool
    {
        return (bool) $this->config->get('threats.enabled', true);
    }

    public function logGuardThreat(
        string $guard,
        string $eventType,
        GuardResult $result,
        ?string $fingerprint = null,
    ): ?ThreatEntry {
        if (! $this->enabled()) {
            return null;
        }

        $entry = new ThreatEntry(
            guard: $guard,
            threatType: $eventType,
            tenantId: $this->config->tenant(),
            fingerprint: $fingerprint ?? $this->fingerprintForGuardThreat($guard, $eventType, $result),
            requestData: [
                'message' => $result->message,
                'severity' => $result->severity->value,
                'metadata' => $result->metadata,
                'guard' => $result->guard,
                'passed' => $result->passed,
                'mode' => $this->config->guardMode($guard),
                'request_context' => $this->requestContext->all(),
            ],
        );

        try {
            $this->driver->log($entry);
        } catch (\Throwable) {
            // Fail-safe
        }

        return $entry;
    }

    public function logAnalysisThreat(
        string $guard,
        AnalysisResult $result,
        ?string $fingerprint = null,
    ): ?ThreatEntry {
        if (! $this->enabled() || $result->clean) {
            return null;
        }

        $entry = new ThreatEntry(
            guard: $guard,
            threatType: 'analysis_complete',
            tenantId: $this->config->tenant(),
            fingerprint: $fingerprint ?? $this->fingerprintForAnalysisThreat($guard, $result),
            requestData: [
                'summary' => $result->summary,
                'severity' => $result->severity->value,
                'driver' => $result->driver,
                'findings' => $result->findings,
                'metadata' => $result->metadata,
                'clean' => $result->clean,
                'request_context' => $this->requestContext->all(),
            ],
        );

        try {
            $this->driver->log($entry);
        } catch (\Throwable) {
            // Fail-safe
        }

        return $entry;
    }

    public function fingerprintForGuardThreat(string $guard, string $eventType, GuardResult $result): string
    {
        return $this->fingerprint([
            'guard' => $guard,
            'event_type' => $eventType,
            'message' => $result->message,
            'severity' => $result->severity->value,
            'metadata' => $this->normalize($result->metadata),
        ]);
    }

    public function fingerprintForAnalysisThreat(string $guard, AnalysisResult $result): string
    {
        return $this->fingerprint([
            'guard' => $guard,
            'event_type' => 'analysis_complete',
            'driver' => $result->driver,
            'summary' => $result->summary,
            'severity' => $result->severity->value,
            'findings' => $this->normalize($result->findings),
        ]);
    }

    protected function fingerprint(array $payload): string
    {
        return hash('sha256', json_encode($this->normalize($payload), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
    }

    protected function normalize(mixed $value): mixed
    {
        if (! is_array($value)) {
            return $value;
        }

        ksort($value);

        foreach ($value as $key => $item) {
            $value[$key] = $this->normalize($item);
        }

        return $value;
    }
}
