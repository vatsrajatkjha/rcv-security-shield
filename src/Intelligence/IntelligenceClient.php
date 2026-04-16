<?php

namespace VendorShield\Shield\Intelligence;

use Illuminate\Support\Facades\Http;
use VendorShield\Shield\Config\ConfigResolver;
use VendorShield\Shield\Contracts\IntelligenceClientContract;

class IntelligenceClient implements IntelligenceClientContract
{
    public function __construct(
        protected ConfigResolver $config,
    ) {}

    public function available(): bool
    {
        return $this->config->get('intelligence.enabled', false)
            && ! empty($this->config->get('intelligence.api_key'));
    }

    public function sync(): void
    {
        if (! $this->available()) {
            return;
        }

        $endpoint = $this->config->get('intelligence.endpoint');
        $apiKey = $this->config->get('intelligence.api_key');

        try {
            Http::timeout(10)
                ->withHeaders(['Authorization' => "Bearer {$apiKey}"])
                ->get("{$endpoint}/api/v1/sync");
        } catch (\Throwable) {
            // Non-blocking — intelligence sync is best-effort
        }
    }

    public function report(ThreatFingerprint $fingerprint): void
    {
        if (! $this->available() || ! $this->config->get('intelligence.share_fingerprints', false)) {
            return;
        }

        try {
            $endpoint = $this->config->get('intelligence.endpoint');
            $apiKey = $this->config->get('intelligence.api_key');

            Http::timeout(5)
                ->withHeaders(['Authorization' => "Bearer {$apiKey}"])
                ->post("{$endpoint}/api/v1/report", $fingerprint->toArray());
        } catch (\Throwable) {
            // Non-blocking
        }
    }

    public function pullPolicies(): array
    {
        if (! $this->available()) {
            return [];
        }

        try {
            $endpoint = $this->config->get('intelligence.endpoint');
            $apiKey = $this->config->get('intelligence.api_key');

            $response = Http::timeout(10)
                ->withHeaders(['Authorization' => "Bearer {$apiKey}"])
                ->get("{$endpoint}/api/v1/policies");

            if ($response->successful()) {
                return $response->json('policies', []);
            }
        } catch (\Throwable) {
            // Non-blocking
        }

        return [];
    }
}
