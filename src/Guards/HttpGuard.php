<?php

namespace VendorShield\Shield\Guards;

use Illuminate\Http\Request;
use VendorShield\Shield\Async\ShieldAnalysisJob;
use VendorShield\Shield\Audit\AuditLogger;
use VendorShield\Shield\Config\ConfigResolver;
use VendorShield\Shield\Contracts\GuardContract;
use VendorShield\Shield\Events\GuardTriggered;
use VendorShield\Shield\Events\ThreatDetected;
use VendorShield\Shield\Support\FailSafe;
use VendorShield\Shield\Support\GuardResult;
use VendorShield\Shield\Support\Severity;

class HttpGuard implements GuardContract
{
    /** @var array<string, string> Suspicious patterns in request payloads */
    protected const SUSPICIOUS_PATTERNS = [
        'sql_injection' => '/(\bunion\b.*\bselect\b|\binsert\b.*\binto\b|\bdelete\b.*\bfrom\b|\bdrop\b.*\btable\b|\bexec\b|\bexecute\b)/i',
        'xss' => '/<script\b[^>]*>|javascript:|on\w+\s*=/i',
        'path_traversal' => '/\.\.[\/\\\\]/i',
        'command_injection' => '/[;&|`$]|\b(bash|sh|cmd|powershell)\b/i',
        'null_byte' => '/\x00/',
    ];

    public function __construct(
        protected ConfigResolver $config,
        protected AuditLogger $audit,
    ) {}

    public function name(): string
    {
        return 'http';
    }

    public function enabled(): bool
    {
        return $this->config->guardEnabled('http');
    }

    public function mode(): string
    {
        return $this->config->guardMode('http');
    }

    /**
     * Execute fast-path validation (<1ms target).
     * Deep inspection is dispatched async.
     */
    public function handle(mixed $context): GuardResult
    {
        if (! $context instanceof Request) {
            return GuardResult::pass($this->name());
        }

        // Fast-path checks
        $result = $this->fastValidation($context);

        if (! $result->passed && $this->mode() === 'enforce') {
            FailSafe::dispatch(fn () => event(new ThreatDetected($this->name(), $result)));
            FailSafe::dispatch(fn () => $this->audit->guardEvent($this->name(), 'threat_blocked', $result));

            return $result;
        }

        if (! $result->passed) {
            // Monitor mode — log but allow
            FailSafe::dispatch(fn () => event(new GuardTriggered($this->name(), $result)));
            FailSafe::dispatch(fn () => $this->audit->guardEvent($this->name(), 'threat_detected', $result));
        }

        // Dispatch async deep inspection (non-blocking)
        $this->dispatchAsyncInspection($context);

        return $result->passed ? $result : GuardResult::monitor(
            guard: $this->name(),
            message: $result->message,
            severity: $result->severity,
            metadata: $result->metadata,
        );
    }

    /**
     * Fast synchronous validation — must complete in <1ms.
     */
    protected function fastValidation(Request $request): GuardResult
    {
        // 1. Payload size check
        $maxPayload = $this->config->guard('http', 'max_payload_size', 10485760);
        $contentLength = $request->header('Content-Length', 0);

        if ($contentLength > $maxPayload) {
            return GuardResult::fail(
                guard: $this->name(),
                message: 'Request payload exceeds maximum allowed size',
                severity: Severity::Medium,
                metadata: ['content_length' => $contentLength, 'max' => $maxPayload],
            );
        }

        // 2. Header anomaly detection
        if ($this->config->guard('http', 'header_anomaly_detection', true)) {
            $headerResult = $this->checkHeaders($request);
            if (! $headerResult->passed) {
                return $headerResult;
            }
        }

        // 3. Request scoring — fast pattern scan on input
        if ($this->config->guard('http', 'request_scoring', true)) {
            $scoreResult = $this->scoreRequest($request);
            if (! $scoreResult->passed) {
                return $scoreResult;
            }
        }

        return GuardResult::pass($this->name());
    }

    /**
     * Detect header anomalies.
     */
    protected function checkHeaders(Request $request): GuardResult
    {
        // Check for missing User-Agent (bot indicator)
        if (empty($request->userAgent())) {
            return GuardResult::fail(
                guard: $this->name(),
                message: 'Missing User-Agent header',
                severity: Severity::Low,
                metadata: ['check' => 'header_anomaly'],
            );
        }

        // Check for suspicious Content-Type mismatches
        $contentType = $request->header('Content-Type', '');
        if ($request->isMethod('POST') && empty($contentType)) {
            return GuardResult::fail(
                guard: $this->name(),
                message: 'POST request without Content-Type header',
                severity: Severity::Low,
                metadata: ['check' => 'header_anomaly'],
            );
        }

        return GuardResult::pass($this->name());
    }

    /**
     * Score request input for suspicious patterns (fast scan).
     */
    protected function scoreRequest(Request $request): GuardResult
    {
        $input = $request->all();
        $flatInput = $this->flattenInput($input);

        foreach ($flatInput as $key => $value) {
            if (! is_string($value)) {
                continue;
            }

            foreach (self::SUSPICIOUS_PATTERNS as $type => $pattern) {
                if (preg_match($pattern, $value)) {
                    return GuardResult::fail(
                        guard: $this->name(),
                        message: "Suspicious pattern detected: {$type}",
                        severity: $this->patternSeverity($type),
                        metadata: [
                            'check' => 'request_scoring',
                            'pattern_type' => $type,
                            'field' => $key,
                        ],
                    );
                }
            }
        }

        return GuardResult::pass($this->name());
    }

    /**
     * Flatten nested input for pattern scanning.
     * Bounded to prevent memory exhaustion on crafted inputs.
     */
    protected function flattenInput(array $input, string $prefix = '', int $depth = 0): array
    {
        $flat = [];
        $maxDepth = 5;
        $maxTotalBytes = 65536; // 64KB

        if ($depth >= $maxDepth) {
            return $flat;
        }

        $totalBytes = 0;

        foreach ($input as $key => $value) {
            $fullKey = $prefix ? "{$prefix}.{$key}" : $key;

            if (is_array($value)) {
                $flat = array_merge($flat, $this->flattenInput($value, $fullKey, $depth + 1));
            } else {
                $strValue = is_string($value) ? $value : (string) $value;
                $totalBytes += strlen($strValue);

                if ($totalBytes > $maxTotalBytes) {
                    break; // Stop scanning — input too large
                }

                $flat[$fullKey] = $strValue;
            }
        }

        return $flat;
    }

    /**
     * Map pattern types to severity levels.
     */
    protected function patternSeverity(string $type): Severity
    {
        return match ($type) {
            'sql_injection' => Severity::Critical,
            'xss' => Severity::High,
            'command_injection' => Severity::Critical,
            'path_traversal' => Severity::High,
            'null_byte' => Severity::Medium,
            default => Severity::Medium,
        };
    }

    /**
     * Dispatch async deep inspection job (non-blocking).
     */
    protected function dispatchAsyncInspection(Request $request): void
    {
        if (! $this->config->get('async.enabled', true)) {
            return;
        }

        FailSafe::dispatch(function () use ($request) {
            ShieldAnalysisJob::dispatch([
                'guard' => $this->name(),
                'method' => $request->method(),
                'url' => $request->fullUrl(),
                'ip' => $request->ip(),
                'user_agent' => $request->userAgent(),
                'input_keys' => array_keys($request->all()),
                'timestamp' => now()->toIso8601String(),
            ])->onQueue($this->config->get('async.queue', 'shield'));
        });
    }
}
