<?php

namespace VendorShield\Shield\Guards;

use Illuminate\Queue\Events\JobProcessing;
use Illuminate\Queue\Events\JobFailed;
use VendorShield\Shield\Config\ConfigResolver;
use VendorShield\Shield\Contracts\GuardContract;
use VendorShield\Shield\Support\GuardResult;
use VendorShield\Shield\Support\Severity;
use VendorShield\Shield\Audit\AuditLogger;
use VendorShield\Shield\Events\ThreatDetected;
use VendorShield\Shield\Events\GuardTriggered;
use VendorShield\Shield\Support\FailSafe;

class QueueGuard implements GuardContract
{
    protected int $failedCount = 0;

    public function __construct(
        protected ConfigResolver $config,
        protected AuditLogger $audit,
    ) {}

    public function name(): string
    {
        return 'queue';
    }

    public function enabled(): bool
    {
        return $this->config->guardEnabled('queue');
    }

    public function mode(): string
    {
        return $this->config->guardMode('queue');
    }

    /**
     * Guard processing jobs.
     */
    public function handle(mixed $context): GuardResult
    {
        if (! $context instanceof JobProcessing) {
            return GuardResult::pass($this->name());
        }

        $jobClass = $context->job->resolveName();

        // 1. Job whitelist/blacklist check
        $result = $this->checkJobAllowance($jobClass);
        if (! $result->passed) {
            $this->handleResult($result);
            return $result;
        }

        // 2. Payload inspection
        if ($this->config->guard('queue', 'payload_inspection', true)) {
            $result = $this->inspectPayload($context);
            if (! $result->passed) {
                $this->handleResult($result);
                return ($this->mode() === 'enforce') ? $result : GuardResult::monitor(
                    guard: $this->name(),
                    message: $result->message,
                    severity: $result->severity,
                    metadata: $result->metadata,
                );
            }
        }

        return GuardResult::pass($this->name());
    }

    /**
     * Handle failed job analysis.
     */
    public function handleFailed(JobFailed $event): void
    {
        if (! $this->config->guard('queue', 'failed_pattern_analysis', true)) {
            return;
        }

        $this->failedCount++;

        $result = GuardResult::fail(
            guard: $this->name(),
            message: 'Job failure detected',
            severity: $this->failedCount > 10 ? Severity::High : Severity::Low,
            metadata: [
                'job' => $event->job->resolveName(),
                'exception' => $event->exception?->getMessage(),
                'failed_count_session' => $this->failedCount,
            ],
        );

        FailSafe::dispatch(fn () => $this->audit->guardEvent($this->name(), 'job_failed', $result));
        FailSafe::dispatch(fn () => event(new GuardTriggered($this->name(), $result)));
    }

    protected function checkJobAllowance(string $jobClass): GuardResult
    {
        $whitelist = $this->config->guard('queue', 'job_whitelist', []);
        $blacklist = $this->config->guard('queue', 'job_blacklist', []);

        // If whitelist is non-empty, only allow listed jobs
        if (! empty($whitelist) && ! in_array($jobClass, $whitelist, true)) {
            return GuardResult::fail(
                guard: $this->name(),
                message: "Job not in whitelist: {$jobClass}",
                severity: Severity::High,
                metadata: ['job_class' => $jobClass],
            );
        }

        // Blacklist check
        if (in_array($jobClass, $blacklist, true)) {
            return GuardResult::fail(
                guard: $this->name(),
                message: "Job is blacklisted: {$jobClass}",
                severity: Severity::Critical,
                metadata: ['job_class' => $jobClass],
            );
        }

        return GuardResult::pass($this->name());
    }

    protected function inspectPayload(JobProcessing $event): GuardResult
    {
        $payload = $event->job->payload();
        $data = $payload['data'] ?? [];

        // Check for suspiciously large payloads
        $payloadSize = strlen(json_encode($data) ?: '');
        if ($payloadSize > 1048576) { // 1MB
            return GuardResult::fail(
                guard: $this->name(),
                message: 'Job payload exceeds size threshold',
                severity: Severity::Medium,
                metadata: [
                    'job' => $event->job->resolveName(),
                    'payload_size' => $payloadSize,
                ],
            );
        }

        // Check for serialized objects in payload (deserialization attacks)
        $serialized = json_encode($data) ?: '';
        if (preg_match('/O:\d+:"[^"]+"/i', $serialized)) {
            return GuardResult::fail(
                guard: $this->name(),
                message: 'Potential deserialization attack in job payload',
                severity: Severity::Critical,
                metadata: ['job' => $event->job->resolveName()],
            );
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

        FailSafe::dispatch(fn () => $this->audit->guardEvent($this->name(), 'queue_threat', $result));
    }
}
