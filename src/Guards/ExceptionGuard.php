<?php

namespace VendorShield\Shield\Guards;

use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Contracts\Foundation\Application;
use Throwable;
use VendorShield\Shield\Audit\AuditLogger;
use VendorShield\Shield\Config\ConfigResolver;
use VendorShield\Shield\Events\GuardTriggered;
use VendorShield\Shield\Support\FailSafe;
use VendorShield\Shield\Support\GuardResult;
use VendorShield\Shield\Support\Severity;

/**
 * Exception guard — decorates the Laravel exception handler.
 * Implements ExceptionHandler to maintain contract compatibility.
 */
class ExceptionGuard implements ExceptionHandler
{
    public function __construct(
        protected ExceptionHandler $inner,
        protected ConfigResolver $config,
        protected Application $app,
    ) {}

    public function report(Throwable $e): void
    {
        $this->analyzeException($e);
        $this->inner->report($e);
    }

    public function shouldReport(Throwable $e): bool
    {
        return $this->inner->shouldReport($e);
    }

    public function render($request, Throwable $e)
    {
        // Scrub sensitive data from exception messages before rendering
        if ($this->config->guard('exception', 'scrub_sensitive_data', true)) {
            $e = $this->scrubException($e);
        }

        return $this->inner->render($request, $e);
    }

    public function renderForConsole($output, Throwable $e): void
    {
        $this->inner->renderForConsole($output, $e);
    }

    /**
     * Analyze exception for security patterns.
     */
    protected function analyzeException(Throwable $e): void
    {
        if (! $this->config->guard('exception', 'pattern_analysis', true)) {
            return;
        }

        $classification = $this->classifyException($e);

        if ($classification !== null) {
            $result = GuardResult::fail(
                guard: 'exception',
                message: "Security exception detected: {$classification}",
                severity: $this->classificationSeverity($classification),
                metadata: [
                    'exception_class' => get_class($e),
                    'classification' => $classification,
                    'message_preview' => substr($e->getMessage(), 0, 200),
                    'file' => $e->getFile(),
                    'line' => $e->getLine(),
                ],
            );

            FailSafe::dispatch(function () use ($result) {
                $this->app->make(AuditLogger::class)->guardEvent('exception', 'security_exception', $result);
                event(new GuardTriggered('exception', $result));
            });
        }
    }

    /**
     * Classify an exception into security categories.
     */
    protected function classifyException(Throwable $e): ?string
    {
        $class = get_class($e);
        $message = $e->getMessage();

        // SQL-related security exceptions
        if (str_contains($class, 'QueryException') || str_contains($class, 'PDOException')) {
            if (preg_match('/syntax error|access denied|constraint violation/i', $message)) {
                return 'sql_anomaly';
            }
        }

        // Authentication exceptions
        if (str_contains($class, 'AuthenticationException') || str_contains($class, 'AuthorizationException')) {
            return 'auth_failure';
        }

        // Filesystem exceptions
        if (str_contains($class, 'FileNotFoundException') || str_contains($message, 'Permission denied')) {
            return 'filesystem_anomaly';
        }

        // Validation exceptions (may indicate probing)
        if (str_contains($class, 'ValidationException')) {
            return null; // Normal flow, not a security concern
        }

        // Serialization/deserialization exceptions
        if (str_contains($message, 'unserialize') || str_contains($message, 'Allowed memory')) {
            return 'deserialization_risk';
        }

        return null;
    }

    /**
     * Map classification to severity.
     */
    protected function classificationSeverity(string $classification): Severity
    {
        return match ($classification) {
            'sql_anomaly' => Severity::High,
            'auth_failure' => Severity::Medium,
            'filesystem_anomaly' => Severity::Medium,
            'deserialization_risk' => Severity::Critical,
            default => Severity::Low,
        };
    }

    /**
     * Scrub sensitive data from exception message.
     */
    protected function scrubException(Throwable $e): Throwable
    {
        $sensitiveKeys = $this->config->guard('exception', 'sensitive_keys', [
            'password', 'secret', 'token', 'api_key', 'authorization',
        ]);

        $message = $e->getMessage();
        $scrubbed = false;

        foreach ($sensitiveKeys as $key) {
            $pattern = "/({$key})\s*[=:]\s*['\"]?([^'\"\\s,;]+)/i";
            if (preg_match($pattern, $message)) {
                $message = preg_replace($pattern, '$1=[REDACTED]', $message);
                $scrubbed = true;
            }
        }

        if ($scrubbed) {
            return new \RuntimeException($message, $e->getCode(), $e);
        }

        return $e;
    }
}
