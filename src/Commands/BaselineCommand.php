<?php

namespace VendorShield\Shield\Commands;

use Illuminate\Console\Command;
use VendorShield\Shield\Config\ConfigResolver;
use VendorShield\Shield\ShieldManager;
use VendorShield\Shield\Support\FailSafe;

class BaselineCommand extends Command
{
    protected $signature = 'shield:baseline
        {--output= : Output file path for the baseline report}';

    protected $description = 'Generate a security baseline snapshot of the current application state';

    public function handle(ShieldManager $manager, ConfigResolver $config): int
    {
        $this->components->info('Generating Shield Security Baseline...');

        $baseline = [
            'generated_at' => now()->toIso8601String(),
            'shield_version' => '1.0.0',
            'mode' => $config->mode(),
            'guards' => [],
            'environment' => [
                'php_version' => PHP_VERSION,
                'laravel_version' => app()->version(),
                'debug_mode' => config('app.debug'),
                'environment' => config('app.env'),
            ],
            'security_checks' => [],
        ];

        // Guard configuration baseline
        foreach ($manager->guards() as $name => $guard) {
            $baseline['guards'][$name] = [
                'enabled' => $guard->enabled(),
                'mode' => $guard->mode(),
            ];
        }

        // Security checks
        $this->components->task('Checking debug mode', function () use (&$baseline) {
            $debugEnabled = config('app.debug', false);
            $baseline['security_checks']['debug_mode'] = [
                'status' => ! $debugEnabled ? 'pass' : 'warning',
                'detail' => $debugEnabled ? 'Debug mode is enabled — disable in production' : 'Debug mode disabled',
            ];

            return ! $debugEnabled;
        });

        $this->components->task('Checking APP_KEY', function () use (&$baseline) {
            $hasKey = ! empty(config('app.key'));
            $baseline['security_checks']['app_key'] = [
                'status' => $hasKey ? 'pass' : 'fail',
                'detail' => $hasKey ? 'APP_KEY is set' : 'APP_KEY is missing',
            ];

            return $hasKey;
        });

        $this->components->task('Checking HTTPS enforcement', function () use (&$baseline) {
            $forcesHttps = config('app.url', '') !== '' && str_starts_with(config('app.url'), 'https');
            $baseline['security_checks']['https'] = [
                'status' => $forcesHttps ? 'pass' : 'info',
                'detail' => $forcesHttps ? 'HTTPS is enforced' : 'HTTPS not detected in APP_URL',
            ];

            return $forcesHttps;
        });

        $this->components->task('Checking session security', function () use (&$baseline) {
            $secure = config('session.secure', false);
            $httpOnly = config('session.http_only', true);
            $baseline['security_checks']['session'] = [
                'status' => ($secure && $httpOnly) ? 'pass' : 'warning',
                'secure_cookie' => $secure,
                'http_only' => $httpOnly,
            ];

            return $secure && $httpOnly;
        });

        // Output
        $output = $this->option('output') ?? storage_path('shield/baseline_'.now()->format('Y_m_d_His').'.json');
        $dir = dirname($output);
        FailSafe::ensureDirectory($dir);

        FailSafe::writeFile(
            $output,
            json_encode($baseline, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)
        );

        $this->newLine();
        $this->components->info("Baseline saved to: {$output}");

        return self::SUCCESS;
    }
}
