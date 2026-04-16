<?php

namespace VendorShield\Shield\Commands;

use Illuminate\Console\Command;
use VendorShield\Shield\Config\ConfigResolver;
use VendorShield\Shield\Contracts\AuditDriverContract;
use VendorShield\Shield\Contracts\LicenseManagerContract;
use VendorShield\Shield\Support\FailSafe;

class ComplianceReportCommand extends Command
{
    protected $signature = 'shield:compliance-report
        {--type=soc2 : Report type (soc2, iso27001, gdpr)}
        {--from= : Start date (Y-m-d)}
        {--to= : End date (Y-m-d)}
        {--output= : Output file path}';

    protected $description = 'Generate a compliance audit report';

    public function handle(
        ConfigResolver $config,
        AuditDriverContract $auditDriver,
        LicenseManagerContract $license,
    ): int {
        // Feature gate: enterprise only
        if (! $license->check('compliance_reports')) {
            $this->components->warn('Compliance reports require an Enterprise license.');
            $this->components->info('Current tier: ' . strtoupper($license->tier()));
            $this->components->info('Visit https://shield.dev/pricing for upgrade options.');
            return self::SUCCESS;
        }

        $type = strtoupper($this->option('type'));
        $from = $this->option('from') ?? now()->subDays(30)->format('Y-m-d');
        $to = $this->option('to') ?? now()->format('Y-m-d');

        $this->components->info("Generating {$type} Compliance Report");
        $this->components->twoColumnDetail('Period', "{$from} to {$to}");
        $this->newLine();

        $report = [
            'report_type' => $type,
            'generated_at' => now()->toIso8601String(),
            'status' => 'experimental',
            'period' => ['from' => $from, 'to' => $to],
            'summary' => [],
            'audit_events' => [],
            'controls' => [],
        ];

        // Fetch audit data
        $this->components->task('Fetching audit records', function () use (&$report, $auditDriver, $from) {
            $records = $auditDriver->query([
                'since' => $from,
                'limit' => 10000,
            ]);
            $report['summary']['total_events'] = count($records);
            $report['audit_events'] = array_slice($records, 0, 100); // Sample for report
        });

        // Assess controls based on report type
        $this->components->task("Assessing {$type} controls", function () use (&$report, $type, $config) {
            $report['controls'] = $this->assessControls($type, $config);
        });

        // Calculate compliance score
        $controls = $report['controls'];
        $total = count($controls);
        $passed = count(array_filter($controls, fn ($c) => $c['status'] === 'pass'));
        $report['summary']['compliance_score'] = $total > 0 ? round(($passed / $total) * 100, 1) : 0;
        $report['summary']['controls_passed'] = $passed;
        $report['summary']['controls_total'] = $total;

        // Output results
        $this->newLine();
        $this->components->twoColumnDetail('Compliance Score', "{$report['summary']['compliance_score']}%");
        $this->components->twoColumnDetail('Controls Passed', "{$passed}/{$total}");
        $this->components->twoColumnDetail('Total Events', (string) $report['summary']['total_events']);

        // Save report
        $output = $this->option('output')
            ?? storage_path("shield/{$type}_report_" . now()->format('Y_m_d_His') . '.json');

        $dir = dirname($output);
        FailSafe::ensureDirectory($dir);
        FailSafe::writeFile($output, json_encode($report, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));

        $this->newLine();
        $this->components->info("Report saved to: {$output}");

        return self::SUCCESS;
    }

    protected function assessControls(string $type, ConfigResolver $config): array
    {
        $controls = [];

        // Common controls
        $controls['encryption_at_rest'] = [
            'control' => 'Data Encryption at Rest',
            'status' => ! empty(config('app.key')) ? 'pass' : 'fail',
        ];

        $controls['audit_logging'] = [
            'control' => 'Audit Logging Enabled',
            'status' => $config->get('audit.enabled', true) ? 'pass' : 'fail',
        ];

        $controls['runtime_protection'] = [
            'control' => 'Runtime Security Active',
            'status' => $config->enabled() ? 'pass' : 'fail',
        ];

        $controls['upload_protection'] = [
            'control' => 'File Upload Protection',
            'status' => $config->guardEnabled('upload') ? 'pass' : 'warning',
        ];

        $controls['sql_monitoring'] = [
            'control' => 'SQL Monitoring Active',
            'status' => $config->guardEnabled('database') ? 'pass' : 'warning',
        ];

        // Type-specific controls
        if ($type === 'GDPR') {
            $controls['data_scrubbing'] = [
                'control' => 'Sensitive Data Scrubbing',
                'status' => $config->guard('exception', 'scrub_sensitive_data', true) ? 'pass' : 'fail',
            ];

            $controls['tenant_isolation'] = [
                'control' => 'Tenant Data Isolation',
                'status' => $config->guardEnabled('tenant') ? 'pass' : 'warning',
            ];
        }

        if ($type === 'SOC2') {
            $controls['auth_monitoring'] = [
                'control' => 'Authentication Monitoring',
                'status' => $config->guardEnabled('auth') ? 'pass' : 'warning',
            ];

            $controls['exception_monitoring'] = [
                'control' => 'Exception Pattern Analysis',
                'status' => $config->guardEnabled('exception') ? 'pass' : 'warning',
            ];
        }

        return $controls;
    }
}
