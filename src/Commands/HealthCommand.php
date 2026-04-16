<?php

namespace VendorShield\Shield\Commands;

use Illuminate\Console\Command;
use VendorShield\Shield\ShieldManager;
use VendorShield\Shield\Config\ConfigResolver;
use VendorShield\Shield\Contracts\LicenseManagerContract;
use VendorShield\Shield\Contracts\IntelligenceClientContract;
use VendorShield\Shield\Runtime\RuntimeHookManager;

class HealthCommand extends Command
{
    protected $signature = 'shield:health';

    protected $description = 'Check the health status of all Shield components';

    public function handle(
        ShieldManager $manager,
        ConfigResolver $config,
        LicenseManagerContract $license,
        IntelligenceClientContract $intelligence,
        RuntimeHookManager $hooks,
    ): int {
        $this->components->info('Laravel Shield Health Check');
        $this->newLine();

        // Global status
        $this->outputStatus('Shield Enabled', $config->enabled());
        $this->outputStatus('Runtime Hooks Booted', $hooks->isBooted());
        $this->components->twoColumnDetail('Global Mode', $config->mode());

        $this->newLine();
        $this->components->info('Guard Status');

        // Guard statuses
        $health = $manager->health();
        foreach ($health['guards'] as $name => $status) {
            $label = ucfirst($name) . ' Guard';
            $this->components->twoColumnDetail(
                $label,
                $status['enabled']
                    ? "<fg=green>✓ Enabled</> ({$status['mode']})"
                    : '<fg=yellow>○ Disabled</>'
            );
        }

        $this->newLine();
        $this->components->info('Subsystem Status');

        // License
        $this->components->twoColumnDetail('License Tier', strtoupper($license->tier()));
        $this->outputStatus('License Valid', $license->isValid() || $license->tier() === 'oss');

        // Intelligence
        $this->outputStatus('Cloud Intelligence', $intelligence->available());

        // Database check
        try {
            \DB::connection()->getPdo();
            $this->outputStatus('Database Connection', true);
        } catch (\Throwable) {
            $this->outputStatus('Database Connection', false);
        }

        // Storage directories
        $quarantine = storage_path('app/' . config('shield.guards.upload.quarantine_path', 'shield/quarantine'));
        $scanned = storage_path('app/' . config('shield.guards.upload.scanned_path', 'shield/scanned'));
        $this->outputStatus('Quarantine Directory', is_dir($quarantine) && is_writable($quarantine));
        $this->outputStatus('Scanned Directory', is_dir($scanned) && is_writable($scanned));

        $this->newLine();

        return self::SUCCESS;
    }

    protected function outputStatus(string $label, bool $healthy): void
    {
        $status = $healthy
            ? '<fg=green>✓ OK</>'
            : '<fg=red>✗ FAIL</>';

        $this->components->twoColumnDetail($label, $status);
    }
}
