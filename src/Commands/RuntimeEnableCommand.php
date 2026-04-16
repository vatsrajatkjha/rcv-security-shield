<?php

namespace VendorShield\Shield\Commands;

use Illuminate\Console\Command;
use VendorShield\Shield\Config\ConfigResolver;

class RuntimeEnableCommand extends Command
{
    protected $signature = 'shield:runtime:enable
        {--disable : Disable runtime hooks instead of enabling}
        {--guard= : Enable/disable a specific guard only}';

    protected $description = 'Enable or disable Shield runtime hooks';

    public function handle(ConfigResolver $config): int
    {
        $disable = $this->option('disable');
        $guard = $this->option('guard');

        if ($guard) {
            $this->toggleGuard($guard, ! $disable);
        } else {
            $this->toggleGlobal(! $disable);
        }

        return self::SUCCESS;
    }

    protected function toggleGlobal(bool $enable): void
    {
        $this->updateEnvValue('SHIELD_ENABLED', $enable ? 'true' : 'false');

        $status = $enable ? 'enabled' : 'disabled';
        $this->components->info("Shield runtime hooks {$status}.");
        $this->components->warn('You may need to restart your application for changes to take effect.');
    }

    protected function toggleGuard(string $guard, bool $enable): void
    {
        $envKey = 'SHIELD_' . strtoupper($guard) . '_ENABLED';
        $this->updateEnvValue($envKey, $enable ? 'true' : 'false');

        $status = $enable ? 'enabled' : 'disabled';
        $this->components->info("Shield {$guard} guard {$status}.");
        $this->components->warn('You may need to restart your application for changes to take effect.');
    }

    protected function updateEnvValue(string $key, string $value): void
    {
        $envPath = base_path('.env');

        if (! file_exists($envPath)) {
            $this->components->error('.env file not found');
            return;
        }

        $content = file_get_contents($envPath);

        if (str_contains($content, "{$key}=")) {
            $content = preg_replace(
                "/^{$key}=.*/m",
                "{$key}={$value}",
                $content
            );
        } else {
            $content .= "\n{$key}={$value}\n";
        }

        file_put_contents($envPath, $content);
    }
}
