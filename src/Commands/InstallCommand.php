<?php

namespace VendorShield\Shield\Commands;

use Illuminate\Console\Command;
use VendorShield\Shield\Support\FailSafe;

class InstallCommand extends Command
{
    protected $signature = 'shield:install
        {--force : Overwrite existing configuration}';

    protected $description = 'Install Laravel Shield — publish config, run migrations, create directories';

    public function handle(): int
    {
        $this->components->info('Installing Laravel Shield...');

        // 1. Publish config
        $this->call('vendor:publish', [
            '--tag' => 'shield-config',
            '--force' => $this->option('force'),
        ]);

        // 2. Run migrations
        if ($this->components->confirm('Run Shield database migrations?', true)) {
            $this->call('migrate', [
                '--path' => realpath(__DIR__ . '/../../database/migrations') ?: __DIR__ . '/../../database/migrations',
                '--realpath' => true,
            ]);
        }

        // 3. Create storage directories
        $quarantinePath = storage_path('app/' . config('shield.guards.upload.quarantine_path', 'shield/quarantine'));
        $scannedPath = storage_path('app/' . config('shield.guards.upload.scanned_path', 'shield/scanned'));

        foreach ([$quarantinePath, $scannedPath] as $path) {
            if (! is_dir($path) && FailSafe::ensureDirectory($path)) {
                $this->components->info("Created directory: {$path}");
            }
        }

        // 4. Add .gitignore to quarantine
        $gitignore = $quarantinePath . '/.gitignore';
        if (! file_exists($gitignore)) {
            FailSafe::writeFile($gitignore, "*\n!.gitignore\n");
        }

        $this->newLine();
        $this->components->info('Laravel Shield installed successfully!');
        $this->components->info('Run `php artisan shield:health` to verify your installation.');

        return self::SUCCESS;
    }
}
