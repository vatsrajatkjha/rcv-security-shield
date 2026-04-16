<?php

namespace VendorShield\Shield;

use Illuminate\Support\ServiceProvider;
use VendorShield\Shield\Config\ConfigResolver;
use VendorShield\Shield\Runtime\RuntimeHookManager;
use VendorShield\Shield\Guards\HttpGuard;
use VendorShield\Shield\Guards\DatabaseGuard;
use VendorShield\Shield\Guards\UploadGuard;
use VendorShield\Shield\Guards\Upload\FilenameCanonicalizer;
use VendorShield\Shield\Guards\Upload\RecursiveDecoder;
use VendorShield\Shield\Guards\Upload\MagicByteValidator;
use VendorShield\Shield\Guards\Upload\PolyglotDetector;
use VendorShield\Shield\Guards\Upload\ContentScannerV2;
use VendorShield\Shield\Guards\Upload\SafeStoragePolicy;
use VendorShield\Shield\Guards\Upload\StreamProcessor;
use VendorShield\Shield\Guards\Upload\ArchiveInspector;
use VendorShield\Shield\Guards\QueueGuard;
use VendorShield\Shield\Guards\AuthGuard;
use VendorShield\Shield\Guards\CacheGuard;
use VendorShield\Shield\Guards\TenantGuard;
use VendorShield\Shield\Policy\PolicyEngine;
use VendorShield\Shield\Policy\PolicyLoader;
use VendorShield\Shield\Tenant\TenantContext;
use VendorShield\Shield\Tenant\HeaderTenantResolver;
use VendorShield\Shield\Licensing\LicenseManager;
use VendorShield\Shield\Licensing\FeatureGate;
use VendorShield\Shield\Intelligence\IntelligenceClient;
use VendorShield\Shield\Intelligence\NullIntelligenceClient;
use VendorShield\Shield\Audit\AuditLogger;
use VendorShield\Shield\Audit\DatabaseAuditDriver;
use VendorShield\Shield\Audit\LogAuditDriver;
use VendorShield\Shield\Audit\NullAuditDriver;
use VendorShield\Shield\Contracts\GuardContract;
use VendorShield\Shield\Contracts\PolicyLoaderContract;
use VendorShield\Shield\Contracts\TenantResolverContract;
use VendorShield\Shield\Contracts\LicenseManagerContract;
use VendorShield\Shield\Contracts\IntelligenceClientContract;
use VendorShield\Shield\Contracts\AuditDriverContract;
use VendorShield\Shield\Commands\InstallCommand;
use VendorShield\Shield\Commands\HealthCommand;
use VendorShield\Shield\Commands\BaselineCommand;
use VendorShield\Shield\Commands\RuntimeEnableCommand;
use VendorShield\Shield\Commands\ComplianceReportCommand;

class ShieldServiceProvider extends ServiceProvider
{
    /**
     * Register package bindings.
     */
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__ . '/../config/shield.php', 'shield');

        // Core — ConfigResolver (singleton)
        $this->app->singleton(ConfigResolver::class, function ($app) {
            return new ConfigResolver($app['config']);
        });

        // Core — ShieldManager (singleton)
        $this->app->singleton(ShieldManager::class, function ($app) {
            $manager = new ShieldManager($app, $app->make(ConfigResolver::class));
            $this->registerGuards($manager);
            return $manager;
        });

        $this->app->alias(ShieldManager::class, 'shield');

        // Tenant Context — scoped singleton (Octane-safe)
        $this->app->scoped(TenantContext::class, function () {
            return new TenantContext();
        });

        // Tenant Resolver
        $this->app->singleton(TenantResolverContract::class, function ($app) {
            $config = $app->make(ConfigResolver::class);
            $resolverClass = $config->guard('tenant', 'resolver');

            if ($resolverClass && class_exists($resolverClass)) {
                return $app->make($resolverClass);
            }

            return new HeaderTenantResolver($config);
        });

        // Audit Driver
        $this->app->singleton(AuditDriverContract::class, function ($app) {
            $config = $app->make(ConfigResolver::class);
            $driver = $config->get('audit.driver', 'database');

            return match ($driver) {
                'database' => new DatabaseAuditDriver($config),
                'log' => new LogAuditDriver($config->get('audit.channel')),
                'null' => new NullAuditDriver(),
                default => new DatabaseAuditDriver($config),
            };
        });

        // Audit Logger
        $this->app->singleton(AuditLogger::class, function ($app) {
            return new AuditLogger(
                $app->make(AuditDriverContract::class),
                $app->make(ConfigResolver::class),
            );
        });

        // Guards (scoped for Octane safety)
        $this->app->scoped(HttpGuard::class, function ($app) {
            return new HttpGuard(
                $app->make(ConfigResolver::class),
                $app->make(AuditLogger::class),
            );
        });

        $this->app->scoped(DatabaseGuard::class, function ($app) {
            return new DatabaseGuard(
                $app->make(ConfigResolver::class),
                $app->make(AuditLogger::class),
            );
        });

        $this->app->scoped(UploadGuard::class, function ($app) {
            $config = $app->make(ConfigResolver::class);
            $decodeDepth = $config->guard('upload', 'recursive_decode_depth', 5);

            $decoder = new RecursiveDecoder($decodeDepth);

            return new UploadGuard(
                $config,
                $app->make(AuditLogger::class),
                new FilenameCanonicalizer(),
                $decoder,
                new MagicByteValidator(),
                new PolyglotDetector(),
                new ContentScannerV2($decoder),
                new SafeStoragePolicy(),
                new StreamProcessor(),
                new ArchiveInspector(),
            );
        });

        $this->app->scoped(QueueGuard::class, function ($app) {
            return new QueueGuard(
                $app->make(ConfigResolver::class),
                $app->make(AuditLogger::class),
            );
        });

        $this->app->scoped(AuthGuard::class, function ($app) {
            return new AuthGuard(
                $app->make(ConfigResolver::class),
                $app->make(AuditLogger::class),
            );
        });

        $this->app->scoped(CacheGuard::class, function ($app) {
            return new CacheGuard(
                $app->make(ConfigResolver::class),
                $app->make(AuditLogger::class),
            );
        });

        $this->app->scoped(TenantGuard::class, function ($app) {
            return new TenantGuard(
                $app->make(ConfigResolver::class),
                $app->make(AuditLogger::class),
            );
        });

        // Policy Engine
        $this->app->singleton(PolicyLoaderContract::class, function ($app) {
            return new PolicyLoader(
                $app->make(ConfigResolver::class),
                $app->make(\Illuminate\Contracts\Cache\Repository::class),
            );
        });

        $this->app->singleton(PolicyEngine::class, function ($app) {
            return new PolicyEngine(
                $app->make(PolicyLoaderContract::class),
                $app->make(ConfigResolver::class),
            );
        });

        // Licensing
        $this->app->singleton(LicenseManagerContract::class, function ($app) {
            return new LicenseManager(
                $app->make(ConfigResolver::class),
                $app->make(\Illuminate\Contracts\Cache\Repository::class),
            );
        });

        $this->app->singleton(FeatureGate::class);

        // Intelligence Client
        $this->app->singleton(IntelligenceClientContract::class, function ($app) {
            $config = $app->make(ConfigResolver::class);

            if ($config->get('intelligence.enabled', false)) {
                return new IntelligenceClient($config);
            }

            return new NullIntelligenceClient();
        });

        // Runtime Hook Manager
        $this->app->singleton(RuntimeHookManager::class, function ($app) {
            return new RuntimeHookManager(
                $app,
                $app->make(ConfigResolver::class),
            );
        });
    }

    /**
     * Boot the package — register hooks AFTER Laravel bootstrap.
     */
    public function boot(): void
    {
        $this->publishConfig();
        $this->publishMigrations();
        $this->registerCommands();

        // Only boot runtime if Shield is enabled
        $config = $this->app->make(ConfigResolver::class);

        if (! $config->enabled()) {
            return;
        }

        // Boot runtime hooks — AFTER Laravel bootstrap
        $this->app->make(RuntimeHookManager::class)->boot();

        // Register Octane reset listener
        $this->registerOctaneResets();
    }

    /**
     * Register all guards with the ShieldManager.
     */
    protected function registerGuards(ShieldManager $manager): void
    {
        $guardMap = [
            'http' => HttpGuard::class,
            'database' => DatabaseGuard::class,
            'upload' => UploadGuard::class,
            'queue' => QueueGuard::class,
            'auth' => AuthGuard::class,
            'cache' => CacheGuard::class,
            'tenant' => TenantGuard::class,
        ];

        foreach ($guardMap as $name => $class) {
            $manager->registerLazyGuard($name, $class);
        }
    }

    /**
     * Publish config file.
     */
    protected function publishConfig(): void
    {
        $this->publishes([
            __DIR__ . '/../config/shield.php' => config_path('shield.php'),
        ], 'shield-config');
    }

    /**
     * Publish migrations.
     */
    protected function publishMigrations(): void
    {
        $this->publishes([
            __DIR__ . '/../database/migrations' => database_path('migrations'),
        ], 'shield-migrations');

        $this->loadMigrationsFrom(__DIR__ . '/../database/migrations');
    }

    /**
     * Register Artisan commands.
     */
    protected function registerCommands(): void
    {
        if ($this->app->runningInConsole()) {
            $this->commands([
                InstallCommand::class,
                HealthCommand::class,
                BaselineCommand::class,
                RuntimeEnableCommand::class,
                ComplianceReportCommand::class,
            ]);
        }
    }

    /**
     * Register Octane reset listeners for state cleanup.
     */
    protected function registerOctaneResets(): void
    {
        if (class_exists(\Laravel\Octane\Events\RequestReceived::class)) {
            $this->app['events']->listen(
                \Laravel\Octane\Events\RequestReceived::class,
                function () {
                    $this->app->make(ShieldManager::class)->reset();
                    $this->app->make(TenantContext::class)->clear();
                }
            );
        }
    }
}
