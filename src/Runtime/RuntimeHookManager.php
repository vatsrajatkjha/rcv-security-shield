<?php

namespace VendorShield\Shield\Runtime;

use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\Facades\DB;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Queue\Events\JobProcessing;
use Illuminate\Queue\Events\JobProcessed;
use Illuminate\Queue\Events\JobFailed;
use VendorShield\Shield\Config\ConfigResolver;
use VendorShield\Shield\Guards\DatabaseGuard;
use VendorShield\Shield\Guards\QueueGuard;
use VendorShield\Shield\Guards\ExceptionGuard;
use VendorShield\Shield\Guards\HttpGuard;
use VendorShield\Shield\Http\Middleware\ShieldMiddleware;

class RuntimeHookManager
{
    protected bool $booted = false;

    public function __construct(
        protected Application $app,
        protected ConfigResolver $config,
    ) {}

    /**
     * Register all runtime hooks based on configuration.
     * Called during service provider boot() — AFTER Laravel bootstrap.
     */
    public function boot(): void
    {
        if ($this->booted || ! $this->config->enabled()) {
            return;
        }

        $this->registerHttpHooks();
        $this->registerDatabaseHooks();
        $this->registerQueueHooks();
        $this->registerExceptionHooks();

        $this->booted = true;
    }

    /**
     * Register HTTP middleware injection.
     */
    protected function registerHttpHooks(): void
    {
        if (
            ! $this->config->guardEnabled('http')
            && ! $this->config->guardEnabled('upload')
            && ! $this->config->guardEnabled('tenant')
        ) {
            return;
        }

        $router = $this->app['router'];
        $groups = $this->config->guard('http', 'middleware_groups', ['web', 'api']);

        foreach ($groups as $group) {
            $router->prependMiddlewareToGroup($group, ShieldMiddleware::class);
        }
    }

    /**
     * Register database query listener.
     */
    protected function registerDatabaseHooks(): void
    {
        if (! $this->config->guardEnabled('database')) {
            return;
        }

        $scanning = false;

        DB::listen(function (QueryExecuted $query) use (&$scanning) {
            // Re-entrancy guard: skip if we're already inside a guard scan
            // (e.g., DatabaseAuditDriver INSERT triggers DB::listen again)
            if ($scanning) {
                return;
            }

            // Skip Shield's own audit/threat log queries
            if (str_starts_with($query->sql, 'insert into `shield_')
                || str_starts_with($query->sql, 'select * from `shield_')
                || str_starts_with($query->sql, 'delete from `shield_')) {
                return;
            }

            $guard = $this->app->make(DatabaseGuard::class);

            if ($guard->enabled()) {
                $scanning = true;
                try {
                    $guard->handle($query);
                } finally {
                    $scanning = false;
                }
            }
        });
    }

    /**
     * Register queue event listeners.
     */
    protected function registerQueueHooks(): void
    {
        if (! $this->config->guardEnabled('queue')) {
            return;
        }

        $events = $this->app['events'];

        $events->listen(JobProcessing::class, function (JobProcessing $event) {
            $guard = $this->app->make(QueueGuard::class);

            if ($guard->enabled()) {
                $guard->handle($event);
            }
        });

        $events->listen(JobFailed::class, function (JobFailed $event) {
            $guard = $this->app->make(QueueGuard::class);

            if ($guard->enabled()) {
                $guard->handleFailed($event);
            }
        });
    }

    /**
     * Register exception handler decorator.
     */
    protected function registerExceptionHooks(): void
    {
        if (! $this->config->guardEnabled('exception')) {
            return;
        }

        // Decorate the exception handler — contracts-only approach
        $this->app->extend(
            \Illuminate\Contracts\Debug\ExceptionHandler::class,
            function ($handler, $app) {
                return new ExceptionGuard($handler, $app->make(ConfigResolver::class), $app);
            }
        );
    }

    /**
     * Check if the hook manager has been booted.
     */
    public function isBooted(): bool
    {
        return $this->booted;
    }

    /**
     * Reset for Octane worker reuse.
     */
    public function reset(): void
    {
        // Hooks remain registered — only per-request state resets
    }
}
