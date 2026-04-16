<?php

namespace VendorShield\Shield\Tests\Feature;

use Illuminate\Http\Request;
use Illuminate\Http\UploadedFile;
use VendorShield\Shield\Audit\AuditEntry;
use VendorShield\Shield\Audit\AuditLogger;
use VendorShield\Shield\Contracts\AuditDriverContract;
use VendorShield\Shield\Events\GuardTriggered;
use VendorShield\Shield\Http\Middleware\ShieldMiddleware;
use VendorShield\Shield\Tests\TestCase;

class MiddlewareIntegrationTest extends TestCase
{
    protected function defineRoutes($router): void
    {
        $router->middleware(ShieldMiddleware::class)
            ->group(function ($router) {
                $router->get('/shield-test', function () {
                    return response()->json(['status' => 'ok']);
                });

                $router->post('/shield-test', function (Request $request) {
                    return response()->json(['received' => $request->all()]);
                });

                $router->post('/shield-upload', function (Request $request) {
                    return response()->json([
                        'files' => array_keys($request->allFiles()),
                        'count' => count($request->allFiles(), COUNT_RECURSIVE),
                    ]);
                });
            });
    }

    public function test_clean_request_passes_through(): void
    {
        $response = $this->get('/shield-test', [
            'User-Agent' => 'Mozilla/5.0 Test',
        ]);

        $response->assertOk();
        $response->assertJson(['status' => 'ok']);
    }

    public function test_clean_post_passes_through(): void
    {
        $response = $this->post('/shield-test', [
            'name' => 'John Doe',
            'email' => 'john@example.com',
        ], [
            'User-Agent' => 'Mozilla/5.0 Test',
        ]);

        $response->assertOk();
    }

    public function test_sql_injection_in_enforce_mode_blocks(): void
    {
        $this->app['config']->set('shield.mode', 'enforce');
        $this->app['config']->set('shield.guards.http.mode', 'enforce');

        // Force the container to re-resolve scoped instances with updated config
        $this->app->forgetScopedInstances();

        $response = $this->withHeaders([
            'User-Agent' => 'Mozilla/5.0 Test',
            'Content-Type' => 'application/x-www-form-urlencoded',
        ])->post('/shield-test', [
            'search' => "1' UNION SELECT * FROM users--",
        ]);

        $response->assertStatus(403);
    }

    public function test_sql_injection_in_monitor_mode_passes(): void
    {
        $this->app['config']->set('shield.mode', 'monitor');

        $response = $this->post('/shield-test', [
            'search' => "1' UNION SELECT * FROM users--",
        ], [
            'User-Agent' => 'Mozilla/5.0 Test',
        ]);

        // Monitor mode — log but allow
        $response->assertOk();
    }

    public function test_disabled_shield_passes_everything(): void
    {
        $this->app['config']->set('shield.enabled', false);

        $response = $this->post('/shield-test', [
            'search' => "'; DROP TABLE users; --",
        ]);

        $response->assertOk();
    }

    public function test_upload_is_blocked_when_http_guard_is_disabled(): void
    {
        $this->app['config']->set('shield.guards.http.enabled', false);
        $this->app['config']->set('shield.guards.upload.enabled', true);
        $this->app['config']->set('shield.guards.upload.mode', 'enforce');
        $this->app->forgetScopedInstances();

        $file = UploadedFile::fake()->create('malicious.php.jpg', 10, 'image/jpeg');

        $response = $this->withHeaders([
            'User-Agent' => 'Mozilla/5.0 Test',
        ])->post('/shield-upload', [
            'avatar' => $file,
        ]);

        $response->assertStatus(422);
    }

    public function test_nested_uploaded_files_are_recursively_scanned(): void
    {
        $this->app['config']->set('shield.guards.upload.mode', 'enforce');
        $this->app->forgetScopedInstances();

        $response = $this->withHeaders([
            'User-Agent' => 'Mozilla/5.0 Test',
        ])->post('/shield-upload', [
            'documents' => [
                'identity' => [
                    UploadedFile::fake()->create('resume.php.jpg', 10, 'image/jpeg'),
                ],
            ],
        ]);

        $response->assertStatus(422);
    }

    public function test_upload_rate_limit_returns_429(): void
    {
        $this->app['config']->set('shield.guards.upload.rate_limit.max_attempts', 2);
        $this->app['config']->set('shield.guards.upload.rate_limit.decay_seconds', 60);
        $this->app->forgetScopedInstances();

        $headers = ['User-Agent' => 'Mozilla/5.0 Test'];

        $this->withHeaders($headers)->post('/shield-upload', [
            'avatar' => UploadedFile::fake()->image('one.jpg'),
        ])->assertOk();

        $this->withHeaders($headers)->post('/shield-upload', [
            'avatar' => UploadedFile::fake()->image('two.jpg'),
        ])->assertOk();

        $this->withHeaders($headers)->post('/shield-upload', [
            'avatar' => UploadedFile::fake()->image('three.jpg'),
        ])->assertStatus(429);
    }

    public function test_guard_event_listener_exception_does_not_break_request(): void
    {
        $this->app['config']->set('shield.mode', 'monitor');
        $this->app['config']->set('shield.guards.http.mode', 'monitor');
        $this->app['events']->listen(GuardTriggered::class, function (): void {
            throw new \RuntimeException('listener failed');
        });

        $response = $this->withHeaders([
            'User-Agent' => 'Mozilla/5.0 Test',
            'Content-Type' => 'application/x-www-form-urlencoded',
        ])->post('/shield-test', [
            'search' => "1' UNION SELECT * FROM users--",
        ]);

        $response->assertOk();
    }

    public function test_audit_driver_exception_does_not_break_request(): void
    {
        $this->app->bind(AuditDriverContract::class, function () {
            return new class implements AuditDriverContract
            {
                public function log(AuditEntry $entry): void
                {
                    throw new \RuntimeException('audit failed');
                }

                public function query(array $filters = []): array
                {
                    return [];
                }

                public function prune(int $days): int
                {
                    return 0;
                }
            };
        });
        $this->app->forgetInstance(AuditLogger::class);
        $this->app->forgetScopedInstances();

        $response = $this->withHeaders([
            'User-Agent' => 'Mozilla/5.0 Test',
            'Content-Type' => 'application/x-www-form-urlencoded',
        ])->post('/shield-test', [
            'search' => "1' UNION SELECT * FROM users--",
        ]);

        $response->assertOk();
    }
}
