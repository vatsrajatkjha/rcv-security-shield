<?php

namespace VendorShield\Shield\Tests\Unit\Guards;

use Illuminate\Http\Request;
use VendorShield\Shield\Guards\HttpGuard;
use VendorShield\Shield\Support\Severity;
use VendorShield\Shield\Tests\TestCase;

class HttpGuardTest extends TestCase
{
    protected HttpGuard $guard;

    protected function setUp(): void
    {
        parent::setUp();
        $this->app['config']->set('shield.guards.http.mode', 'enforce');
        $this->guard = $this->app->make(HttpGuard::class);
    }

    public function test_guard_name(): void
    {
        $this->assertEquals('http', $this->guard->name());
    }

    public function test_guard_is_enabled_by_default(): void
    {
        $this->assertTrue($this->guard->enabled());
    }

    public function test_clean_request_passes(): void
    {
        $request = Request::create('/test', 'GET');
        $request->headers->set('User-Agent', 'Mozilla/5.0 Test');

        $result = $this->guard->handle($request);

        $this->assertTrue($result->passed);
    }

    public function test_sql_injection_is_detected(): void
    {
        $request = Request::create('/test', 'POST', [
            'search' => "1' UNION SELECT * FROM users--",
        ]);
        $request->headers->set('User-Agent', 'Mozilla/5.0 Test');
        $request->headers->set('Content-Type', 'application/x-www-form-urlencoded');

        $result = $this->guard->handle($request);

        $this->assertFalse($result->passed);
        $this->assertEquals(Severity::Critical, $result->severity);
        $this->assertStringContainsString('sql_injection', $result->metadata['pattern_type'] ?? '');
    }

    public function test_xss_is_detected(): void
    {
        $request = Request::create('/test', 'POST', [
            'comment' => '<script>alert("xss")</script>',
        ]);
        $request->headers->set('User-Agent', 'Mozilla/5.0 Test');
        $request->headers->set('Content-Type', 'application/x-www-form-urlencoded');

        $result = $this->guard->handle($request);

        $this->assertFalse($result->passed);
        $this->assertStringContainsString('xss', $result->metadata['pattern_type'] ?? '');
    }

    public function test_path_traversal_is_detected(): void
    {
        $request = Request::create('/test', 'GET', [
            'file' => '../../etc/passwd',
        ]);
        $request->headers->set('User-Agent', 'Mozilla/5.0 Test');

        $result = $this->guard->handle($request);

        $this->assertFalse($result->passed);
        $this->assertStringContainsString('path_traversal', $result->metadata['pattern_type'] ?? '');
    }

    public function test_missing_user_agent_is_flagged(): void
    {
        $request = Request::create('/test', 'GET');
        // Request::create sets User-Agent to 'Symfony' by default, remove it
        $request->headers->remove('User-Agent');
        $request->server->remove('HTTP_USER_AGENT');

        $result = $this->guard->handle($request);

        $this->assertFalse($result->passed);
        $this->assertStringContainsString('User-Agent', $result->message);
    }

    public function test_oversized_payload_is_rejected(): void
    {
        $request = Request::create('/test', 'POST');
        $request->headers->set('User-Agent', 'Mozilla/5.0 Test');
        $request->headers->set('Content-Type', 'application/json');
        $request->headers->set('Content-Length', '999999999');

        $result = $this->guard->handle($request);

        $this->assertFalse($result->passed);
        $this->assertStringContainsString('payload', $result->message);
    }

    public function test_non_request_context_passes(): void
    {
        $result = $this->guard->handle('not a request');

        $this->assertTrue($result->passed);
    }

    public function test_guard_respects_disabled_config(): void
    {
        $this->app['config']->set('shield.guards.http.enabled', false);

        $guard = $this->app->make(HttpGuard::class);
        $this->assertFalse($guard->enabled());
    }
}
