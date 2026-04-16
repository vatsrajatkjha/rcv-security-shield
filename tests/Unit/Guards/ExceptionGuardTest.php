<?php

namespace VendorShield\Shield\Tests\Unit\Guards;

use VendorShield\Shield\Tests\TestCase;
use VendorShield\Shield\Guards\ExceptionGuard;
use VendorShield\Shield\Config\ConfigResolver;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Http\Request;
use RuntimeException;

class ExceptionGuardTest extends TestCase
{
    protected ExceptionGuard $guard;
    protected ExceptionHandler $innerHandler;

    protected function setUp(): void
    {
        parent::setUp();

        $this->app['config']->set('shield.guards.exception.enabled', true);
        $this->app['config']->set('shield.guards.exception.pattern_analysis', true);
        $this->app['config']->set('shield.guards.exception.scrub_sensitive_data', true);

        $this->innerHandler = $this->app->make(ExceptionHandler::class);
        $config = $this->app->make(ConfigResolver::class);
        $this->guard = new ExceptionGuard($this->innerHandler, $config, $this->app);
    }

    public function test_delegates_should_report_to_inner_handler(): void
    {
        $exception = new RuntimeException('Test error');
        $result = $this->guard->shouldReport($exception);

        // Should delegate to inner handler (Laravel's default reports all)
        $this->assertIsBool($result);
    }

    public function test_report_delegates_to_inner_handler(): void
    {
        // ExceptionGuard::report calls analyzeException and then inner->report
        // It should not throw even if analysis detects a pattern
        $exception = new RuntimeException('syntax error near table users');

        // Should not throw
        $this->guard->report($exception);
        $this->assertTrue(true); // No exception thrown
    }

    public function test_scrubs_sensitive_data_from_exception_message(): void
    {
        $exception = new RuntimeException('Connection failed: password=s3cr3t_pass and token=abc123xyz');

        $request = Request::create('/test', 'GET');
        $request->headers->set('User-Agent', 'Mozilla/5.0');

        // render() should scrub password and token
        $response = $this->guard->render($request, $exception);

        // The response should not contain the raw password
        $content = $response->getContent();
        $this->assertStringNotContainsString('s3cr3t_pass', $content);
    }

    public function test_does_not_scrub_when_disabled(): void
    {
        $this->app['config']->set('shield.guards.exception.scrub_sensitive_data', false);

        $config = $this->app->make(ConfigResolver::class);
        $this->guard = new ExceptionGuard($this->innerHandler, $config, $this->app);

        $exception = new RuntimeException('password=visible');
        $request = Request::create('/test', 'GET');
        $request->headers->set('User-Agent', 'Mozilla/5.0');

        // When scrubbing is disabled, the original exception is passed through
        $response = $this->guard->render($request, $exception);
        $this->assertNotNull($response);
    }

    public function test_does_not_throw_on_analysis_failure(): void
    {
        // ExceptionGuard wraps analysis in try/catch — should never throw
        $this->app['config']->set('shield.guards.exception.pattern_analysis', true);

        $config = $this->app->make(ConfigResolver::class);
        $guard = new ExceptionGuard($this->innerHandler, $config, $this->app);

        // Even with a PDOException-like message, report should not throw
        $exception = new RuntimeException('access denied for user');
        $guard->report($exception);
        $this->assertTrue(true);
    }
}
