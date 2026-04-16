<?php

namespace VendorShield\Shield\Tests\Unit\Guards;

use VendorShield\Shield\Tests\TestCase;
use VendorShield\Shield\Guards\AuthGuard;
use VendorShield\Shield\Config\ConfigResolver;
use VendorShield\Shield\Audit\AuditLogger;
use VendorShield\Shield\Audit\NullAuditDriver;
use Illuminate\Support\Facades\Cache;

class AuthGuardTest extends TestCase
{
    protected AuthGuard $guard;

    protected function setUp(): void
    {
        parent::setUp();

        $this->app['config']->set('shield.guards.auth.enabled', true);
        $this->app['config']->set('shield.guards.auth.mode', 'enforce');
        $this->app['config']->set('shield.guards.auth.brute_force_threshold', 3);
        $this->app['config']->set('shield.guards.auth.brute_force_window', 300);

        $config = $this->app->make(ConfigResolver::class);
        $audit = new AuditLogger(new NullAuditDriver(), $config);
        $this->guard = new AuthGuard($config, $audit);

        Cache::flush();
    }

    public function test_clean_login_passes(): void
    {
        $context = [
            'event_type' => 'login',
            'ip' => '10.0.0.1',
            'user_id' => 1,
            'user_agent' => 'Mozilla/5.0',
        ];

        $result = $this->guard->handle($context);
        $this->assertTrue($result->passed);
    }

    public function test_brute_force_detected_after_threshold(): void
    {
        $context = [
            'event_type' => 'failed_login',
            'ip' => '192.168.1.100',
            'email' => 'attacker@example.com',
        ];

        // Attempts 1 and 2 should pass
        $this->assertTrue($this->guard->handle($context)->passed);
        $this->assertTrue($this->guard->handle($context)->passed);

        // Attempt 3 hits the threshold (set to 3)
        $result = $this->guard->handle($context);
        $this->assertFalse($result->passed);
        $this->assertStringContainsString('Brute force', $result->message);
    }

    public function test_brute_force_different_ips_tracked_separately(): void
    {
        $contextA = [
            'event_type' => 'failed_login',
            'ip' => '192.168.1.1',
        ];
        $contextB = [
            'event_type' => 'failed_login',
            'ip' => '192.168.1.2',
        ];

        $this->guard->handle($contextA);
        $this->guard->handle($contextA);
        $this->guard->handle($contextB);

        // IP A at 2 attempts — should still pass (threshold is 3)
        // But next attempt for A hits threshold
        $result = $this->guard->handle($contextA);
        $this->assertFalse($result->passed);

        // IP B at 2 attempts — should still pass
        $result = $this->guard->handle($contextB);
        $this->assertTrue($result->passed);
    }

    public function test_session_anomaly_user_agent_change_detected(): void
    {
        $this->app['config']->set('shield.guards.auth.session_anomaly', true);

        // First session check — stores the user agent
        $context = [
            'event_type' => 'session',
            'session_id' => 'sess_abc123',
            'user_agent' => 'Mozilla/5.0 Chrome',
        ];
        $result = $this->guard->handle($context);
        $this->assertTrue($result->passed);

        // Same session, different user agent — anomaly
        $context['user_agent'] = 'curl/7.68.0';
        $result = $this->guard->handle($context);
        $this->assertFalse($result->passed);
        $this->assertStringContainsString('Session anomaly', $result->message);
    }

    public function test_non_array_context_passes(): void
    {
        $result = $this->guard->handle('not_an_array');
        $this->assertTrue($result->passed);
    }

    public function test_unknown_event_type_passes(): void
    {
        $result = $this->guard->handle([
            'event_type' => 'password_reset',
            'ip' => '10.0.0.1',
        ]);
        $this->assertTrue($result->passed);
    }
}
