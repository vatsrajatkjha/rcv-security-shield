<?php

namespace VendorShield\Shield\Tests\Unit\Guards;

use VendorShield\Shield\Tests\TestCase;
use VendorShield\Shield\Guards\DatabaseGuard;
use VendorShield\Shield\Support\Severity;
use Illuminate\Database\Events\QueryExecuted;

class DatabaseGuardTest extends TestCase
{
    protected DatabaseGuard $guard;

    protected function setUp(): void
    {
        parent::setUp();
        $this->guard = $this->app->make(DatabaseGuard::class);
    }

    public function test_guard_name(): void
    {
        $this->assertEquals('database', $this->guard->name());
    }

    public function test_normal_query_passes(): void
    {
        $query = new QueryExecuted(
            'SELECT * FROM users WHERE id = ?',
            [1],
            1.0,
            $this->app['db']->connection(),
        );

        $result = $this->guard->handle($query);
        $this->assertTrue($result->passed);
    }

    public function test_union_injection_is_detected(): void
    {
        $query = new QueryExecuted(
            "SELECT * FROM users WHERE id = 1 UNION SELECT * FROM passwords",
            [],
            1.0,
            $this->app['db']->connection(),
        );

        $result = $this->guard->handle($query);
        $this->assertFalse($result->passed);
        $this->assertEquals(Severity::Critical, $result->severity);
    }

    public function test_drop_table_is_detected(): void
    {
        $query = new QueryExecuted(
            "DROP TABLE users",
            [],
            1.0,
            $this->app['db']->connection(),
        );

        $result = $this->guard->handle($query);
        $this->assertFalse($result->passed);
    }

    public function test_sleep_injection_is_detected(): void
    {
        $query = new QueryExecuted(
            "SELECT * FROM users WHERE id = 1 AND SLEEP(5)",
            [],
            1.0,
            $this->app['db']->connection(),
        );

        $result = $this->guard->handle($query);
        $this->assertFalse($result->passed);
    }

    public function test_non_query_context_passes(): void
    {
        $result = $this->guard->handle('not a query');
        $this->assertTrue($result->passed);
    }
}
