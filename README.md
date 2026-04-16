<p align="center">
  <strong>Laravel Shield</strong>
</p>

<p align="center">
  Enterprise Runtime Application Security Platform for Laravel
</p>

<p align="center">
  <em>Post-bootstrap security fabric — extends Laravel through contracts, never overrides it.</em>
</p>

<p align="center">
  <a href="#installation">Install</a> · <a href="#architecture-overview">Architecture</a> · <a href="#configuration-system">Configure</a> · <a href="#runtime-protection-coverage">Protection</a> · <a href="#testing">Testing</a> · <a href="#enterprise-deployment">Deploy</a> · <a href="#commercial-licensing">License</a>
</p>

---

## Why This Exists

Modern SaaS platforms face a runtime attack surface that input validation alone cannot address. SQL injection, file upload weaponization, tenant boundary violations, queue payload manipulation, and cache poisoning all occur *after* validation — during execution.

Traditional approaches fall short:

- **Validation-layer security** catches malformed input but cannot detect runtime exploitation patterns such as time-based SQL injection, MIME spoofing, or deserialization attacks embedded in queue payloads.
- **WAF/CDN-level protection** operates without application context — it cannot enforce tenant isolation, inspect authenticated sessions, or correlate query patterns to business logic.
- **Kernel-level interception** breaks upgrade paths, couples security to framework internals, and introduces fragile failure modes in production.

Laravel Shield addresses this gap. It provides a runtime security layer that operates *inside* the Laravel container, *after* bootstrap, with full access to authentication, configuration, database connections, and tenant context — without modifying a single line of application code.

The system is designed for engineering teams operating at scale: multi-tenant SaaS, distributed queue architectures, Octane deployments, and environments subject to SOC 2, ISO 27001, or GDPR compliance requirements.

---

## Core Capabilities

| Capability | Status | Current Scope |
|---|---|---|
| **Runtime SQL Protection** | Implemented and tested | Query inspection via `DB::listen()` for common injection, raw query, slow query, and tenant-scope anomalies |
| **Upload Inspection Pipeline** | Implemented and tested | Strict extension allowlist, client/server MIME comparison, magic-byte validation, content scanning, polyglot detection, archive blocking by default, synchronous ZIP inspection when archives are allowed |
| **Tenant Boundary Enforcement** | Implemented and tested | Request-scoped tenant context plus basic cross-tenant and missing-tenant detection |
| **HTTP Request Scoring** | Implemented and tested | Bounded payload/header checks for common injection and traversal patterns |
| **Queue Security** | Implemented and tested | Job allow/block lists, payload size checks, serialized-object detection, failed-job monitoring |
| **Auth Anomaly Detection** | Implemented and tested | Brute-force counters, IP-change heuristics, session User-Agent anomaly detection |
| **Exception Intelligence** | Implemented and tested | Exception classification and sensitive-data scrubbing through exception handler decoration |
| **Cache Guard** | Implemented and tested | Cache key validation, serialized-object detection, and size anomaly checks |
| **Async Deep Inspection** | Implemented but limited | Best-effort async enrichment for HTTP and upload findings; not a substitute for external AV/CDR infrastructure |
| **Fail-Open Safety** | Implemented and tested | Middleware and guard side effects are wrapped so logging, events, and enrichment failures degrade safely |
| **Lazy Guard Resolution** | Implemented | Guards resolve from the container on demand |
| **Policy Engine** | Implemented but limited | Config-driven policy evaluation exists, but policy authoring and distribution remain application-owned |
| **Compliance Reporting** | Experimental | Reports summarize Shield configuration and audit evidence; they are not a complete certification or control automation system |
| **Observability** | Implemented | Structured audit events with database/log/null drivers |

---

## Architecture Overview

### Runtime Placement

```
Infrastructure Layer (CDN / WAF / Load Balancer)
        │
        ▼
  Laravel Bootstrap
        │
        ▼
  ShieldServiceProvider (Auto-Discovered)
        │
        ├── RuntimeHookManager
        │     ├── Middleware Injection (web, api groups)
        │     ├── DB::listen() with Re-Entrancy Guard
        │     ├── Queue Event Subscription
        │     └── ExceptionHandler Decoration
        │
        ├── ConfigResolver (Global → Env → Tenant → Runtime)
        │
        ├── PolicyEngine
        │
        └── Lazy Guard Registry
              ├── HttpGuard     (resolved on first HTTP request)
              ├── DatabaseGuard (resolved on first query event)
              ├── UploadGuard   (resolved on first file upload)
              ├── QueueGuard    (resolved on first job event)
              ├── AuthGuard     (resolved on first auth event)
              ├── CacheGuard    (resolved on first cache operation)
              ├── TenantGuard   (resolved on first tenant check)
              └── ExceptionGuard (resolved on first exception)
        │
        ▼
  Application Code (Unmodified)
```

### HTTP Request Lifecycle

```
Incoming Request
    │
    ▼
┌─────────────────────────────────────────┐
│  ShieldMiddleware (fail-open wrapper)   │
│  ├─ Tenant Resolution                  │
│  ├─ HttpGuard (fast-path <1ms)         │
│  │   ├─ Payload Size Check             │
│  │   ├─ Header Anomaly Scan            │
│  │   └─ Bounded Input Pattern Scoring  │
│  ├─ UploadGuard (if files present)     │
│  │   ├─ Extension + Filename Validation│
│  │   ├─ MIME + Magic Bytes Verify      │
│  │   ├─ Content Scan (configurable KB) │
│  │   └─ SVG/PS/EICAR Pattern Detection │
│  ├─ Async Dispatch (non-blocking)      │
│  └─ try/catch Fail-Open Safety         │
└─────────────────────────────────────────┘
    │
    ▼
Application Controller
    │
    ▼
┌─────────────────────────────────────────┐
│  DB::listen() → DatabaseGuard          │
│  ├─ Context-Aware SQL Injection Detect  │
│  ├─ Raw Query Detection                │
│  ├─ Slow Query Flagging                │
│  ├─ Tenant Boundary Check              │
│  └─ Re-Entrancy Protection             │
└─────────────────────────────────────────┘
    │
    ▼
Response
```

### Why Post-Bootstrap Placement Is Non-Negotiable

Pre-bootstrap interception — overriding the HTTP Kernel, manipulating the request before container initialization, or injecting custom bootstrap scripts — creates three critical failure modes:

1. **Upgrade fragility.** Laravel's bootstrap sequence changes between major versions. Any package that depends on boot order will break silently.
2. **Missing context.** Before bootstrap, there is no service container, no config repository, no database connection, no authentication state. Security decisions made without this context are guesses.
3. **State corruption.** Packages that manipulate the request pipeline before Laravel initializes it risk leaving the container in an inconsistent state — causing failures in unrelated application code.

Shield operates exclusively through Laravel's documented extension points: Service Providers, Contracts, Events, and Middleware registration. This guarantees that removal of the package cannot corrupt application state.

---

## Design Principles

| Principle | Implementation |
|---|---|
| **Framework-first** | All integration via Service Providers, Contracts, and Events. Zero monkey-patching. |
| **Upgrade-safe** | No Kernel override, no bootstrap manipulation, no internal class extension. Survives `composer update laravel/framework` without intervention. |
| **Zero core override** | The `ExceptionHandler` is decorated via `$app->extend()`, not replaced. Router middleware is prepended, not injected. DB monitoring uses the public `DB::listen()` API. |
| **Fail-open by design** | The middleware wraps all guard execution in a top-level `try/catch`. All `event()` dispatches are exception-safe. Audit driver failures are swallowed. A Shield bug can never become an application outage. |
| **Async-first deep analysis** | Synchronous path limited to <1ms. Heavy inspection (scanner detection, hash lookups, behavioral analysis, Zip Slip, archive bombs) dispatched to queue workers. |
| **Bounded resource usage** | Input scanning limited to 5 levels of nesting and 64KB total. Content scanning configurable via `content_scan_bytes`. No unbounded memory allocation. |
| **Observability-first** | Every guard decision emits a structured event. Audit logging is built in — not bolted on. |
| **Container-driven** | Every component is resolved through the service container. Lazy construction via `registerLazyGuard()`. Scoped singletons for Octane safety. No static state. |
| **Re-entrancy safe** | The `DB::listen()` callback includes a re-entrancy flag and filters Shield's own audit table queries, preventing infinite recursion when using the database audit driver. |
| **CLI & queue safe** | No guard or subsystem calls `request()` or assumes an HTTP context. License validation, audit logging, and exception analysis all work correctly in artisan and queue contexts. |
| **Safe removal** | `composer remove` leaves zero side effects. No migrations to roll back. No config to clean. No application code references to update. |

---

## Installation

### Requirements

| Requirement | Version |
|---|---|
| PHP | 8.2+ |
| Laravel | 11.x, 12.x |

### Install via Composer

```bash
composer require vendor-shield/laravel-shield
```

### Run the Installer

```bash
php artisan shield:install
```

The installer performs:

- Publishes `config/shield.php` with documented, secure defaults
- Runs database migrations (`shield_audit_logs`, `shield_threat_logs`)
- Creates quarantine and scanned file directories in `storage/app/shield/`
- Writes `.gitignore` to quarantine directory

No manual Kernel modification. No middleware registration. No bootstrap file changes.

### Verify Installation

```bash
php artisan shield:health
```

Reports status of all guards, license validation, database connectivity, intelligence availability, and storage directory permissions.

---

## Integration Modes

### Existing Laravel Application

```bash
composer require vendor-shield/laravel-shield
php artisan shield:install
```

Shield auto-discovers its service provider and begins monitoring immediately. Default mode is `monitor` — all threats are logged but no requests are blocked.

### New Application

```bash
laravel new my-app
cd my-app
composer require vendor-shield/laravel-shield
php artisan shield:install
php artisan shield:baseline
```

The baseline command generates a security snapshot of the environment configuration for future comparison.

### Multi-Tenant SaaS

```php
// config/shield.php
'guards' => [
    'tenant' => [
        'enabled' => true,
        'resolver' => \App\Security\TenantResolver::class,
        'isolation_level' => 'strict', // 'strict' or 'permissive'
    ],
],
```

Implement `TenantResolverContract` to integrate with your tenancy system. Shield enforces tenant boundaries at the query, upload, cache, and policy layers.

```php
use VendorShield\Shield\Contracts\TenantResolverContract;
use Illuminate\Http\Request;

class TenantResolver implements TenantResolverContract
{
    public function resolve(Request $request): ?string
    {
        return $request->header('X-Tenant-ID')
            ?? $request->user()?->tenant_id;
    }

    public function resolveFromContext(array $context = []): ?string
    {
        return $context['tenant_id'] ?? null;
    }
}
```

### API Platform

Shield attaches to both `web` and `api` middleware groups by default. For API-only deployments:

```php
'guards' => [
    'http' => [
        'middleware_groups' => ['api'],
    ],
],
```

### Queue Workers

Queue protection activates automatically when `guards.queue.enabled` is `true`. Shield monitors `JobProcessing` and `JobFailed` events natively — no worker configuration changes required.

### Octane Compatibility

All guards use scoped singletons and lazy resolution. Tenant context, config overrides, and per-request state reset automatically via Octane's `RequestReceived` event listener. No memory leaks. No cross-request state bleed.

---

## Configuration System

Published to `config/shield.php`. All values support `.env` overrides.

### Global Controls

```php
'enabled' => env('SHIELD_ENABLED', true),
'mode'    => env('SHIELD_MODE', 'monitor'),  // enforce | monitor | learning | disabled
```

### Per-Guard Configuration

Each guard supports independent enable/disable and mode override:

```php
'guards' => [
    'http' => [
        'enabled' => env('SHIELD_HTTP_ENABLED', true),
        'mode'    => env('SHIELD_HTTP_MODE', null),  // null inherits global mode
        'max_payload_size' => 10485760, // 10MB
        'header_anomaly_detection' => true,
        'request_scoring' => true,
    ],
    'database' => [
        'enabled'                => env('SHIELD_DB_ENABLED', true),
        'detect_sql_injection'   => true,
        'detect_raw_queries'     => true,
        'slow_query_threshold_ms'=> 5000,
        'max_query_length'       => 10000,
        'tenant_boundary_check'  => true,
    ],
    'upload' => [
        'enabled'            => env('SHIELD_UPLOAD_ENABLED', true),
        'max_file_size'      => 10485760, // 10MB
        'max_filename_length'=> 120,
        'allowed_extensions' => ['jpg', 'jpeg', 'png', 'gif', 'webp', 'pdf', 'txt', 'csv', 'doc', 'docx', 'xls', 'xlsx', 'zip', 'gz', 'tar', 'tgz', 'bz2', 'rar', '7z'],
        'content_scan_bytes' => env('SHIELD_UPLOAD_SCAN_BYTES', 8192),
        'compare_client_mime'=> true,
        'block_archives'     => true,
        'archive_max_entries'=> 500,
        'archive_max_uncompressed_bytes' => 104857600,
        'allowed_mimes' => [
            'image/jpeg', 'image/png', 'image/gif',
            'application/pdf',
            'text/plain', 'text/csv',
            'application/msword',
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            'application/vnd.ms-excel',
            'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            'application/zip',
            'application/gzip',
            'application/x-tar',
        ],
        'rate_limit' => [
            'enabled' => true,
            'max_attempts' => 10,
            'decay_seconds' => 60,
        ],
    ],
    'auth' => [
        'enabled'                => env('SHIELD_AUTH_ENABLED', true),
        'brute_force_threshold'  => 5,
        'brute_force_window'     => 300, // seconds
        'impossible_travel'      => true,
        'session_anomaly'        => true,
    ],
    'queue' => [
        'enabled'            => env('SHIELD_QUEUE_ENABLED', true),
        'payload_inspection' => true,
        'job_whitelist'      => [],
        'job_blacklist'      => [],
    ],
    'cache' => [
        'enabled'                  => env('SHIELD_CACHE_ENABLED', true),
        'key_pattern_validation'   => true,
        'serialization_check'      => true,
        'size_anomaly_threshold'   => 1048576, // 1MB
    ],
    'tenant' => [
        'enabled'         => env('SHIELD_TENANT_ENABLED', false),
        'isolation_level' => 'strict',
        'header'          => 'X-Tenant-ID',
    ],
],
```

### Enforcement Modes

| Mode | Behavior |
|---|---|
| `enforce` | Threats are blocked. HTTP returns 403. Jobs are rejected. Queries are flagged. |
| `monitor` | Threats are logged and events dispatched. No blocking. Production-safe default. |
| `learning` | All activity is recorded for baseline generation. No enforcement. |
| `disabled` | Guard is completely inactive. Zero overhead. |

### Configuration Layering

Resolution order (highest priority first):

```
Runtime Override  →  Tenant Config  →  Environment (.env)  →  Global (config/shield.php)
```

Runtime overrides via API:

```php
Shield::config()->override('mode', 'enforce');
Shield::config()->setTenant('tenant-123');
```

### Upload Security: SVG Exclusion

SVG files (`image/svg+xml`) are **excluded from the default allowed MIME types** because they can serve as vectors for XXE injection, XSS, and SSRF attacks. If your application requires SVG uploads, add the MIME type explicitly and ensure the UploadGuard's content scanner is active:

```php
'upload' => [
    'allowed_mimes' => [
        // ... your types
        'image/svg+xml', // Only if you understand the risk
    ],
],
```

The UploadGuard automatically scans SVG content for `<!ENTITY`, `<!DOCTYPE SYSTEM`, and `xlink:href` pointing to external URLs.

---

## Runtime Protection Coverage

### HTTP Layer — `HttpGuard`

The `HttpGuard` executes synchronous fast-path validation on every request:

- **Payload size enforcement** — rejects requests exceeding configurable size limits
- **Header anomaly detection** — flags missing User-Agent, Content-Type mismatches, POST-without-Content-Type
- **Bounded input pattern scoring** — scans all input (max 5 depth levels, 64KB cap) against 13 SQL injection, 9 XSS, 5 path traversal, and 4 command injection patterns
- **Null byte detection** — catches injection attempts via `%00` and `\0`
- **Async deep inspection dispatch** — scanner fingerprinting, sensitive file probing (`.env`, `.git`, `.sql`)

### Database Layer — `DatabaseGuard`

The `DatabaseGuard` monitors all queries via `DB::listen()` with re-entrancy protection:

- **Context-aware injection detection** — UNION-based, time-based blind (`SLEEP`, `BENCHMARK`, `WAITFOR DELAY`), destructive statements, `INFORMATION_SCHEMA` probes. Patterns are tuned to avoid false positives on ORM-generated queries (`CONCAT()`, `CHAR()`, `SUBSTRING()` are only flagged when combined with injection context).
- **Re-entrancy guard** — prevents infinite recursion when using the `database` audit driver (Shield's own audit INSERT queries are automatically filtered from `DB::listen()`)
- **Raw query identification** — queries without parameter bindings that contain inline user input
- **Slow query detection** — configurable threshold (default 5000ms)
- **Tenant scope enforcement** — flags `UPDATE` and `DELETE` statements that lack `tenant_id` in their WHERE clause

### Filesystem Layer — `UploadGuard`

The `UploadGuard` validates every uploaded file through a multi-stage pipeline:

1. **Filename structure validation** — null bytes, path traversal (`../`), double extensions (`.php.jpg`), RTLO, URL-encoded newlines (`%0a`, `%0d`), Windows ADS (`file.php::$DATA`), trailing dots/spaces, hidden dotfiles, overlong names
2. **Extension allowlist first** — only explicitly allowed extensions are accepted; executable/script blocklists remain defense-in-depth
3. **File size enforcement** — configurable per-file limit
4. **MIME signal comparison** — compares extension, client-declared MIME, and server-detected MIME; mismatches are rejected in `enforce`
5. **Magic byte verification** — actual file signature must match the detected type and the allowed extension family
6. **Polyglot detection** — rejects files that present mixed binary/script characteristics
7. **Archive handling** — archives are blocked by default. If enabled, ZIP files are synchronously checked for Zip Slip, excessive entries, and decompression-budget abuse before acceptance
8. **Content scanning** — configurable scan size against high-risk patterns including:
   - PHP tags: `<?php`, `<?=`, `<%`
   - Script injection: `<script`, `__HALT_COMPILER`
   - ImageTragick CVE: `push graphic-context`, `fill 'url(`
   - FFmpeg HLS CVE: `#EXTM3U`
   - Ghostscript/PostScript: `%!PS`, `%pipe%`
   - EICAR AV test signature
   - SVG XXE: `<!ENTITY`, `<!DOCTYPE SYSTEM`
   - SVG SSRF: `xlink:href` to external URLs
9. **Async deep inspection** — best-effort enrichment only; request-path security decisions happen synchronously

### Queue Layer — `QueueGuard`

The `QueueGuard` monitors job lifecycle events:

- **Job class whitelist/blacklist enforcement** — configure allowed or blocked job classes
- **Payload size limits** — flags payloads exceeding 1MB
- **Serialized object detection** — catches `O:\d+:"ClassName"` patterns in payloads (deserialization attack prevention)
- **Failed job pattern analysis** — escalating severity as failure count increases

### Auth Layer — `AuthGuard`

The `AuthGuard` detects authentication anomalies:

- **Brute force detection** — atomic counter via `Cache::increment()` (race-condition safe under concurrent load), configurable threshold and window
- **Impossible travel detection** — flags logins from different IPs within 5 minutes
- **Session anomaly detection** — detects User-Agent changes within the same session (session hijack indicator)

### Cache Layer — `CacheGuard`

The `CacheGuard` protects against cache poisoning:

- **Key pattern validation** — detects path traversal (`../`) and null bytes in cache keys, enforces 250-char key limit
- **Serialization attack detection** — flags PHP serialized objects (`O:\d+:`) in cache values
- **Size anomaly monitoring** — configurable threshold (default 1MB)

### Tenant Layer — `TenantGuard`

The `TenantGuard` enforces data isolation:

- **Cross-tenant access detection** — flags operations where `resource_tenant_id !== current_tenant_id`
- **Strict isolation mode** — rejects requests with no tenant context
- **Pluggable resolution** — header-based default (`X-Tenant-ID`), replaceable via `TenantResolverContract`

### Exception Layer — `ExceptionGuard`

The `ExceptionGuard` decorates Laravel's exception handler:

- **Exception classification** — categorizes exceptions as `sql_anomaly`, `auth_failure`, `filesystem_anomaly`, or `deserialization_risk`
- **Sensitive data scrubbing** — automatically redacts `password`, `secret`, `token`, `api_key`, `authorization` values from exception messages before rendering
- **Fail-safe design** — analysis wrapped in `try/catch`; never causes cascading exceptions

### CLI & Scheduler

Shield guards remain active in Artisan commands and scheduled tasks. Database monitoring, exception intelligence, and audit logging operate identically across HTTP, CLI, and queue contexts. No guard or subsystem assumes an HTTP request exists.

---

## Fail-Open Safety Model

Shield is engineered so that its own failures can never crash the host application:

| Layer | Safety Mechanism |
|---|---|
| **ShieldMiddleware** | Entire guard execution wrapped in top-level `try/catch(\Throwable)` with `Log::warning()` fallback |
| **Event dispatches** | All `event()` calls in every guard wrapped in `try/catch` — listener exceptions cannot propagate |
| **AuditLogger** | All `driver->log()` calls wrapped in `try/catch` — audit failures silenced |
| **DatabaseAuditDriver** | `DB::table()->insert()` wrapped in `try/catch` — missing migration table handled gracefully |
| **DB::listen()** | Re-entrancy flag prevents infinite recursion; Shield's own `shield_*` table queries automatically skipped |
| **LicenseManager** | Remote validation wrapped in `try/catch` with `fail_open: true` default — license server outages never block requests |
| **IntelligenceClient** | All HTTP calls wrapped in `try/catch` with timeouts — best-effort, non-blocking |
| **ShieldAnalysisJob** | `handle()` wraps analysis in `try/catch` — queue processing never disrupted |
| **ExceptionGuard** | Analysis wrapped in `try/catch` — never causes cascading exceptions |

---

## Performance Model

Shield is designed to keep request-path work bounded, but exact latency depends on application traffic, storage drivers, payload size, enabled guards, and queue configuration.

### Synchronous Path

The `HttpGuard` performs bounded fast-path validation:

- Regex-based pattern matching on bounded, flattened input (max depth 5, max 64KB)
- Constant-time header checks
- No payload cloning, no stream duplication, no request replay

### Lazy Guard Construction

Guards are registered as class names and only resolved from the container on first access. A request that doesn't touch uploads won't construct the `UploadGuard`. A request without queries won't construct the `DatabaseGuard`.

### Asynchronous Path

Deep analysis executes outside the request lifecycle:

- `ShieldAnalysisJob` dispatched to a dedicated `shield` queue
- Scanner fingerprinting, hash lookups, Zip Slip detection, and archive bomb analysis
- Configurable queue connection and worker isolation

### Database Monitoring

`DB::listen()` adds per-query callback overhead. Pattern matching is synchronous and bounded, but you should benchmark Shield inside your own workload before enabling blocking mode broadly.

### Caching

- Policy compilation cached with configurable TTL
- License validation cached for 24 hours (configurable)
- Tenant configuration resolved once per request
- Brute force counters use `Cache::increment()` (single atomic operation)

### Expected Overhead

Shield does not publish hard performance guarantees in this README. Measure with representative traffic before relying on specific latency budgets in production.

---

## Testing

### Running the Test Suite

```bash
# Install dependencies
composer install

# Run all tests
./vendor/bin/phpunit
```

### Test Coverage

The package includes unit and feature tests covering the primary guards, middleware integration, and upload hardening regressions. Test counts intentionally are not hard-coded in this README; CI is the source of truth.

| Category | Tests | Assertions |
|---|---|---|
| **UploadGuard** | CI-generated | Extension allowlist, MIME mismatches, magic bytes, polyglot detection, archive handling, and filename bypasses |
| **HttpGuard** | CI-generated | Injection patterns, header anomalies, and middleware enforcement behavior |
| **DatabaseGuard** | CI-generated | Injection heuristics, raw queries, slow queries, and tenant boundaries |
| **AuthGuard** | CI-generated | Brute-force counters and anomaly heuristics |
| **ExceptionGuard** | CI-generated | Exception classification, sensitive-data scrubbing, fail-safe decoration |
| **CacheGuard** | CI-generated | Path traversal, null bytes, serialization attacks, size anomalies |
| **QueueGuard** | CI-generated | Allow/block lists, payload inspection, and failure escalation |
| **Middleware Integration** | CI-generated | Upload blocking, nested uploads, rate limiting, and fail-open resilience |

### Writing Custom Guard Tests

All tests extend `VendorShield\Shield\Tests\TestCase` which provides Orchestra Testbench integration:

```php
use VendorShield\Shield\Tests\TestCase;
use VendorShield\Shield\Guards\HttpGuard;
use VendorShield\Shield\Config\ConfigResolver;
use VendorShield\Shield\Audit\AuditLogger;
use VendorShield\Shield\Audit\NullAuditDriver;
use Illuminate\Http\Request;

class CustomGuardTest extends TestCase
{
    public function test_sql_injection_detected(): void
    {
        $this->app['config']->set('shield.guards.http.mode', 'enforce');

        $config = $this->app->make(ConfigResolver::class);
        $audit = new AuditLogger(new NullAuditDriver(), $config);
        $guard = new HttpGuard($config, $audit);

        $request = Request::create('/search', 'GET', [
            'q' => "1' UNION SELECT * FROM users--",
        ]);

        $result = $guard->handle($request);
        $this->assertFalse($result->passed);
    }
}
```

### CI Integration

```yaml
# GitHub Actions
- name: Validate, analyse, and test
  run: |
    composer validate --strict
    composer analyse
    composer lint
    composer test
```

---

## Observability & Monitoring

### Structured Events

Every guard decision dispatches a Laravel event:

| Event | Trigger |
|---|---|
| `ThreatDetected` | Guard detects threat in `enforce` mode |
| `GuardTriggered` | Guard detects anomaly in `monitor` mode |
| `PolicyViolation` | Policy engine denies an action |
| `AnalysisCompleted` | Async deep inspection finishes |
| `LicenseValidated` | License validation completes |

All event dispatches are wrapped in `try/catch` — subscriber exceptions cannot crash the application.

Subscribe to events via standard Laravel listeners for integration with external monitoring, alerting, or SIEM systems:

```php
// EventServiceProvider
protected $listen = [
    \VendorShield\Shield\Events\ThreatDetected::class => [
        \App\Listeners\NotifySecurityTeam::class,
        \App\Listeners\SendToSIEM::class,
    ],
];
```

### Audit Logging

Three built-in drivers:

| Driver | Target | Use Case |
|---|---|---|
| `database` | `shield_audit_logs` table | Production default, queryable. Gracefully handles missing table. |
| `log` | Laravel log channel | Integration with log aggregators (Datadog, Papertrail, ELK) |
| `null` | Discarded | Testing, development |

Retention is configurable. The `shield_audit_logs` table includes composite indexes on `(guard, severity, created_at)` and `(tenant_id, guard, created_at)` for efficient querying.

### Health Endpoint

```bash
php artisan shield:health
```

Reports status of all guards, license validation, database connectivity, intelligence availability, and storage directory permissions.

---

## Enterprise Deployment

### Kubernetes

```yaml
env:
  - name: SHIELD_ENABLED
    value: "true"
  - name: SHIELD_MODE
    value: "enforce"
  - name: SHIELD_ASYNC_ENABLED
    value: "true"
  - name: SHIELD_QUEUE_CONNECTION
    value: "redis"
  - name: SHIELD_LICENSE_KEY
    valueFrom:
      secretKeyRef:
        name: shield-secrets
        key: license-key
```

Deploy dedicated Shield analysis workers:

```yaml
# shield-worker deployment
command: ["php", "artisan", "queue:work", "--queue=shield"]
```

### Docker

```dockerfile
# No additional build steps required.
# Shield activates via service provider auto-discovery.
RUN php artisan shield:install --force
```

### Horizontal Scaling

Shield is stateless by design. Each application instance operates independently. Shared state (audit logs, threat logs) is persisted to the configured database. Cache-based guards (auth brute force, session tracking) use the application's configured cache store with atomic operations.

### CI/CD Integration

```bash
# In deployment pipeline
php artisan shield:baseline --output=storage/shield/baseline.json
php artisan shield:health
./vendor/bin/phpunit
```

### Zero-Downtime Deployments

Shield requires no deployment ceremony. Configuration changes take effect on next request. Guard enable/disable applies instantly via environment variables. No process restart required for config-level changes.

### Recommended Production Rollout

```
Phase 1 — Monitor Mode (Week 1)
  SHIELD_MODE=monitor
  → Deploy to production, verify zero application regressions
  → Review audit logs for false positive rate

Phase 2 — Selective Enforcement (Week 2)
  SHIELD_HTTP_MODE=enforce
  SHIELD_UPLOAD_MODE=enforce
  → Enable enforcement on highest-value guards first

Phase 3 — Full Enforcement (Week 3+)
  SHIELD_MODE=enforce
  → Monitor audit logs and event-driven alerts
  → Fine-tune thresholds based on production traffic
```

---

## Security Philosophy

> **Extend Laravel — never precede Laravel.**

Shield does not:

- Override `Illuminate\Foundation\Http\Kernel`
- Modify the application bootstrap sequence
- Intercept requests before the service container is initialized
- Clone request streams or duplicate payloads
- Introduce static global state
- Call `request()` in CLI or queue contexts

Shield does:

- Register middleware through `$router->prependMiddlewareToGroup()`
- Listen to queries through `DB::listen()` with re-entrancy protection
- Subscribe to queue events through the event dispatcher
- Decorate the exception handler through `$app->extend()`
- Resolve all dependencies through the service container with lazy construction
- Use scoped singletons for Octane-safe per-request isolation
- Wrap all external interactions (events, audit, licensing, intelligence) in fail-safe try/catch

This architecture guarantees that `composer remove vendor-shield/laravel-shield` returns the application to its exact pre-installation state. No residual middleware. No orphaned bindings. No corrupted exception handling.

---

## Security Boundaries

Shield reduces common runtime attack paths inside Laravel, but it is not a complete application security program by itself.

Shield does help with:

- Request-path inspection for common injection and traversal patterns
- Upload validation before application code accepts a file
- Runtime query, queue, cache, and exception telemetry
- Fail-open security instrumentation that should not take the host app down

Shield does **not** by itself guarantee:

- Malware detection equivalent to a maintained antivirus or sandbox engine
- Content Disarm & Reconstruct (CDR) for office documents or PDFs
- Safe public file serving headers in your own download controllers
- Business-specific authorization or tenant modeling beyond the context you provide
- Compliance certification, legal sufficiency, or external audit readiness on its own

For high-risk upload workflows, pair Shield with storage outside the public web root, application-generated filenames, safe download headers (`Content-Disposition: attachment`, accurate `Content-Type`, `X-Content-Type-Options: nosniff`), and external malware/CDR tooling where required.

---

## Compatibility

| Requirement | Version |
|---|---|
| PHP | 8.2+ |
| Laravel | 11.x, 12.x |
| Octane | Supported (scoped singletons, lazy resolution) |
| Horizon | Compatible |
| Queue Workers | All drivers (atomic cache operations) |
| Scheduler | Native support |
| Vapor / Serverless | Compatible |
| CLI / Artisan | Fully supported (no HTTP context assumptions) |

---

## Upgrade Strategy

Shield interacts exclusively with Laravel's stable public API surface:

- `Illuminate\Support\ServiceProvider`
- `Illuminate\Contracts\Debug\ExceptionHandler`
- `Illuminate\Routing\Router` (middleware registration)
- `Illuminate\Database\Events\QueryExecuted`
- `Illuminate\Queue\Events\*`
- `Illuminate\Support\Facades\Cache` (atomic increment)

These interfaces have remained stable across Laravel 9 through 12. Shield's test suite validates compatibility against each supported Laravel version via Orchestra Testbench.

**Forward compatibility guarantee:** Shield will support each new Laravel major version within 30 days of stable release.

---

## Commercial Licensing

### Community Edition (OSS)

Available at no cost. Includes:

- HTTP request guard with bounded input scanning
- Database query monitoring with context-aware patterns
- Upload inspection pipeline with full content scanning
- Queue security with payload inspection
- Basic audit logging with graceful fallback
- CLI tooling (`shield:install`, `shield:health`, `shield:baseline`)
- Fail-open safety across all components

### Professional Edition

For teams requiring advanced security posture:

- Authentication anomaly detection (atomic brute force, impossible travel, session monitoring)
- Cache guard with serialization attack detection
- Tenant boundary enforcement with configurable isolation
- Policy engine with configurable rules and priority evaluation
- Full audit trail with retention management
- CI/CD baseline integration

### Enterprise Edition

For organizations with compliance and scale requirements:

- Cloud threat intelligence sync
- Automated compliance reporting (SOC 2, ISO 27001, GDPR)
- Centralized policy management
- Threat analytics and fingerprinting
- Priority support with SLA

Licensing follows a **fail-open philosophy** — license validation failures never block application requests. Premium features degrade gracefully to community-tier behavior. License validation is CLI/queue-safe and cached for 24 hours.

```bash
# .env
SHIELD_LICENSE_KEY=SHIELD-PRO-xxxxxxxx-xxxx-xxxx-xxxx
```

---

## CLI Reference

| Command | Description |
|---|---|
| `shield:install` | Publish configuration, run migrations, create storage directories |
| `shield:health` | Display status of all guards, license, and subsystems |
| `shield:baseline` | Generate a security configuration snapshot |
| `shield:runtime:enable` | Toggle Shield or individual guards via `.env` |
| `shield:compliance-report` | Generate SOC 2 / ISO 27001 / GDPR compliance report |

---

## API Reference

### Facade

```php
use VendorShield\Shield\Facades\Shield;

// Access the manager
Shield::enabled();
Shield::mode();

// Access guards
Shield::guard('http');
Shield::guard('upload');
Shield::guards(); // All guards (lazily resolved)

// Health check
Shield::health();

// Tenant context
Shield::tenant('tenant-123');

// Policy engine
Shield::policy()->evaluate('http', $context);

// Audit logging
Shield::audit()->log('custom', 'event_type', Severity::Low, ['key' => 'value']);

// Configuration
Shield::config()->override('mode', 'enforce');
Shield::config()->guardMode('http');
```

### Guard Result

```php
use VendorShield\Shield\Support\GuardResult;
use VendorShield\Shield\Support\Severity;

// All guards return GuardResult
$result = $guard->handle($context);

$result->passed;    // bool
$result->message;   // string
$result->severity;  // Severity enum (Critical, High, Medium, Low)
$result->metadata;  // array
$result->toArray(); // Full serialization for audit logging
```

### Custom Guard

```php
use VendorShield\Shield\Contracts\GuardContract;
use VendorShield\Shield\Support\GuardResult;

class RateLimitGuard implements GuardContract
{
    public function name(): string { return 'rate_limit'; }
    public function enabled(): bool { return true; }
    public function mode(): string { return 'enforce'; }

    public function handle(mixed $context): GuardResult
    {
        // Your logic here
        return GuardResult::pass($this->name());
    }
}

// Register in a service provider
Shield::registerGuard('rate_limit', new RateLimitGuard());
```

### Optional Integration Contracts

Shield exposes extension points for teams that want to wire in external file-security tooling without pretending it is built in:

- `VendorShield\Shield\Contracts\MalwareScannerContract`
- `VendorShield\Shield\Contracts\ContentDisarmContract`

These contracts are intended for application or enterprise integrations with AV, sandboxing, or CDR services.

---

## Contributing

Contributions are welcome from engineers who understand the constraints of production Laravel package development.

**Requirements:**

- All code must pass static analysis and the existing test suite (`./vendor/bin/phpunit`)
- New guards or policies must include unit tests
- No Kernel overrides, no bootstrap manipulation, no static mutable state
- All `event()` dispatches must be wrapped in `try/catch(\Throwable)`
- Changes must maintain Octane compatibility (scoped singletons, no shared-nothing violations)
- All guards must support CLI/queue contexts (no `request()` helper calls)
- Documentation updates required for any public API surface change

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines.

---

## Support & Security Reporting

### Security Vulnerabilities

**Do not open a public issue for security vulnerabilities.**

Report vulnerabilities directly to: **security@shield.dev**

Include:

- Affected version
- Reproduction steps
- Impact assessment

We follow a 90-day responsible disclosure policy and will issue a patch release within 72 hours of confirmed critical vulnerabilities.

### Commercial Support

Enterprise license holders receive priority support with defined SLAs. Contact **enterprise@shield.dev**.

---

## Roadmap

| Phase | Focus |
|---|---|
| **Current** | Core guard system, policy engine, audit logging, compliance reporting, fail-open safety, lazy guard resolution |
| **Next** | Rate limiting integration, GraphQL guard, WebSocket protection |
| **Future** | ML-based anomaly detection, distributed threat correlation, real-time dashboard |

Roadmap priorities are informed by enterprise customer requirements. Feature requests can be submitted through the issue tracker.

---

## Credits

- **Rajat Kumar Jha (Software Engineer)** — Research and core security architecture architecture.

---

<p align="center">
  <strong>Laravel Shield</strong>
  <br>
  Runtime security for Laravel. Production-grade. Framework-safe. Fail-open by design.
  <br><br>
  <em>Extend Laravel — never precede Laravel.</em>
</p>
