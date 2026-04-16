<?php

return [

    /*
    |--------------------------------------------------------------------------
    | Shield Master Switch
    |--------------------------------------------------------------------------
    |
    | When disabled, the entire Shield runtime becomes a no-op. No guards
    | are registered, no hooks are attached, and no middleware is injected.
    |
    */
    'enabled' => env('SHIELD_ENABLED', true),

    /*
    |--------------------------------------------------------------------------
    | Global Mode
    |--------------------------------------------------------------------------
    |
    | Controls the default behavior of all guards. Individual guards can
    | override this setting.
    |
    | Supported: "enforce", "monitor", "learning", "disabled"
    |
    */
    'mode' => env('SHIELD_MODE', 'monitor'),

    /*
    |--------------------------------------------------------------------------
    | Async Processing
    |--------------------------------------------------------------------------
    |
    | Heavy analysis is delegated to queue workers. Configure the queue
    | connection and queue name for Shield analysis jobs.
    |
    */
    'async' => [
        'enabled' => env('SHIELD_ASYNC_ENABLED', true),
        'connection' => env('SHIELD_QUEUE_CONNECTION', null), // null = default
        'queue' => env('SHIELD_QUEUE_NAME', 'shield'),
    ],

    /*
    |--------------------------------------------------------------------------
    | Performance
    |--------------------------------------------------------------------------
    */
    'performance' => [
        'max_sync_ms' => env('SHIELD_MAX_SYNC_MS', 1),
        'cache_ttl' => env('SHIELD_CACHE_TTL', 3600),
        'cache_store' => env('SHIELD_CACHE_STORE', null), // null = default
    ],

    /*
    |--------------------------------------------------------------------------
    | Guards Configuration
    |--------------------------------------------------------------------------
    |
    | Each guard can be individually enabled/disabled and assigned its own
    | mode. Guard-level mode overrides the global mode when set.
    |
    */
    'guards' => [

        'http' => [
            'enabled' => env('SHIELD_HTTP_ENABLED', true),
            'mode' => env('SHIELD_HTTP_MODE', null), // null = inherit global
            'middleware_groups' => ['web', 'api'],
            'max_payload_size' => env('SHIELD_HTTP_MAX_PAYLOAD', 10485760), // 10MB
            'header_anomaly_detection' => true,
            'request_scoring' => true,
        ],

        'database' => [
            'enabled' => env('SHIELD_DB_ENABLED', true),
            'mode' => env('SHIELD_DB_MODE', null),
            'detect_raw_queries' => true,
            'detect_sql_injection' => true,
            'slow_query_threshold_ms' => env('SHIELD_DB_SLOW_THRESHOLD', 5000),
            'max_query_length' => env('SHIELD_DB_MAX_QUERY_LENGTH', 10000),
            'tenant_boundary_check' => true,
        ],

        'upload' => [
            'enabled' => env('SHIELD_UPLOAD_ENABLED', true),
            'mode' => env('SHIELD_UPLOAD_MODE', null),
            'allowed_extensions' => [
                'jpg', 'jpeg', 'png', 'gif', 'webp',
                'pdf',
                'txt', 'csv',
                'doc', 'docx',
                'xls', 'xlsx',
                'zip', 'gz', 'tar', 'tgz', 'bz2', 'rar', '7z',
            ],
            'allowed_mimes' => [
                'image/jpeg', 'image/png', 'image/gif', 'image/webp',
                // 'image/svg+xml' — Excluded by default: SVG files are high-risk XXE/XSS/SSRF vectors.
                // Enable explicitly only if your application requires SVG support and you accept the risk.
                'application/pdf',
                'text/plain', 'text/csv',
                'application/msword',
                'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
                'application/vnd.ms-excel',
                'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                'application/zip',
                'application/gzip',
                'application/x-gzip',
                'application/x-tar',
                'application/x-bzip2',
                'application/vnd.rar',
                'application/x-rar-compressed',
                'application/x-7z-compressed',
            ],
            'blocked_extensions' => [
                'php', 'phtml', 'php3', 'php4', 'php5', 'phps',
                'exe', 'bat', 'cmd', 'sh', 'bash',
                'js', 'vbs', 'wsf', 'wsh',
            ],
            'max_file_size' => env('SHIELD_UPLOAD_MAX_SIZE', 52428800), // 50MB
            'max_filename_length' => env('SHIELD_UPLOAD_MAX_FILENAME_LENGTH', 120),
            'quarantine_path' => env('SHIELD_QUARANTINE_PATH', 'shield/quarantine'),
            'scanned_path' => env('SHIELD_SCANNED_PATH', 'shield/scanned'),
            'verify_magic_bytes' => true,
            'compare_client_mime' => env('SHIELD_UPLOAD_COMPARE_CLIENT_MIME', true),
            'content_scan_bytes' => env('SHIELD_UPLOAD_SCAN_BYTES', 8192), // Bytes to read for content inspection
            'async_scan' => true,
            'block_archives' => env('SHIELD_UPLOAD_BLOCK_ARCHIVES', true),
            'archive_max_entries' => env('SHIELD_UPLOAD_ARCHIVE_MAX_ENTRIES', 500),
            'archive_max_uncompressed_bytes' => env('SHIELD_UPLOAD_ARCHIVE_MAX_UNCOMPRESSED_BYTES', 104857600),
            'allow_hidden_dotfiles' => env('SHIELD_UPLOAD_ALLOW_HIDDEN_DOTFILES', false),

            /*
            |----------------------------------------------------------------------
            | Zero-Trust Upload Firewall — Enhanced Security Engines
            |----------------------------------------------------------------------
            */

            // Recursive Decode Engine: max depth for multi-layer decoding
            'recursive_decode_depth' => env('SHIELD_UPLOAD_DECODE_DEPTH', 5),

            // Full content scan: scan entire file instead of first N bytes
            'full_content_scan' => env('SHIELD_UPLOAD_FULL_SCAN', true),

            // Reject uploads with no file extension
            'reject_extensionless' => env('SHIELD_UPLOAD_REJECT_EXTENSIONLESS', true),

            // Reject files with unknown/unmatched MIME type signatures
            'reject_unknown_mime' => env('SHIELD_UPLOAD_REJECT_UNKNOWN_MIME', true),

            // Enable unicode NFKC normalization for homoglyph defense
            'unicode_normalization' => env('SHIELD_UPLOAD_UNICODE_NORMALIZE', true),

            // Enable polyglot file detection (multi-header + script-in-binary)
            'polyglot_detection' => env('SHIELD_UPLOAD_POLYGLOT_DETECT', true),

            // Generate random storage filenames (never store user-supplied name)
            'generate_random_filename' => env('SHIELD_UPLOAD_RANDOM_FILENAME', true),

            // Fail-closed: reject files when scanning errors occur (vs. fail-open)
            'fail_closed_on_error' => env('SHIELD_UPLOAD_FAIL_CLOSED', true),

            // Safe storage path (should be outside web root)
            'safe_storage_path' => env('SHIELD_SAFE_STORAGE_PATH', 'shield/uploads'),

            // Hash-based scan caching
            'scan_cache_enabled' => env('SHIELD_UPLOAD_CACHE_ENABLED', true),
            'scan_cache_ttl' => env('SHIELD_UPLOAD_CACHE_TTL', 3600), // seconds

            'rate_limit' => [
                'enabled' => env('SHIELD_UPLOAD_RATE_LIMIT_ENABLED', true),
                'max_attempts' => env('SHIELD_UPLOAD_RATE_LIMIT_MAX_ATTEMPTS', 10),
                'decay_seconds' => env('SHIELD_UPLOAD_RATE_LIMIT_DECAY_SECONDS', 60),
            ],
        ],

        'queue' => [
            'enabled' => env('SHIELD_QUEUE_GUARD_ENABLED', true),
            'mode' => env('SHIELD_QUEUE_GUARD_MODE', null),
            'job_whitelist' => [],  // empty = allow all
            'job_blacklist' => [],
            'max_execution_time' => env('SHIELD_QUEUE_MAX_EXEC', 3600),
            'payload_inspection' => true,
            'failed_pattern_analysis' => true,
        ],

        'auth' => [
            'enabled' => env('SHIELD_AUTH_ENABLED', true),
            'mode' => env('SHIELD_AUTH_MODE', null),
            'brute_force_threshold' => env('SHIELD_AUTH_BRUTE_FORCE', 5),
            'brute_force_window' => env('SHIELD_AUTH_BRUTE_FORCE_WINDOW', 300), // 5 min
            'impossible_travel' => true,
            'session_anomaly' => true,
        ],

        'cache' => [
            'enabled' => env('SHIELD_CACHE_ENABLED', true),
            'mode' => env('SHIELD_CACHE_MODE', null),
            'key_pattern_validation' => true,
            'serialization_check' => true,
            'size_anomaly_threshold' => env('SHIELD_CACHE_SIZE_THRESHOLD', 1048576), // 1MB
        ],

        'tenant' => [
            'enabled' => env('SHIELD_TENANT_ENABLED', false),
            'mode' => env('SHIELD_TENANT_MODE', null),
            'resolver' => null, // FQCN implementing TenantResolverContract
            'isolation_level' => env('SHIELD_TENANT_ISOLATION', 'strict'), // strict|permissive
            'header' => env('SHIELD_TENANT_HEADER', 'X-Tenant-ID'),
        ],

        'exception' => [
            'enabled' => env('SHIELD_EXCEPTION_ENABLED', true),
            'mode' => env('SHIELD_EXCEPTION_MODE', null),
            'scrub_sensitive_data' => true,
            'pattern_analysis' => true,
            'sensitive_keys' => [
                'password', 'secret', 'token', 'api_key', 'authorization',
                'credit_card', 'ssn', 'card_number',
            ],
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Policy Engine
    |--------------------------------------------------------------------------
    */
    'policy' => [
        'enabled' => env('SHIELD_POLICY_ENABLED', true),
        'loader' => 'config', // config|file|database
        'path' => null,       // for file-based loader
        'cache' => true,
        'rules' => [
            // Define inline policy rules
            // ['guard' => 'http', 'condition' => '...', 'action' => 'block'],
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Cloud Intelligence
    |--------------------------------------------------------------------------
    */
    'intelligence' => [
        'enabled' => env('SHIELD_INTELLIGENCE_ENABLED', false),
        'endpoint' => env('SHIELD_INTELLIGENCE_ENDPOINT', 'https://intelligence.shield.dev'),
        'api_key' => env('SHIELD_INTELLIGENCE_KEY', null),
        'sync_interval' => env('SHIELD_INTELLIGENCE_SYNC', 3600),
        'share_fingerprints' => env('SHIELD_SHARE_FINGERPRINTS', false),
    ],

    /*
    |--------------------------------------------------------------------------
    | Audit Logging
    |--------------------------------------------------------------------------
    */
    'audit' => [
        'enabled' => env('SHIELD_AUDIT_ENABLED', true),
        'driver' => env('SHIELD_AUDIT_DRIVER', 'database'), // database|log|null
        'channel' => env('SHIELD_AUDIT_CHANNEL', null), // for log driver
        'table' => 'shield_audit_logs',
        'retention_days' => env('SHIELD_AUDIT_RETENTION', 90),
    ],

    /*
    |--------------------------------------------------------------------------
    | Threat Logging
    |--------------------------------------------------------------------------
    */
    'threats' => [
        'table' => 'shield_threat_logs',
        'retention_days' => env('SHIELD_THREAT_RETENTION', 365),
    ],

];
