# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.0] - 2026-04-22

### Added
- **Access Control Framework**: Pluggable policy-based access control system
  - `AccessControlDeciderContract` for custom access decision implementations
  - `NullAccessControlDecider` default implementation (permissive)
  - `AccessDecision` value object for blocking decisions with metadata
  - Integration into `ShieldMiddleware` for enforcing access policies
  - Blocking with custom HTTP status codes and error messages
- **Request Context System**: Comprehensive request-scoped context tracking
  - `RequestContextStore` for managing request lifecycle data
  - `RequestContextResolverContract` for extensible context resolution
  - `DefaultRequestContextResolver` that captures:
    - Request ID (UUID) for request tracing
    - Timestamp and request metadata
    - Client IP and forwarded-for chain
    - Authentication user information
    - Request scheme, method, and host
    - Authentication method and capabilities
  - Scoped binding in service container (cleared per request)
- Request context integration into audit and threat logging for correlation

### Changed
- **AuditLogger**: Now includes request context in all audit entries
  - Unified `contextForGuard()` method for consistent context structure
  - Enhanced analysis and policy error event logging
- **ThreatLogger**: Enriched threat entries with request context
  - Better threat correlation across events
- **ShieldMiddleware**: Enhanced with access control enforcement
  - Request context resolution on every request
  - Access control decision evaluation before HTTP guard
  - Threat blocking with detailed JSON responses including request reference
  - Automatic request ID generation for tracing
- **DatabaseGuard**: Improved handling of DDL operations
  - Console commands can safely execute CREATE/ALTER/DROP operations
  - Exemption for migration table operations (INSERT/DELETE)
  - Better framework automation detection
- **ServiceProvider**: Registered new access control and context infrastructure
  - Bindings for request context and resolver contracts
  - Injected RequestContextStore into AuditLogger and ThreatLogger

## [1.1.0] - 2026-04-22

### Added
- **Threat Logging System**: Comprehensive threat fingerprinting and logging with multiple driver backends
  - `ThreatLogger` for centralized threat event correlation
  - `ThreatDriverContract` for pluggable threat drivers (`database`, `log`, `null`)
  - `DatabaseThreatDriver` and `LogThreatDriver` implementations
  - Threat fingerprint generation for guard events and analysis results
  - Threat logger access via `Shield::threats()` facade method
- **Upload Guard Improvements**:
  - Support for additional image formats: BMP, TIFF, ICO, AVIF, HEIC, HEIF
  - MIME type normalization to handle variant MIME types
  - Intelligent skipping of deep content scans for raster images to reduce false positives
- **HTTP Guard Enhancements**:
  - Improved command injection detection regex for precision and coverage
  - Relaxed command injection validation for common text fields (bio, summary, description, etc.) to reduce false positives
- **Config Structure**: New threat driver configuration options in `shield.php`
  - `SHIELD_THREATS_DRIVER` environment variable
  - `SHIELD_THREATS_CHANNEL` for log driver support
- Documentation: README updates explaining dual logging streams (audit logs and threat logs)

### Changed
- **AuditLogger**: Refactored to integrate threat fingerprinting on audit events
  - Augmented guard payload with threat context when applicable
  - Enhanced payload construction for both guard events and analysis results
- **Upload Filename Validation**: Refined regex pattern for improved security
  - Removed `=` character (reduced false positives)
  - Added `` ` `` and `|` characters (critical shell operators)
- **ShieldServiceProvider**: Updated bindings to register threat logging infrastructure
  - Injected `ThreatLogger` into `AuditLogger`
  - Registered threat driver factory with configuration-driven selection
- **ShieldManager**: Added `threats()` method for direct access to threat logger
- Removed license-tier/commercial gating and related references.
- Updated README for fully open-source positioning and cleaner onboarding.

### Fixed
- Raster image upload validation: Eliminated false positives from text-oriented payload scanning
- Command injection detection in common text fields: Now properly distinguishes legitimate text from shell commands
- MIME type consistency issues with variant representations (e.g., `image/jpg` → `image/jpeg`)

## [1.0.0] - 2026-04-16

### Added
- Initial public release of Laravel Shield.
- Runtime guards for HTTP, database, uploads, queue, auth, cache, tenant, and exceptions.
- Policy engine and audit logging drivers (`database`, `log`, `null`).
- CLI commands:
  - `shield:install`
  - `shield:health`
  - `shield:baseline`
  - `shield:runtime:enable`
  - `shield:compliance-report`

