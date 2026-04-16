# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Open-source project governance docs:
  - `CONTRIBUTING.md`
  - `SECURITY.md`
  - issue and pull request templates under `.github/`

### Changed
- Removed license-tier/commercial gating and related references.
- Updated README for fully open-source positioning and cleaner onboarding.

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

