# Contributing

Thanks for your interest in contributing to Laravel Shield.

## Development Principles

- Keep integration framework-safe (no kernel override, no bootstrap mutation).
- Preserve fail-safe behavior: Shield issues should not bring down host apps.
- Keep request-path logic bounded; move heavy tasks to async flows when possible.
- Maintain CLI and queue compatibility (no mandatory HTTP context assumptions).

## Prerequisites

- PHP `^8.2`
- Composer
- SQLite extension (used by test environment)

## Setup

```bash
composer install
```

## Local Quality Checks

Run these before opening a pull request:

```bash
composer lint
composer analyse
composer test
```

## Branch and Commit Guidance

- Create focused branches (one change theme per PR).
- Keep commits atomic and descriptive.
- Reference related issues in your PR description.

## Pull Request Checklist

- [ ] Code follows existing conventions and architecture.
- [ ] New/changed behavior has tests.
- [ ] `composer lint`, `composer analyse`, and `composer test` pass locally.
- [ ] README/docs updated for any user-facing changes.
- [ ] Changelog entry added to `CHANGELOG.md` under `Unreleased`.

## Testing Expectations

- Add or update tests for every functional change.
- For guard changes, include:
  - positive path tests
  - block/monitor behavior tests
  - edge-case regression tests

## Reporting Bugs and Proposing Features

- Use the GitHub issue templates.
- Include reproduction steps and expected vs actual behavior.
- For security-sensitive reports, use the policy in `SECURITY.md`.

