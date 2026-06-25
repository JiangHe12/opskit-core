# Changelog

## v1.1.0

### Added

- Added the shared `trust` package providing transport-neutral
  trust-on-first-use (TOFU) pin storage: a lock-guarded, permission-hardened pin
  store with first-use pinning, same-algorithm material-change detection,
  algorithm-change detection, and a non-mutating permission checker. Lets family
  CLIs pin SSH host keys and TLS certificate material on a common, audited store
  instead of reimplementing trust-on-first-use per tool.

## v1.0.5

### Added

- Extended the shared `redact` package with low-false-positive opaque token,
  URL credential, Bearer authorization, and session identifier redaction.

## v1.0.4

### Added

- Added the shared `redact` package with fail-safe structured key, secret flag,
  PEM private key, AWS access key, and JWT redaction for family CLI output and
  audit boundaries.
