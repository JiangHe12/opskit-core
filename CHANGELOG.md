# Changelog

## v1.1.3

### Added

- Extended list JSON envelopes with an optional operation target field, preserving
  existing output when no target is supplied.

## v1.1.2

### Added

- Added shared printer target helpers for operation-target headers and JSON
  `data.target` injection, so family CLIs can show target awareness without
  duplicating output wrapping logic.

## v1.1.1

### Added

- Added `credstore.IsPlaintextBackend` and `credstore.RequireSecureBackend` so
  family CLIs share one fail-closed guard rejecting credential storage under a
  plaintext (`plain-yaml`) backend, instead of duplicating the check per CLI.

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
