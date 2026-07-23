# Changelog

## [Unreleased]

## v2.0.3

### Fixed

- `securefile.WriteFileWithResult` now distinguishes writes that did not commit
  from replacements that committed before a later durability error. The TOFU
  trust store uses that state so a persisted first-use pin is still reported
  exactly once when parent-directory sync fails after replacement.

## v2.0.2

### Security

- Added the shared `securefile` package for owner-only, no-follow reads and
  durable atomic replacement on Unix and Windows, including parent-directory,
  owner, ACL, symlink/reparse-point, and regular-file validation.
- Migrated context, encrypted credential, and TOFU trust stores to the shared
  secure file boundary. Trust updates are now locked and atomically replace the
  complete store, preventing concurrent lost updates and predictable temporary
  file attacks.
- Context loading now rejects additional YAML documents, and trust loading
  rejects conflicting duplicate records instead of accepting ambiguous
  security state.

### Changed

- Upgraded `golang.org/x/crypto`, `x/net`, `x/sys`, and `x/term` to their current
  patched releases.

## v2.0.1

### Security

- Upgraded `golang.org/x/text` from v0.37.0 to v0.39.0, eliminating the
  imported-package `GO-2026-5970` finding from the supported dependency graph.
- Release automation now requires a GitHub-verified signed annotated tag that
  exactly targets freshly fetched `origin/main`, plus an exact literal changelog
  heading, and reruns the complete CI/vulnerability gate on that tag commit.

## v2.0.0

### Breaking

- Changed the Go module and all package imports to
  `github.com/JiangHe12/opskit-core/v2` in accordance with Go semantic import
  versioning. Version 1 consumers must opt in by updating both `require` and
  import paths.
- Output-writing `printer` methods now return errors so broken pipes, short
  writes, and encoder failures cannot be reported as successful commands.
- Vault credential storage now requires HTTPS endpoints and rejects plaintext
  HTTP configuration.

### Migration

- Update all imports to the `/v2` module path and propagate every `printer`
  error to the command boundary.
- Use `audit.AppendRecordWithResult` where mutation recovery must distinguish a
  definitely absent record from committed, post-commit-error, or indeterminate
  states. Never duplicate-spool a record that may already be committed.
- Use `VerifyResult.HasProblems()` for strict audit verification and replace
  direct rotation deletion with `audit.PruneRotatedFiles` after consumer-side
  R3 authorization.

### Security

- Added authenticated v2 audit envelopes with HMAC-SHA256 chaining,
  monotonically increasing sequences, and an authenticated base/head
  checkpoint that detects edits, gaps, reordering, downgrade insertion, and
  log-only tail rollback.
- Added owner-only artifact and directory validation, safer lock reclamation,
  durable append rollback semantics, bounded parsing, and fail-closed handling
  of integrity-key/checkpoint aliases, missing state, and duplicate top-level
  keys in legacy or foreign JSON records.
- Protected POSIX lock initialization with an inode lock from exclusive create
  through publication, and made Windows stale-lock PID probes treat access or
  status-query failures as alive/unknown rather than reclaimable.
- Hardened age recipient loading against file and parent-directory replacement:
  the opened file must be owned by the current user and not writable by an
  untrusted principal. Public read access remains valid for this public key.
- Hardened encrypted-file credential locking and Vault transport validation;
  redaction remains required before both caller output and audit persistence.

### Added

- Added `audit.AppendRecordWithResult` and explicit commit states for mutation
  intent/outcome recovery.
- Added checkpoint-aware `audit.PruneRotatedFiles`. It accepts only the current
  continuous oldest rotation prefix, can bind the full preview through
  `ExpectedRotatedFiles`, advances the checkpoint before deletion, syncs each
  removal, rejects unrecognized rotation-namespace entries, and safely resumes
  partially completed pruning.
- Added `VerifyOptions.ExpectedRotatedFiles` for lock-atomic preview binding and
  `VerifyResult.HasProblems()` for one complete verification predicate.
- Added authenticated audit verification/repair regression coverage, lock and
  permission race coverage, and cross-platform security tests.

### Changed

- Audit append, query, verify, rotation, and legacy repair now share one
  lock-consistent storage boundary. Legacy rows remain readable only before the
  first authenticated envelope; authenticated-history repair fails closed.
- Context, credential, safety, lockfile, and printer APIs now preserve typed
  errors and durable state more precisely for governed CLI consumers.

## v1.1.4

### Changed

- Updated README example to use the aligned API namespace `dbgov-cli.io/audit/v1`
  (previously `dbgov.io/audit/v1`) following family namespace convention.
- Upgraded GitHub Actions dependencies in release workflow (checkout@v7,
  action-gh-release v3.0.1).

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
