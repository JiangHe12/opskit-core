# Onboarding a new CLI onto opskit-core

This is the contract for building a new governed operations CLI (e.g. `es-cli`)
on top of `opskit-core`, so it behaves like the rest of the family
([dbgov-cli](https://github.com/JiangHe12/dbgov-cli),
[srvgov-cli](https://github.com/JiangHe12/srvgov-cli),
[cfgov-cli](https://github.com/JiangHe12/cfgov-cli),
[mqgov-cli](https://github.com/JiangHe12/mqgov-cli)).

The rule of thumb: **opskit-core is the engine; your CLI injects its own domain
types and text and keeps its own audit record shape.** You do not fork core, and
you do not reimplement risk/audit/credentials.

## 1. Depend on the released module

```sh
go get github.com/JiangHe12/opskit-core/v2@<released-version>
```

Do not use a `replace` directive in committed code — depend on the tagged
version so your repo builds standalone.

Version 2 is a semantic-import-versioned breaking release. All core imports
must also use `github.com/JiangHe12/opskit-core/v2/<package>`; do not mix v1 and
v2 package identities in one CLI.

## 2. Configure the shared packages once at startup

Add a `cmd/core_config.go` with an `init()` (or an explicit setup call) that
injects your CLI's identity into each package. Example shape (from dbgov):

```go
apperrors.Configure(apperrors.Options{ /* APIVersion, code→hint overrides */ })
audit.Configure(audit.Config{APIVersion: "<tool>.io/audit/v1", ConfigDirName: ".<tool>"})
corectx.Configure(corectx.Options{APIVersion: "<tool>.io/context/v1", ConfigDirName: ".<tool>"})
printer.Configure(printer.Options{APIVersion: "<tool>.io/v1"})
credstore.Configure(credstore.Options{KeychainService: "<tool>", EncryptedFileMagic: []byte("<TOOL>01")})
safety.Configure(safety.Config{Prompt: "...", RoleAssignmentHintFormat: "..."})
telemetry.Configure(telemetry.Options{ServiceName: "<tool>", AttributePrefix: "<tool>", ...})
```

Pick a unique `ConfigDirName` (`~/.<tool>`), keychain service, and encrypted-file
magic so tools never collide.

Every `printer` method that writes output returns an error. Propagate or
explicitly handle it so broken pipes and short writes become command failures:

```go
if err := out.Table(headers, rows); err != nil {
	return err
}
```

## 3. Define your own audit event (foreign record)

Core's `audit.Event` is sentinel/nacos-shaped. Your domain almost certainly
needs different fields. Define your **own** `Event` struct in `internal/audit`,
write it through `audit.AppendRecord(path, event, opts)` (a "foreign record"),
and read it back with `audit.QueryRaw` (unmarshal into your type) + `audit.Verify`
(works on any well-formed JSONL with `timestamp`/`eventType`/`operator`). Core
stays the storage/query/verify engine; you keep full fidelity over your fields.

New writes use the fixed `opskit-core.io/audit/v2` authenticated envelope; the
foreign record is its payload and remains unchanged to `QueryRaw`. Keep the
active log, strict-name rotated logs, `<audit.log>.hmac-key`, and
`<audit.log>.checkpoint` together in backups. If you override
`Options.IntegrityKeyPath`, pass the identical path to `Filter` and
`VerifyOptions` when reading. Never regenerate or substitute a missing key for
existing v2 history.

Legacy plaintext/base64-age rows are read before the first v2 envelope during
migration. Do not append, import, or restore legacy rows after v2 has started:
that is a downgrade and fails closed. `Verify` authenticates encrypted v2
envelopes without decrypting their payload; v2 repair is deliberately
unsupported, so recovery is a consistent snapshot restore rather than deleting
individual rows.

Confirmed legacy repair holds the audit lock across validation and commit. It
uses owner-only same-directory staging, syncs staged files and the containing
directory, and durably rolls back the original if the commit-directory sync
fails. A rollback failure is reported as indeterminate.

For a preview-bound repair, pass the exact preview list in
`VerifyOptions.ExpectedRotatedFiles`; core compares it under the audit lock and
returns `CONFLICT` if rotations changed. Do not take a second outer audit lock.

For audit pruning, first obtain the strict `RotatedFiles` list and select only
its continuous oldest prefix. After the CLI completes R3 authorization, call
`PruneRotatedFiles` with `Confirm: true` and the full preview list in
`ExpectedRotatedFiles`. Core verifies the complete history, advances the v2
checkpoint base, then deletes and directory-syncs each candidate. On partial
failure, audit `PruneResult.Started`, `DeletedFiles`, and `CheckpointState`, and
retry only the remaining current oldest prefix. Never delete rotations before
core has persisted the new checkpoint base.

Treat the HMAC key and checkpoint as local tamper-evidence state, not as an
external trust anchor. They detect edits/deletions/reordering and log-only
rollback by an actor without the key. They do not protect against the same OS
account, administrator, or root after key access, and they cannot detect a
coordinated rollback of log + key + checkpoint to an older consistent set. Use
an externally non-rollbackable anchor, remote signing, or a separately trusted
backup/attestation service when that stronger threat model applies.

Always audit — including denied and failed operations.
Never discard an `audit.AppendRecord` error; propagate it or use
`AppendRecordWithResult` when mutation recovery needs the commit state.

## 4. Your context type embeds `corectx.Base`

```go
type Context struct {
    corectx.Base        // password (literal/credstore ref) resolution, roles, ticket pattern, protected, env
    /* your domain fields: host, port, cluster, ... */
}
```

Resolve credentials via `ctx.ResolvePasswordContext(...)` — never read a literal
password directly. Support `ctx migrate-credentials` to move literals into a
secure backend.

## 5. Wire the governance spine

Build thin `authorizeRead` / `authorizeWrite` helpers over `safety.Authorize`:

- Compute the effective risk with `safety.EffectiveRisk(base, ContextMeta{Protected, Roles, TicketPattern, ...})` (protected contexts raise a tier).
- Pass `safety.Options{Yes, NonInteractive, Ticket, TicketPattern, RequiredAllowFlags, GrantedAllowFlags, Roles, Operator}`.
- `RequiredAllowFlags` is a slice — require **all** relevant allow-flags when an
  operation carries more than one class of danger.

Follow the family canon exactly:

- **R0** read/local — free, still audited (do **not** RBAC-gate reads).
- **R1** ordinary write — `--yes`/confirm. **R2** sensitive — `+ --ticket`.
  **R3** destructive — `+ --ticket + matching --allow-*`.
- An agent must never be able to satisfy `--ticket` / `--allow-*` / high-risk
  `--yes` on its own — those are human-approval walls.
- Impact / blast radius must come from the system being governed, never guessed;
  if it can't be measured, refuse rather than guess.
- Allow-flag values have no `--` prefix; risk constants are `R0/R1/R2/R3`.

## 6. Match the engineering setup

Mirror the family repo infrastructure (see dbgov-cli / mqgov-cli):

- `.github/workflows/ci.yml` — Ubuntu and Windows gofmt, integration-tag vet,
  build, and `go test -count=1`; Linux race; golangci-lint; govulncheck; plus an
  opt-in real-backend integration job when the CLI has one.
- `.github/workflows/release.yml` — tag-triggered matrix build with version ldflags, cosign signing, checksums, GitHub Release, `npm publish --provenance`.
- `.github/workflows/security-scan.yml`, `.github/dependabot.yml`, `.github/pull_request_template.md`.
- `package.json` + `bin/<tool>.js` + `scripts/install.js` (npm wrapper that downloads the matching release binary — keep the asset name identical on both sides).
- `CHANGELOG.md`, `LICENSE` (MIT).
- Version injection: `main` holds `version/commit/date` set via `-ldflags`.

Before review, run the same complete local gate as CI (gofmt must print
nothing):

```sh
gofmt -l .
go vet -tags=integration ./...
go build ./...
go test -count=1 ./...
go test -race -count=1 ./...
golangci-lint run --timeout=5m
govulncheck ./...
```

## Checklist

- [ ] `require github.com/JiangHe12/opskit-core/v2@<released-version>`, no `replace`
- [ ] `core_config.go` injects all packages with a unique tool identity
- [ ] own audit `Event` written via `AppendRecord`, with errors propagated; queried via `QueryRaw`
- [ ] audit log + rotations + HMAC key + checkpoint backed up/restored together
- [ ] context embeds `corectx.Base`; credentials via `ResolvePasswordContext`
- [ ] `authorizeRead`/`authorizeWrite` over `safety.Authorize` + `EffectiveRisk`
- [ ] R0–R3 + ticket + allow-flags + opt-in RBAC, reads not gated
- [ ] impact authoritative (measured, never guessed); refuse if unmeasurable
- [ ] every command audited, including denied/failed
- [ ] CI / release / npm / security-scan / dependabot / PR template in place
- [ ] MIT license, CHANGELOG, README
