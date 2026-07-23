<div align="center">

# opskit-core

**The governance engine behind the `opskit` family of CLIs for humans _and_ AI agents.**

One shared Go library so every governed operations CLI — databases, remote servers, config centers, message brokers — speaks the **same** safety model: risk tiers, change tickets, allow-flags, RBAC, and a tamper-evident audit trail. Write the dangerous parts once, correctly; never copy-paste them again.

[![Go Reference](https://pkg.go.dev/badge/github.com/JiangHe12/opskit-core/v2.svg)](https://pkg.go.dev/github.com/JiangHe12/opskit-core/v2)
[![CI](https://github.com/JiangHe12/opskit-core/actions/workflows/ci.yml/badge.svg)](https://github.com/JiangHe12/opskit-core/actions/workflows/ci.yml)
[![release](https://img.shields.io/github/v/tag/JiangHe12/opskit-core.svg?label=release&sort=semver)](https://github.com/JiangHe12/opskit-core/releases)
[![Go](https://img.shields.io/badge/go-1.25%2B-00ADD8.svg)](go.mod)
[![license](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

[English](README.md) · [简体中文](README_zh.md)

</div>

---

## 🧭 What is this? (read me first)

Building a CLI that lets humans **— or AI agents —** operate production systems is mostly about the *guardrails*, not the operations. Who's allowed to do this? Is it reversible? Does it need a human's explicit sign-off? Was it recorded? Get that wrong once and you've handed an agent a loaded gun.

`opskit-core` is the **engine that gets those guardrails right, once.** Every CLI in the family plugs into it instead of re-implementing risk classification, authorization, credential storage, redaction, and audit:

- 🔐 **One risk model (R0–R3)** — reads are free, ordinary writes need confirmation, sensitive writes need a change ticket, destructive ones need an explicit per-operation allow-flag. Protected contexts raise every tier.
- 🎫 **Human approval inputs** — `--ticket` and `--allow-*` represent a single, traceable, intentional human approval for dangerous operations; agents must never invent them.
- 📜 **Append-only, tamper-evident audit** — every action is an HMAC-chained JSONL record; while its key and checkpoint remain trusted, `Verify` detects edits, gaps, reorderings, and log-only rollback. Consumers must remove or fingerprint bodies and secrets before `AppendRecord`; core preserves foreign payloads and does not inspect domain fields.
- 🔑 **Pluggable credential storage** — plaintext is never required; secrets resolve through keychain, encrypted-file, or vault backends.
- 🧩 **Domain-agnostic by design** — each CLI injects its own command vocabulary, audit record shape, prompts, and error text through `Configure(...)`; the engine never hard-codes a domain.

It's the foundation under [`dbgov-cli`](https://github.com/JiangHe12/dbgov-cli) (databases), [`srvgov-cli`](https://github.com/JiangHe12/srvgov-cli) (remote servers), [`cfgov-cli`](https://github.com/JiangHe12/cfgov-cli) (config centers), and [`mqgov-cli`](https://github.com/JiangHe12/mqgov-cli) (message brokers).

---

## ✨ What's in the box

| | |
|---|---|
| 🔐 **`safety`** | The risk model: `R0`–`R3`, `Authorize`, `EffectiveRisk` (protected contexts raise a tier), allow-flags (every required flag must be granted), opt-in RBAC, ticket validation, backup policy. |
| 📜 **`audit`** | Append-only JSONL audit engine: `AppendRecord` (works with each CLI's own event type), `Query`/`QueryRaw`, `Verify`, size-based rotation, optional age encryption. |
| 🔑 **`credstore`** | Pluggable credential backends — `plain-yaml`, cross-process-locked `encrypted-file`, OS `keychain`, and HTTPS-only `vault` — plus credential-reference encoding. |
| 🗂️ **`ctx`** | Context configuration store: per-context settings, per-operator roles, and literal or credstore-referenced secret resolution. |
| 🖨️ **`printer`** | `table` / `json` / `plain` output behind a configurable, versioned API envelope. Every output-writing method returns an error that callers must propagate or explicitly handle. |
| 🧹 **`redact`** | Context-free secret redaction for both caller output and audit records. |
| 📈 **`telemetry`** | OpenTelemetry tracing and metrics with per-CLI service / attribute / metric prefixes. |
| ⚠️ **`apperrors`** | Typed error codes and the shared process exit-code contract. |
| 🔒 **`lockfile`** | Advisory lock file that serializes mutating operations. |
| 🛡️ **`securefile`** | Owner-only, no-follow reads and durable atomic file replacement with validated parent directories. |
| 📌 **`trust`** | Transport-neutral trust-on-first-use (TOFU) pin store: pin SSH host keys or TLS certificate SPKI on first use, hard-fail on any later change. |

---

## 📦 Install

```sh
go get github.com/JiangHe12/opskit-core/v2@v2.0.3
```

Requires **Go 1.25+**. Version 2 follows Go semantic import versioning and uses
the `/v2` module suffix. Existing v1 consumers remain on the unsuffixed module
until they intentionally migrate their dependency and imports.

---

## 🚀 Quick start

Configure the shared packages once at startup with your CLI's identity, then use them with your own domain types.

```go
import (
	"github.com/JiangHe12/opskit-core/v2/audit"
	"github.com/JiangHe12/opskit-core/v2/credstore"
	"github.com/JiangHe12/opskit-core/v2/safety"
)

// 1. Wire the engine to your CLI's identity (once, at startup)
safety.Configure(safety.Config{ /* prompt text and RBAC hints */ })
audit.Configure(audit.Config{APIVersion: "dbgov-cli.io/audit/v1", ConfigDirName: ".dbgov"})
credstore.Configure(credstore.Options{KeychainService: "dbgov", EncryptedFileMagic: []byte("DBGOV001")})

// 2. Classify an operation, then gate it behind the right human approvals
risk := safety.EffectiveRisk(safety.R3, meta) // a protected context raises the tier
if err := safety.Authorize(risk, safety.Options{
	Yes:                flags.Yes,                              // --yes
	Ticket:             flags.Ticket,                           // --ticket   (required at R2+)
	RequiredAllowFlags: []safety.AllowFlag{"allow-drop-table"}, // --allow-*  (required at R3)
	GrantedAllowFlags:  flags.Allows,
	Operator:           operator,
}); err != nil {
	return err // carries the shared apperrors exit-code contract
}

// 3. Record it — your own event struct, the engine's tamper-evident storage
if err := audit.AppendRecord(auditPath, myEvent, audit.Options{}); err != nil {
	return err
}
```

Your CLI owns its vocabulary and audit fields; the engine owns risk, authorization, storage, and verification.
All `printer` methods that write output also return an error; return or
explicitly handle it so broken pipes and short writes produce a non-zero exit.

---

## 📜 Tamper-evident audit storage

`Append` and `AppendRecord` store every new row in a fixed
`opskit-core.io/audit/v2` `AuditEnvelope`. The caller's JSON remains the
payload, so `Query` and `QueryRaw` still return the same business record shape.
Each envelope has a monotonically increasing sequence number and an
HMAC-SHA256 link to its predecessor.

Mutation callers that must distinguish an absent intent from an intent that was
already persisted can use `AppendRecordWithResult`. Its `AppendResult.State`
is one of `not-committed`, `committed`, `committed-postcommit-error`, or
`indeterminate`. For an existing active file, the record commits when its bytes
are fsynced. For a newly created active file, POSIX also fsyncs the parent
directory; Windows uses the synced and closed file as its platform durability
boundary because directory handles do not expose the POSIX fsync contract.
Short writes and file-sync failures are truncated back to the original length
and fsynced while the same audit lock remains held. A successful rollback is
`not-committed`; a rollback failure is `indeterminate`. A checkpoint or lock
cleanup failure after the record commit point is
`committed-postcommit-error`. The existing `AppendRecord` API remains
compatible and returns only the error.

The default integrity artifacts are:

- `<audit.log>.hmac-key` — a generated 32-byte HMAC key;
- `<audit.log>.checkpoint` — an authenticated base/head checkpoint used to
  detect tail truncation.

The active log, rotated logs, key, and checkpoint are owner-only. Back them up
and restore them as one consistent set. A missing key is never regenerated once
authenticated history exists. To put the key elsewhere, pass the same
`IntegrityKeyPath` in `audit.Options`, `audit.Filter`, and
`audit.VerifyOptions`.

Readers remain compatible with legacy v1 plaintext and base64-age rows. Legacy
rows may appear before the first v2 envelope; a legacy row after v2 is treated
as a downgrade and rejected. With encrypted v2 payloads, `Verify` can
authenticate the outer envelope without an age private key and reports the
payload as `encryptedOpaque`.

When `EncryptPublicKeyPath` is configured, core validates the opened age
recipient file itself and its full parent-directory chain. The file must be
owned by the current user and must not grant write access to group/other users
or any untrusted Windows principal; parent directories must not permit an
untrusted replacement. Public read access (for example POSIX `0644`) is allowed
because the recipient is a public key.

`VerifyResult.HasProblems()` covers malformed/schema/timestamp errors plus MAC,
sequence, checkpoint, and truncation failures. Repair is intentionally rejected
for v2 history because deleting a failed row would itself break the
authenticated chain; restore a consistent backup instead.
Confirmed legacy repair holds the audit lock from verification through commit,
uses owner-only same-directory staging, and durably replaces each repaired file
while preserving the original if a pre-commit step fails. A commit-directory
sync failure triggers a durable rollback; an unsuccessful rollback is reported
as indeterminate rather than as a successful repair.

Destructive rotation pruning is exposed through `PruneRotatedFiles`. Core does
not grant authorization: the consumer CLI must complete its R3 ticket,
confirmation, and exact allow-flag checks before setting `PruneOptions.Confirm`.
Pass only a continuous oldest prefix returned by `RotatedFiles`; when a preview
must bind the entire observed set, also pass that set as
`ExpectedRotatedFiles`. Core repeats the comparison and full history
verification while holding the audit lock. For authenticated history it then
persists a checkpoint whose base is the final deleted envelope before removing
any file, and performs the parent durability step after every removal (directory
sync on POSIX; completed removal is the available Windows boundary). If
deletion is partial, retry with the remaining current oldest prefix. A retry whose files
end at the authenticated checkpoint base returns checkpoint state
`already-advanced` and safely finishes cleanup without moving the head.
`PruneResult.DeletedFiles` contains only removals whose platform durability
step succeeded; `Started` and `CheckpointState` let callers audit partial or
indeterminate outcomes without guessing.
Prune also rejects unrecognized `audit.log.*.log` namespace entries instead of
silently ignoring files that resemble malformed rotations; strict quarantine
and in-progress repair staging names are excluded from that check.

For preview-bound legacy repair, set `VerifyOptions.ExpectedRotatedFiles` to
the exact list shown to the operator. The comparison occurs under the same lock
as verification and repair; a changed set returns `CONFLICT` before mutation.

This is local tamper evidence, not an external trust anchor. It detects an
attacker who edits, deletes, reorders, or rolls back only the log without the
HMAC key. It cannot resist the same OS account, an administrator, or root after
they obtain the key and re-sign history; nor can it detect a coordinated
rollback of the log, key, and checkpoint to one older consistent snapshot.
Those threats require an externally non-rollbackable anchor, remote signing, or
a separately trusted backup/attestation system.

### Migrating from v1

1. Change the required module and every import to
   `github.com/JiangHe12/opskit-core/v2`.
2. Propagate the errors now returned by all output-writing `printer` methods.
3. Use `AppendRecordWithResult` for mutation intent/outcome recovery and treat
   `indeterminate` or post-commit errors as audit failures, not retryable absent
   records.
4. Treat `VerifyResult.HasProblems()` as the complete strict verification
   predicate, and use core's lock-bound repair/prune APIs rather than deleting
   rotations directly.
5. Configure Vault with HTTPS endpoints; plaintext HTTP is rejected in v2.

---

## 🔐 The governance model

Each consumer assigns every operation one of four **risk tiers**. The higher the tier, the more explicit human sign-off `safety.Authorize` demands:

| Tier | What it covers | What the caller must provide |
|:---:|---|---|
| **R0** | Reads & previews | Nothing — but it's still audited |
| **R1** | Ordinary writes | `--yes` (or an interactive confirmation) |
| **R2** | Sensitive writes / protected-context R1 | `--yes` **and** a non-empty `--ticket` |
| **R3** | Destructive / irreversible / protected-context R2 | The above **plus** the matching `--allow-*` flag(s) |

Two properties make this safe for automation:

1. **Authorization is fail-closed.** Missing confirmation, an empty/invalid ticket, or an ungranted allow-flag all reject the operation — callers classify uncertain operations at the **highest** tier, never the lowest.
2. **🤖 `--ticket` and `--allow-*` are human-supplied approval inputs.** An AI agent should surface *"this needs approval X"* to its operator and stop — it must never invent these values. Protected contexts raise every operation one tier automatically (`EffectiveRisk`).

RBAC operator identity must be supplied by the consumer from a trusted local
identity source; `safety.Authorize` never falls back to an environment variable.
This does not separate an AI process from a human process running under the same
OS account. That boundary requires an externally signed approval source or a
separately protected operator account.

---

## 🧩 The injection model

`opskit-core` is the engine; it never hard-codes a domain. Each consumer configures the shared packages once and then uses them with its own types:

- The CLI defines its **own audit `Event` struct** and writes it through `audit.AppendRecord` as a *foreign record* — `audit` stays the storage / query / verify engine while each tool keeps full fidelity over its own fields.
- `safety.Configure`, `audit.Configure`, and `credstore.Configure` inject prompt text, RBAC hints, the audit API version and config directory, and the keychain service / encrypted-file magic — so one engine serves four different domains without forking.

New CLI? The full contract for building one that behaves like the rest of the family lives in **[ONBOARDING.md](ONBOARDING.md)**.

---

## 🏗️ Build & contribute

```sh
git clone https://github.com/JiangHe12/opskit-core && cd opskit-core
go build ./...
go test -count=1 ./...
gofmt -l .                 # must print nothing
go vet -tags=integration ./...
go test -race -count=1 ./...
golangci-lint run --timeout=5m
govulncheck ./...
```

`opskit-core` ships as a Go module only — releases are git tags (no npm, no
binaries). Each semantic-import major maintains its own compatibility line;
v2 intentionally requires the `/v2` import path. New releases require a
GitHub-verified signed annotated tag that exactly targets freshly fetched
`origin/main` and whose version has an exact literal `CHANGELOG.md` heading;
the complete CI/vulnerability gate reruns on that tag commit. See
[CHANGELOG.md](CHANGELOG.md) for the per-release history.

---

## 📄 License

[MIT](LICENSE) © 2026 JiangHe12
