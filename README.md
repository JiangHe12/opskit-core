<div align="center">

# opskit-core

**The governance engine behind the `opskit` family of CLIs for humans _and_ AI agents.**

One shared Go library so every governed operations CLI — databases, remote servers, config centers, message brokers — speaks the **same** safety model: risk tiers, change tickets, allow-flags, RBAC, and a tamper-evident audit trail. Write the dangerous parts once, correctly; never copy-paste them again.

[![Go Reference](https://pkg.go.dev/badge/github.com/JiangHe12/opskit-core.svg)](https://pkg.go.dev/github.com/JiangHe12/opskit-core)
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
- 🎫 **Human-only authorization walls** — `--ticket` and `--allow-*` are inputs an autonomous agent *cannot* fabricate, forcing a single, traceable, intentional human approval for anything dangerous.
- 📜 **Append-only, tamper-evident audit** — every action is a hash-chained JSONL record; `Verify` detects any gap or edit. Bodies and secrets never land in the log.
- 🔑 **Pluggable credential storage** — plaintext is never required; secrets resolve through keychain, encrypted-file, or vault backends.
- 🧩 **Domain-agnostic by design** — each CLI injects its own command vocabulary, audit record shape, prompts, and error text through `Configure(...)`; the engine never hard-codes a domain.

It's the foundation under [`dbgov-cli`](https://github.com/JiangHe12/dbgov-cli) (databases), [`srvgov-cli`](https://github.com/JiangHe12/srvgov-cli) (remote servers), [`cfgov-cli`](https://github.com/JiangHe12/cfgov-cli) (config centers), and [`mqgov-cli`](https://github.com/JiangHe12/mqgov-cli) (message brokers).

---

## ✨ What's in the box

| | |
|---|---|
| 🔐 **`safety`** | The risk model: `R0`–`R3`, `Authorize`, `EffectiveRisk` (protected contexts raise a tier), allow-flags (every required flag must be granted), opt-in RBAC, ticket validation, backup policy. |
| 📜 **`audit`** | Append-only JSONL audit engine: `AppendRecord` (works with each CLI's own event type), `Query`/`QueryRaw`, `Verify`, size-based rotation, optional age encryption. |
| 🔑 **`credstore`** | Pluggable credential backends — `plain-yaml`, `encrypted-file`, OS `keychain`, and `vault` — plus credential-reference encoding. |
| 🗂️ **`ctx`** | Context configuration store: per-context settings, per-operator roles, and literal or credstore-referenced secret resolution. |
| 🖨️ **`printer`** | `table` / `json` / `plain` output behind a configurable, versioned API envelope. |
| 🧹 **`redact`** | Context-free secret redaction for both caller output and audit records. |
| 📈 **`telemetry`** | OpenTelemetry tracing and metrics with per-CLI service / attribute / metric prefixes. |
| ⚠️ **`apperrors`** | Typed error codes and the shared process exit-code contract. |
| 🔒 **`lockfile`** | Advisory lock file that serializes mutating operations. |
| 📌 **`trust`** | Transport-neutral trust-on-first-use (TOFU) pin store: pin SSH host keys or TLS certificate SPKI on first use, hard-fail on any later change. |

---

## 📦 Install

```sh
go get github.com/JiangHe12/opskit-core
```

Requires **Go 1.25+**. The library follows Go semantic import versioning — the `v1` module path is stable and carries no version suffix, so patch and minor releases never break your build.

---

## 🚀 Quick start

Configure the shared packages once at startup with your CLI's identity, then use them with your own domain types.

```go
import (
	"github.com/JiangHe12/opskit-core/audit"
	"github.com/JiangHe12/opskit-core/credstore"
	"github.com/JiangHe12/opskit-core/safety"
)

// 1. Wire the engine to your CLI's identity (once, at startup)
safety.Configure(safety.Config{ /* prompt text, operator env var, RBAC hints */ })
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
_ = audit.AppendRecord(auditPath, myEvent, audit.Options{})
```

Your CLI owns its vocabulary and audit fields; the engine owns risk, authorization, storage, and verification.

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
2. **🤖 `--ticket` and `--allow-*` are walls a non-human cannot fill.** They force a single, traceable, intentional human approval. An AI agent should surface *"this needs approval X"* to its operator and stop — it must never invent these values. Protected contexts raise every operation one tier automatically (`EffectiveRisk`).

---

## 🧩 The injection model

`opskit-core` is the engine; it never hard-codes a domain. Each consumer configures the shared packages once and then uses them with its own types:

- The CLI defines its **own audit `Event` struct** and writes it through `audit.AppendRecord` as a *foreign record* — `audit` stays the storage / query / verify engine while each tool keeps full fidelity over its own fields.
- `safety.Configure`, `audit.Configure`, and `credstore.Configure` inject prompt text, the operator env var, RBAC hints, the audit API version and config directory, and the keychain service / encrypted-file magic — so one engine serves four different domains without forking.

New CLI? The full contract for building one that behaves like the rest of the family lives in **[ONBOARDING.md](ONBOARDING.md)**.

---

## 🏗️ Build & contribute

```sh
git clone https://github.com/JiangHe12/opskit-core && cd opskit-core
go build ./...
go test -count=1 ./...
gofmt -l .                 # must print nothing
go vet ./...
```

`opskit-core` ships as a Go module only — releases are git tags (no npm, no binaries). The public contract was frozen at `v1.0.0`; everything since is backward-compatible. See [CHANGELOG.md](CHANGELOG.md) for the per-release history.

---

## 📄 License

[MIT](LICENSE) © 2026 JiangHe12
