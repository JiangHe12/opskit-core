# opskit-core

Shared governance primitives for the JiangHe12 operations CLI family
([sentinel-cli](https://github.com/JiangHe12/sentinel-cli),
[nacos-cli](https://github.com/JiangHe12/nacos-cli), dbgov-cli, …).

`opskit-core` is the engine; each CLI injects its own domain types and text
through `Configure(...)` and supplies its own audit record shape. The goal is
one consistent governance model — risk tiers, change tickets, allow-flags,
RBAC, and an append-only audit trail — across every tool, without copy-pasting
the hard parts.

## Install

```sh
go get github.com/JiangHe12/opskit-core
```

Requires Go 1.25+.

## Packages

| Package | Responsibility |
|---|---|
| `safety` | Risk model `R0–R3`, `Authorize`, `EffectiveRisk` (protected contexts raise a tier), allow-flags (all required flags must be granted), opt-in RBAC, ticket validation, backup policy. |
| `audit` | Append-only JSONL audit engine: `AppendRecord` (works with each CLI's own event type), `Query`/`QueryRaw`, `Verify`, size-based rotation, optional age encryption. |
| `ctx` | Context configuration store: per-context settings, per-operator roles, and literal/credstore-referenced password resolution. |
| `credstore` | Pluggable credential backends — `plain-yaml`, `encrypted-file`, OS `keychain`, and `vault` — plus credential reference encoding. |
| `printer` | `table` / `json` / `plain` output with a configurable API-version envelope. |
| `redact` | Context-free secret redaction for caller output and audit records. |
| `telemetry` | OpenTelemetry tracing and metrics with per-CLI service/attribute/metric prefixes. |
| `apperrors` | Typed error codes shared across the family. |
| `lockfile` | Advisory lock file for serializing mutating operations. |

## Injection model

Each consumer configures the shared packages once at startup, then uses them
with its own domain types:

```go
audit.Configure(audit.Config{APIVersion: "dbgov.io/audit/v1", ConfigDirName: ".dbgov"})
credstore.Configure(credstore.Options{KeychainService: "dbgov", EncryptedFileMagic: []byte("DBGOV001")})
safety.Configure(safety.Config{ /* prompt text, operator env var, RBAC hints */ })
```

The CLI defines its own audit `Event` struct and writes it through
`audit.AppendRecord` (a "foreign record"); `audit` stays the storage/query/verify
engine while each tool keeps full fidelity over its own fields.

## Governance model

- **R0** read / local — free, still audited.
- **R1** ordinary write — needs `--yes` (or interactive confirmation).
- **R2** sensitive write / protected-context R1 — also needs `--ticket`.
- **R3** destructive / irreversible / protected-context R2 — also needs the
  matching `--allow-*` flag(s).

`--ticket` and `--allow-*` are deliberately walls a non-human cannot fill in:
they force a single, traceable, intentional human approval. Protected contexts
raise every operation one tier.

## Stability

`v1.0.0` is the first stable release and freezes the public contract for the
CLI family. It follows Go semantic import versioning (the `v1` module path has
no version suffix).

## License

[MIT](LICENSE) © 2026 JiangHe12
