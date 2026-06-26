<div align="center">

# opskit-core

**`opskit` 家族 CLI 的治理引擎 —— 同时面向人类_与_ AI agent。**

一个共享 Go 库,让每一个受治理的运维 CLI（数据库、远程服务器、配置中心、消息中间件）都讲同一套安全模型:风险分级、变更工单、放行标志、RBAC,以及防篡改审计链。危险的部分只写一次、写对,永不再复制粘贴。

[![Go Reference](https://pkg.go.dev/badge/github.com/JiangHe12/opskit-core.svg)](https://pkg.go.dev/github.com/JiangHe12/opskit-core)
[![CI](https://github.com/JiangHe12/opskit-core/actions/workflows/ci.yml/badge.svg)](https://github.com/JiangHe12/opskit-core/actions/workflows/ci.yml)
[![release](https://img.shields.io/github/v/tag/JiangHe12/opskit-core.svg?label=release&sort=semver)](https://github.com/JiangHe12/opskit-core/releases)
[![Go](https://img.shields.io/badge/go-1.25%2B-00ADD8.svg)](go.mod)
[![license](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

[English](README.md) · [简体中文](README_zh.md)

</div>

---

## 🧭 这是什么?（请先读这里）

做一个能让人类 **——或 AI agent——** 操作生产系统的 CLI,难点几乎全在*护栏*,而非操作本身。谁有权做这件事?可逆吗?要不要人类显式签字?有没有被记录?这些只要错一次,你就等于把一把上了膛的枪交给了 agent。

`opskit-core` 就是那台**把护栏一次做对**的引擎。家族里每个 CLI 都接入它,而不是各自重新实现风险分级、授权、凭据存储、脱敏与审计:

- 🔐 **统一风险模型(R0–R3)** —— 读免费、普通写需确认、敏感写需变更工单、破坏性操作需逐操作的显式放行标志。受保护上下文整体抬升一档。
- 🎫 **只有人能填的授权墙** —— `--ticket` 与 `--allow-*` 是自主 agent *无法*伪造的输入,强制让任何危险操作都经过一次可追溯、有意为之的人类批准。
- 📜 **只增、防篡改审计** —— 每个动作都是哈希链式 JSONL 记录;`Verify` 能检出任何断裂或改动。消息体与密钥永不入日志。
- 🔑 **可插拔凭据存储** —— 从不要求明文;密钥经 keychain、加密文件或 vault 后端解析。
- 🧩 **设计上与领域无关** —— 每个 CLI 通过 `Configure(...)` 注入自己的命令词汇、审计记录结构、提示语与错误文案;引擎从不硬编码某个领域。

它是 [`dbgov-cli`](https://github.com/JiangHe12/dbgov-cli)（数据库）、[`srvgov-cli`](https://github.com/JiangHe12/srvgov-cli)（远程服务器）、[`cfgov-cli`](https://github.com/JiangHe12/cfgov-cli)（配置中心）、[`mqgov-cli`](https://github.com/JiangHe12/mqgov-cli)（消息中间件）共同的底座。

---

## ✨ 盒子里有什么

| | |
|---|---|
| 🔐 **`safety`** | 风险模型:`R0`–`R3`、`Authorize`、`EffectiveRisk`（受保护上下文抬升一档）、放行标志（所有必需标志都须授予）、可选 RBAC、工单校验、备份策略。 |
| 📜 **`audit`** | 只增 JSONL 审计引擎:`AppendRecord`（适配每个 CLI 自己的事件类型）、`Query`/`QueryRaw`、`Verify`、按大小轮转、可选 age 加密。 |
| 🔑 **`credstore`** | 可插拔凭据后端 —— `plain-yaml`、`encrypted-file`、操作系统 `keychain`、`vault` —— 以及凭据引用编码。 |
| 🗂️ **`ctx`** | 上下文配置存储:每上下文设置、每操作者角色,以及字面量或 credstore 引用的密钥解析。 |
| 🖨️ **`printer`** | `table` / `json` / `plain` 输出,带可配置、带版本的 API 信封。 |
| 🧹 **`redact`** | 面向调用方输出与审计记录的、无上下文依赖的密钥脱敏。 |
| 📈 **`telemetry`** | OpenTelemetry 链路与指标,带每 CLI 的服务/属性/指标前缀。 |
| ⚠️ **`apperrors`** | 家族共享的类型化错误码与进程退出码契约。 |
| 🔒 **`lockfile`** | 串行化变更操作的咨询式锁文件。 |
| 📌 **`trust`** | 传输无关的首次信任（TOFU）锚定存储:首次连接锁定 SSH 主机密钥或 TLS 证书 SPKI,此后任何变更硬失败。 |

---

## 📦 安装

```sh
go get github.com/JiangHe12/opskit-core
```

需要 **Go 1.25+**。本库遵循 Go 语义化导入版本 —— `v1` 模块路径稳定且不带版本后缀,patch 与 minor 发布永不破坏你的构建。

---

## 🚀 快速上手

在启动时用你 CLI 的身份配置一次共享包,然后用你自己的领域类型使用它们。

```go
import (
	"github.com/JiangHe12/opskit-core/audit"
	"github.com/JiangHe12/opskit-core/credstore"
	"github.com/JiangHe12/opskit-core/safety"
)

// 1. 用你 CLI 的身份接上引擎（启动时一次）
safety.Configure(safety.Config{ /* 提示文案、操作者环境变量、RBAC 提示 */ })
audit.Configure(audit.Config{APIVersion: "dbgov.io/audit/v1", ConfigDirName: ".dbgov"})
credstore.Configure(credstore.Options{KeychainService: "dbgov", EncryptedFileMagic: []byte("DBGOV001")})

// 2. 对操作分级，再用正确的人类批准把它拦在门外
risk := safety.EffectiveRisk(safety.R3, meta) // 受保护上下文会抬升一档
if err := safety.Authorize(risk, safety.Options{
	Yes:                flags.Yes,                              // --yes
	Ticket:             flags.Ticket,                           // --ticket   （R2+ 必需）
	RequiredAllowFlags: []safety.AllowFlag{"allow-drop-table"}, // --allow-*  （R3 必需）
	GrantedAllowFlags:  flags.Allows,
	Operator:           operator,
}); err != nil {
	return err // 携带共享的 apperrors 退出码契约
}

// 3. 记录它 —— 你自己的事件结构，引擎的防篡改存储
_ = audit.AppendRecord(auditPath, myEvent, audit.Options{})
```

你的 CLI 拥有自己的词汇与审计字段;引擎拥有风险、授权、存储与校验。

---

## 🔐 治理模型

每个使用方都给操作分配四个**风险档**之一。档位越高,`safety.Authorize` 要求的人类签字越显式:

| 档位 | 覆盖范围 | 调用方必须提供 |
|:---:|---|---|
| **R0** | 读取与预览 | 无 —— 但仍会被审计 |
| **R1** | 普通写 | `--yes`（或交互式确认） |
| **R2** | 敏感写 / 受保护上下文的 R1 | 上述 **加** 非空 `--ticket` |
| **R3** | 破坏性 / 不可逆 / 受保护上下文的 R2 | 上述 **再加** 对应的 `--allow-*` 标志 |

两条性质让它对自动化是安全的:

1. **授权是 fail-closed 的。** 缺确认、工单为空/非法、放行标志未授予 —— 任一情况都拒绝操作;使用方对不确定的操作按**最高**档分级,绝不落到最低档。
2. **🤖 `--ticket` 与 `--allow-*` 是非人类填不了的墙。** 它们强制一次可追溯、有意为之的人类批准。AI agent 应当把*"这需要批准 X"*抛给它的操作者并停下 —— 绝不能自己编造这些值。受保护上下文会自动把每个操作抬升一档（`EffectiveRisk`）。

---

## 🧩 注入模型

`opskit-core` 是引擎,从不硬编码领域。每个使用方配置一次共享包,然后用自己的类型使用它们:

- CLI 定义**自己的审计 `Event` 结构**,通过 `audit.AppendRecord` 作为*外来记录(foreign record)*写入 —— `audit` 始终是存储/查询/校验引擎,而每个工具对自己的字段保有完整保真度。
- `safety.Configure`、`audit.Configure`、`credstore.Configure` 注入提示文案、操作者环境变量、RBAC 提示、审计 API 版本与配置目录、keychain 服务名与加密文件魔数 —— 于是一台引擎不必分叉就能服务四个不同领域。

要做新的 CLI?让它表现得像家族其余成员的完整契约见 **[ONBOARDING.md](ONBOARDING.md)**。

---

## 🏗️ 构建与贡献

```sh
git clone https://github.com/JiangHe12/opskit-core && cd opskit-core
go build ./...
go test -count=1 ./...
gofmt -l .                 # 必须无输出
go vet ./...
```

`opskit-core` 仅以 Go 模块发布 —— 发布即 git tag(无 npm、无二进制)。公共契约在 `v1.0.0` 冻结,此后全部向后兼容。逐版本历史见 [CHANGELOG.md](CHANGELOG.md)。

---

## 📄 许可证

[MIT](LICENSE) © 2026 JiangHe12
