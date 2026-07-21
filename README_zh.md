<div align="center">

# opskit-core

**`opskit` 家族 CLI 的治理引擎 —— 同时面向人类_与_ AI agent。**

一个共享 Go 库,让每一个受治理的运维 CLI（数据库、远程服务器、配置中心、消息中间件）都讲同一套安全模型:风险分级、变更工单、放行标志、RBAC,以及防篡改审计链。危险的部分只写一次、写对,永不再复制粘贴。

[![Go Reference](https://pkg.go.dev/badge/github.com/JiangHe12/opskit-core/v2.svg)](https://pkg.go.dev/github.com/JiangHe12/opskit-core/v2)
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
- 🎫 **人类批准输入** —— `--ticket` 与 `--allow-*` 表示一次可追溯、有意为之的人类批准；agent 绝不能自行编造。
- 📜 **只增、防篡改审计** —— 每个动作都是 HMAC 链式 JSONL 记录；在密钥与检查点仍可信时，`Verify` 能发现编辑、缺口、重排和仅回滚日志。调用方必须在 `AppendRecord` 前删除消息体与密钥，或将其转换为指纹；core 会完整保留外来载荷，不检查领域字段。
- 🔑 **可插拔凭据存储** —— 从不要求明文;密钥经 keychain、加密文件或 vault 后端解析。
- 🧩 **设计上与领域无关** —— 每个 CLI 通过 `Configure(...)` 注入自己的命令词汇、审计记录结构、提示语与错误文案;引擎从不硬编码某个领域。

它是 [`dbgov-cli`](https://github.com/JiangHe12/dbgov-cli)（数据库）、[`srvgov-cli`](https://github.com/JiangHe12/srvgov-cli)（远程服务器）、[`cfgov-cli`](https://github.com/JiangHe12/cfgov-cli)（配置中心）、[`mqgov-cli`](https://github.com/JiangHe12/mqgov-cli)（消息中间件）共同的底座。

---

## ✨ 盒子里有什么

| | |
|---|---|
| 🔐 **`safety`** | 风险模型:`R0`–`R3`、`Authorize`、`EffectiveRisk`（受保护上下文抬升一档）、放行标志（所有必需标志都须授予）、可选 RBAC、工单校验、备份策略。 |
| 📜 **`audit`** | 只增 JSONL 审计引擎:`AppendRecord`（适配每个 CLI 自己的事件类型）、`Query`/`QueryRaw`、`Verify`、按大小轮转、可选 age 加密。 |
| 🔑 **`credstore`** | 可插拔凭据后端 —— `plain-yaml`、带跨进程锁的 `encrypted-file`、操作系统 `keychain`、仅接受 HTTPS 地址的 `vault` —— 以及凭据引用编码。 |
| 🗂️ **`ctx`** | 上下文配置存储:每上下文设置、每操作者角色,以及字面量或 credstore 引用的密钥解析。 |
| 🖨️ **`printer`** | `table` / `json` / `plain` 输出,带可配置、带版本的 API 信封。所有写输出的方法都会返回 error，调用方必须传播或显式处理。 |
| 🧹 **`redact`** | 面向调用方输出与审计记录的、无上下文依赖的密钥脱敏。 |
| 📈 **`telemetry`** | OpenTelemetry 链路与指标,带每 CLI 的服务/属性/指标前缀。 |
| ⚠️ **`apperrors`** | 家族共享的类型化错误码与进程退出码契约。 |
| 🔒 **`lockfile`** | 串行化变更操作的咨询式锁文件。 |
| 📌 **`trust`** | 传输无关的首次信任（TOFU）锚定存储:首次连接锁定 SSH 主机密钥或 TLS 证书 SPKI,此后任何变更硬失败。 |

---

## 📦 安装

```sh
go get github.com/JiangHe12/opskit-core/v2@v2.0.0
```

需要 **Go 1.25+**。v2 遵循 Go 语义化导入版本并使用 `/v2` 模块后缀。
现有 v1 使用方会继续停留在不带后缀的模块，直到主动迁移依赖与 import。

---

## 🚀 快速上手

在启动时用你 CLI 的身份配置一次共享包,然后用你自己的领域类型使用它们。

```go
import (
	"github.com/JiangHe12/opskit-core/v2/audit"
	"github.com/JiangHe12/opskit-core/v2/credstore"
	"github.com/JiangHe12/opskit-core/v2/safety"
)

// 1. 用你 CLI 的身份接上引擎（启动时一次）
safety.Configure(safety.Config{ /* 提示文案与 RBAC 提示 */ })
audit.Configure(audit.Config{APIVersion: "dbgov-cli.io/audit/v1", ConfigDirName: ".dbgov"})
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
if err := audit.AppendRecord(auditPath, myEvent, audit.Options{}); err != nil {
	return err
}
```

你的 CLI 拥有自己的词汇与审计字段;引擎拥有风险、授权、存储与校验。
所有写输出的 `printer` 方法也会返回 error；必须返回或显式处理该错误，确保
管道断开和短写能产生非零退出码。

---

## 📜 防篡改审计存储

`Append` 与 `AppendRecord` 现在会把每条新记录写入固定的
`opskit-core.io/audit/v2` `AuditEnvelope`。调用方 JSON 原样放在 payload
中，所以 `Query` 与 `QueryRaw` 返回的业务记录结构保持不变。每个信封都带
单调递增序号，并通过 HMAC-SHA256 链接前一条记录。

需要区分“intent 完全未写入”和“intent 已持久化但后续步骤失败”的 mutation
调用方，可以使用 `AppendRecordWithResult`。其 `AppendResult.State` 取值为
`not-committed`、`committed`、`committed-postcommit-error` 或
`indeterminate`。对于已有活动文件，追加字节 fsync 成功即达到记录提交点；
对于新建活动文件，POSIX 还会 fsync 父目录，Windows 因目录句柄不提供 POSIX
fsync 契约，以文件完成 fsync 并关闭作为平台持久化边界。短写或文件 fsync
失败时，会在同一个 audit lock 内截断回原长度并再次 fsync：回滚成功为
`not-committed`，回滚失败为 `indeterminate`。记录提交后若检查点或锁清理
失败，则为 `committed-postcommit-error`。原有 `AppendRecord` API 保持兼容，
仍只返回 error。

默认完整性文件为：

- `<audit.log>.hmac-key` —— 自动生成的 32 字节 HMAC 密钥；
- `<audit.log>.checkpoint` —— 带认证的 base/head 检查点，用于发现尾部截断。

活动日志、轮转日志、密钥与检查点均限制为仅所有者可访问。备份和恢复时必须把
它们视为同一组一致快照；已有认证历史时，密钥丢失绝不会被自动重建。若要把
密钥放到其他位置，必须在 `audit.Options`、`audit.Filter` 与
`audit.VerifyOptions` 中一致传入 `IntegrityKeyPath`。

读取端继续兼容旧 v1 明文行与 base64-age 行。旧行可以位于第一个 v2 信封之前；
v2 之后再出现旧行会被视为降级并拒绝。对于加密的 v2 payload，`Verify`
无需 age 私钥也能认证外层信封，并把 payload 计为 `encryptedOpaque`。

配置 `EncryptPublicKeyPath` 后，core 会校验实际打开的 age recipient 文件句柄及其
完整父目录链。文件必须由当前用户所有，且不能向 group/other 或任何不可信的
Windows principal 授予写权限；父目录也不能允许不可信主体替换该文件。recipient
是公钥，因此允许公开只读访问（例如 POSIX `0644`）。

`VerifyResult.HasProblems()` 同时覆盖格式、schema、时间顺序、MAC、序列、
检查点与截断问题。v2 历史不允许 `Repair`，因为删除失败行本身就会破坏认证链；
此时应恢复一组一致备份。
已确认的旧版历史修复会从验证到提交全程持有审计锁，使用同目录、仅所有者可访问
的暂存文件，并以持久化原子替换提交。提交前失败时原始文件保持不变；提交目录
同步失败时执行持久化回滚，回滚本身若失败则报告状态不确定，不会误报修复成功。

破坏性的轮转日志清理由 `PruneRotatedFiles` 提供。core 不授予权限：使用方 CLI
必须先完成 R3 工单、确认和精确 allow flag 校验，之后才能设置
`PruneOptions.Confirm`。候选只能是 `RotatedFiles` 返回结果的连续最老前缀；若
preview 还需要绑定当时看到的完整集合，同时传入 `ExpectedRotatedFiles`。core
会在持有 audit lock 时重新比较并完整验证历史。对于认证历史，core 会先把
checkpoint base 持久推进到最后一个待删信封，再开始删文件，并在每次删除后同步
父级持久化边界（POSIX 同步目录；Windows 以删除完成作为可用边界）。删除部分失败
时，用剩余的当前最老前缀重试；若其末尾正好对应已认证的
checkpoint base，返回 `already-advanced` 并安全完成清理，不改变 head。
`PruneResult.DeletedFiles` 只包含删除且平台持久化步骤成功的文件；调用方可结合
`Started` 与 `CheckpointState` 准确审计部分失败或状态不确定的结果。
Prune 还会拒绝无法识别的 `audit.log.*.log` 命名空间条目，不会静默忽略看起来像
畸形 rotation 的文件；严格 quarantine 与修复中的 staging 名称不参与此检查。

对需要绑定 preview 的旧版修复，把操作者看到的精确列表传入
`VerifyOptions.ExpectedRotatedFiles`。比较与验证、修复使用同一把锁；集合变化会在
任何写入前返回 `CONFLICT`。

这里提供的是本地防篡改证据，并非外部信任锚。它能发现没有 HMAC 密钥的攻击者
编辑、删除、重排记录或只回滚日志；但同一 OS 账户、管理员或 root 一旦取得密钥，
即可重签历史。同时协调回滚日志、密钥与检查点到同一个较旧一致快照，也无法由
本地 HMAC 自行发现。若威胁模型包含这些情况，需要外部不可回滚锚、远程签名，
或独立可信的备份/证明系统。

### 从 v1 迁移

1. 把依赖与全部 import 改为 `github.com/JiangHe12/opskit-core/v2`。
2. 传播所有写输出的 `printer` 方法现在返回的 error。
3. mutation intent/outcome 恢复使用 `AppendRecordWithResult`；
   `indeterminate` 与提交后的错误都属于审计失败，不能当作“记录不存在”重试。
4. 使用 `VerifyResult.HasProblems()` 作为完整严格校验条件；修复和清理必须调用
   core 的锁内 API，不能直接删除轮转文件。
5. Vault 必须配置 HTTPS endpoint；v2 会拒绝明文 HTTP。

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
2. **🤖 `--ticket` 与 `--allow-*` 是由人提供的批准输入。** AI agent 应当把*"这需要批准 X"*抛给它的操作者并停下 —— 绝不能自己编造这些值。受保护上下文会自动把每个操作抬升一档（`EffectiveRisk`）。

RBAC 操作者身份必须由使用方从可信的本机身份源传入；`safety.Authorize`
不会再回退读取环境变量。这不能区分同一 OS 账户下运行的 AI 进程与人工
进程；若需要建立这条边界，必须使用外部签名批准源或独立受保护的操作者账户。

---

## 🧩 注入模型

`opskit-core` 是引擎,从不硬编码领域。每个使用方配置一次共享包,然后用自己的类型使用它们:

- CLI 定义**自己的审计 `Event` 结构**,通过 `audit.AppendRecord` 作为*外来记录(foreign record)*写入 —— `audit` 始终是存储/查询/校验引擎,而每个工具对自己的字段保有完整保真度。
- `safety.Configure`、`audit.Configure`、`credstore.Configure` 注入提示文案、RBAC 提示、审计 API 版本与配置目录、keychain 服务名与加密文件魔数 —— 于是一台引擎不必分叉就能服务四个不同领域。

要做新的 CLI?让它表现得像家族其余成员的完整契约见 **[ONBOARDING.md](ONBOARDING.md)**。

---

## 🏗️ 构建与贡献

```sh
git clone https://github.com/JiangHe12/opskit-core && cd opskit-core
go build ./...
go test -count=1 ./...
gofmt -l .                 # 必须无输出
go vet -tags=integration ./...
go test -race -count=1 ./...
golangci-lint run --timeout=5m
govulncheck ./...
```

`opskit-core` 仅以 Go 模块发布 —— 发布即 git tag（无 npm、无二进制）。每个
语义化导入大版本维护自己的兼容线；v2 有意要求 `/v2` import 路径。逐版本历史见
[CHANGELOG.md](CHANGELOG.md)。

---

## 📄 许可证

[MIT](LICENSE) © 2026 JiangHe12
