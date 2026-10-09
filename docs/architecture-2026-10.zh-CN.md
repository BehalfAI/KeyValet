# KeyValet 技术架构（阶段 0 到阶段 3）

- 日期：2026-10-08
- 范围：从现有 v0.1 到阶段 3「iPhone 审批与 Team 完整版」（约 14 个月）；阶段 4 的 enclave 离线执行、远程 MCP 端点、Enterprise 自托管、SCIM、Windows/Android 保留设计章节但标注阶段，不进入前 14 个月的实施计划
- 版本：第二版（2026-10-08），按整体 review 修订：独立开发者版本的阶段顺序；透明代理的客户端认证与 CA 归属；relay 客户端移出特权 helper；KMS 路径的信任声明与 BYO-KMS；grant 范围定义与模板 `summarize`；Ory Hydra 代替自研授权服务器；运行时适配改为 Rust trait + 仅含安装元数据的 manifest
- 首批运行时：Claude Code、Codex、Cursor、Grok
- 配套文档：`docs/strategy-2026-10.zh-CN.md`（市场、定价、路线图）、`docs/product-2026-10.zh-CN.md`（产品规划、用户旅程、UX 规范）、`SECURITY.md`（现有威胁模型）
- 注意：`docs/` 由 GitHub Pages 对外发布，本文无敏感数据，可公开

## 目录

1. 设计原则
2. 现状基线与改动范围
3. 总体架构
4. 核心流水线与插件系统
5. 运行时适配层
6. 策略引擎
7. 审批子系统
8. 密钥、身份与 vault 格式
9. 执行端与路由
10. 服务端：relay、远程 MCP 端点、团队与计费
11. Nitro enclave 执行端
12. 审计
13. 存储后端与导入
14. Team 功能
15. 官方 relay 额度与 CI 离线执行附加项
16. 安全设计要点
17. 可观测性与运维
18. 工程计划：仓库布局、迁移、测试、发布
19. 阶段交付对照
20. 未决问题
- 附录 A：`keyvalet.toml` 示例
- 附录 B：`policy.yaml` 示例
- 附录 C：运行时 manifest 示例
- 附录 D：审批请求与能力令牌示例
- 附录 E：服务端 API 一览
- 附录 F：IPC v4 新增操作

---

## 1. 设计原则

1. **agent 永不持有密钥。** 默认交付方式是代理执行，新增凭据默认 `proxy_only = true`（产品文档 §6.3）；文件路径次之；明文必须显式允许并记审计。
2. **审批绑定真实请求。** 审批的对象是规范化后的请求摘要，不是 agent 写的一句话；一次审批只能执行一次。
3. **本地优先。** 没有服务端也能用全部本机功能；服务端只在远程审批、远程 agent、离线执行时参与。
4. **服务端只见密文。** 所有经过 relay 的内容都是端到端加密的，服务端被攻破只泄露密文和元数据。
5. **一切皆插件。** 运行时、身份、策略、审批、签发、交付、守卫、存储、审计、模板十个扩展点，核心只依赖 trait。
6. **一份核心，三端运行。** 同一套 Rust crate 编译到 Mac/Linux helper、iPhone（UniFFI）、Nitro enclave。
7. **声明式适配运行时。** 新增一个运行时主要是写一份 manifest，不是写代码。
8. **默认不降级。** 默认授权模式保持「按凭据」，T2 敏感操作强制逐次强审批，透明代理 opt-in。
9. **可审计、可复现。** 审计哈希链；enclave 镜像可复现并公开 PCR；发布物签名。
10. **向后兼容。** IPC 协议从 v3 平滑到 v4，现有 TS MCP 前端在迁移期继续工作。
11. **最小可收费路径优先。** 阶段顺序按收入的前置条件排：策略与 Linux → relay 与 Team v1 → 手机 → enclave；不在当前阶段收费链路上的组件只做接口预留。

---

## 2. 现状基线与改动范围

### 2.1 现有组件（v0.1）

| 组件 | 位置 | 说明 |
| --- | --- | --- |
| MCP server（TypeScript） | `src/server/` | stdio MCP，约 30 个 `credential_*` 工具，模板、OAuth 浏览器流程、原生对话框 |
| 特权 helper | `src/helper/`（TS）与 `rust/crates/kv-helper`（Rust 重写） | 由 `sudo` 拉起、root 运行、只通过 stdin/stdout 与 MCP server 通信、stdin 关闭即退出；`verify_root_environment` 校验自身路径与环境 |
| IPC 协议 v3 | `src/shared/protocol.ts`、`rust/crates/kv-ipc` | 24 个操作：ListTypes、CreateType、DeleteType、List、Exists、Info、Get、Set、Delete、SetupProtocol、OauthExchange、OauthDeviceStart、OauthDevicePoll、AccessToken、Totp、Aws、AuditQuery、HttpConfigure、HttpRequest、HttpTest、Grant、Settings、SessionInfo、GatewayOpen；每行一个 JSON，1 MiB 上限；`[GRANT_REQUIRED]` 前缀表示需要授权 |
| 授权门 | `kv-core/auth_gate.rs`、`dispatch.rs` | `AuthorizeGate` trait；`TouchIdSessionGate` 包装 Touch ID 加失败冷却与锁；`SessionAuth` 实现四种授权模式 PerUse / PerCredential / PerSession / Remember |
| vault | `kv-vault` | 加密文件；`CredentialRecord { kind, value, config, secrets, state, generation, http, template, description, attributes }`；`Kind`：Static、Oauth2、GoogleServiceAccount、GithubApp、Jwt、Totp、Aws；审计写入 `audit()` |
| 协议签发 | `kv-protocols` | oauth2、jwt、github_app、google_sa、aws（STS）、totp、http；`setup_protocol` / `access_token` |
| 代理与网关 | `kv-proxy` | `HttpConfig { inject, allowed_hosts, proxy_only, test }`；`InjectRule { headers, query, basic }`；占位符渲染；本地 gateway（`OPENAI_BASE_URL` 方式，peer uid 校验）；响应脱敏 `redact.rs` |
| 平台层 | `kv-platform` | `Authenticator`（Touch ID）、`Confirmer`（原生确认框）、路径与信任校验 |
| Claude Code 插件 | `claude-plugin/` | hooks：`UserPromptSubmit`（用户贴了密钥→提示存入）、`PreToolUse`（Write/Edit/MultiEdit/NotebookEdit/Bash 命中密钥→`permissionDecision: ask`）；skills 与 `/keyvalet:*` 命令 |
| 模板 | `templates/catalog.json`、`n8n-catalog.json` | `CredentialTemplate { id, name, source, kind, fields, inject, test, oauth }` |
| 官网与文档站 | `site/index.html`、`site/guide.md`、`site/install.sh`（GitHub Pages） | 静态落地页、指南、安装脚本；2026-10-09 已从 `docs/` 迁出——`docs/` 曾同时是 Pages 发布根目录又放着本次的全部内部规划文档，等于把它们公开发布了，发现后立即迁移（§18.6） |

### 2.2 本文引入的改动

| 类别 | 改动 |
| --- | --- |
| 保留 | vault 加密文件、七种 Kind、四种授权模式、代理注入与脱敏、模板格式、Claude Code 插件、root helper 的隔离模型 |
| 重构 | `dispatch.rs` 的单体分发拆成流水线 + 注册表；`AuthorizeGate` 升级为 `Approver` trait 并增加请求摘要；`SessionAuth` 的模式逻辑并入策略引擎 |
| 新增 | 策略引擎、审批绑定与一次性 nonce、能力令牌、设备身份密钥、运行时 manifest 与共用 hook 二进制、透明代理、Linux helper、relay 服务端、远程 MCP 端点、iPhone App、enclave 执行端、团队与计费、审计哈希链、存储后端插件、`keyvalet scan` |
| 迁移 | TS MCP server 逐步被 Rust MCP server 取代（§18.3）；IPC v3 → v4 增量扩展（附录 F）；vault 文件格式 v1 → v2（§8.4） |

---

## 3. 总体架构

### 3.1 组件图

```
┌──────────────────────────── 用户机器（Mac / Linux）──────────────────────────────┐
│  Claude Code / Codex / Cursor / Grok                                              │
│     │ MCP(stdio)      │ hooks(JSON)      │ HTTPS_PROXY(带会话 token) / OPENAI_BASE_URL │
│     ▼                 ▼                  ▼                                        │
│  kv-mcp (用户态)   kv-hook (用户态)    kv-proxy 透明代理 / 网关 (用户态，无 CA 私钥) │
│     └────────────────┬┴─────────────────┘                                         │
│                      │ IPC v4（Unix socket，peer-uid 校验）                         │
│                      ▼                                                            │
│  ┌──────── kv-helper（特权：Mac root / Linux 专用用户；不出网、无长连接）────────┐  │
│  │  流水线：Identity → Policy → Approver → Issuer → Deliverer → Guard → Audit   │  │
│  │  插件注册表 · vault（密文）· 设备密钥（SE / TPM2）· 代理 CA 私钥 · 审计哈希链 │  │
│  │  Approver: TouchID | TTY(仅 Quick) | Remote(phone, 阶段 3) | Auto | Team      │  │
│  │  StorageBackend: local | keychain | 1password | infisical | bitwarden        │  │
│  └────────────────────────────┬────────────────────────────────────────────────┘  │
│                               │ IPC（本地）                                        │
│                    kv-relay-client（用户态，唯一出网进程，阶段 2）                   │
└───────────────────────────────┼───────────────────────────────────────────────────┘
                                │ WebSocket + HPKE（端到端）
┌───────────────────────────────▼───────────────────────────────────────────────────┐
│  kv-server（自建 Docker 或 AWS；官方实例美国托管）——只见密文与不透明 id             │
│  relay：设备注册 · 在线表 · 待审批队列(TTL) · 密文存储                   [阶段 2]    │
│  team：组织 · 成员 · 共享凭据(每成员包裹的 CEK) · 策略分发 · 审计同步   [阶段 2]    │
│  billing：Stripe webhook · 权益签发 · 用量计量                           [阶段 2]    │
│  auth：Ory Hydra（OAuth 2.1 AS）+ 登录/同意页；远程 MCP 资源服务器       [阶段 3/4]  │
└──────┬─────────────────────────────┬────────────────────────────┬─────────────────┘
       │ 唤醒(仅 id) [阶段 3]         │ E2E [阶段 3]                │ E2E [阶段 4]
       ▼                             ▼                            ▼
  kv-push（美国托管，持 APNs 密钥，  iPhone App（Swift + UniFFI）    kv-enclave（AWS Nitro）
  只转发 approval id）               两级审批 · SE 密钥 · 配对       远程证明 · HPKE · BYO-KMS
```

### 3.2 进程与信任边界

| 进程 | 运行身份 | 持有什么 | 不持有什么 |
| --- | --- | --- | --- |
| `kv-mcp` | 当前用户 | IPC 连接；工具 schema | 任何密钥 |
| `kv-hook` | 当前用户，由运行时拉起 | 运行时事件 JSON；可向 helper 查询「这是不是已知密钥的指纹」 | 密钥明文；网络 |
| `kv-proxy`（透明代理/网关） | 当前用户 | 会话 token 表；按 host 向 helper 申请的短期叶证书（私钥仅内存） | CA 私钥；凭据明文 |
| `kv-relay-client` | 当前用户 | relay 连接、HPKE 封装、设备公钥目录 | 密钥明文；设备私钥（需要签名时经 IPC 请 helper 代签） |
| `kv-helper` | Mac：root（sudo 拉起）；Linux：系统用户 `keyvalet` | vault 密文、UMK 的设备包裹、设备密钥句柄、代理 CA 私钥、审计链 | 任何出网长连接；服务端长期凭据 |
| `kv-server` | 容器 | 密文、不透明 id、设备公钥、权益、Team 邮箱 | 明文、UMK、CEK、凭据元数据 |
| Ory Hydra | 容器 | OAuth 客户端与令牌 | 任何凭据 |
| `kv-push` | 容器（美国） | APNs 密钥、设备 push token | 审批内容 |
| iPhone App | 用户 | 两把 SE 密钥、UMK 的手机包裹 | 完整 vault（只在需要时拉取单条密文） |
| Web 控制台（浏览器，阶段 2 起） | 用户 | 会话 cookie；阶段 3 起可作为一台设备：WebCrypto 不可导出的 P-256 密钥（IndexedDB） | 完整 vault；Strong 审批能力 |
| 官方网站（静态） | — | 公开内容：文档、定价、`install.sh` 与校验和、PCR 列表、CIMD 文档 | 任何用户数据 |
| `kv-enclave` | Nitro enclave | 每次启动生成的临时密钥；单请求的 CEK | UMK、持久化任何东西 |

注入发生在哪里：代理执行路径上，`kv-proxy`（用户态）只做 TLS 终止与转发，**真正把密钥写进请求头的是 helper**。代理把去掉凭据的请求通过 IPC 交给 helper，helper 注入、发出上游请求、脱敏后把响应交回。网络出口只有两个：helper 发出的上游 HTTPS（注入后的请求）和 `kv-relay-client`；helper 自身不维持任何入站或长连接。

---

## 4. 核心流水线与插件系统

### 4.1 十个扩展点

```
crate kv-core
  pipeline.rs      流水线编排
  registry.rs      插件注册表
  request.rs       规范化请求、摘要
  traits/
    runtime.rs     RuntimeAdapter   —— Rust trait，每个运行时一个实现；manifest 只含安装元数据，见 §5.2
    identity.rs    IdentityProvider —— 设备密钥、agent 身份
    policy.rs      PolicyEvaluator  —— 规则求值
    approver.rs    Approver         —— 人工或自动审批
    issuer.rs      Issuer           —— 把长期凭据换成可用凭据
    deliverer.rs   Deliverer        —— 交付方式
    guard.rs       Guard            —— 请求前/响应后中间件
    storage.rs     StorageBackend   —— 凭据密文来源
    audit.rs       AuditSink        —— 审计落地
    template.rs    TemplateSource   —— 模板来源
```

Trait 签名（Rust，省略错误类型细节）：

```rust
/// 规范化后的一次凭据使用请求（§4.3）
pub struct UseRequest {
    pub id: Ulid,
    pub agent: AgentIdentity,          // 运行时、宿主设备、会话、仓库/cwd
    pub credential: CredentialRef,     // type/name 或 keyvalet:// 引用
    pub action: Action,                // HttpCall{method,url,headers_digest,body_digest} | AccessToken{scope} | Totp | Aws{role} | Read | ExportFile
    pub purpose: Option<String>,       // agent 声明的用途（展示与审计，不参与授权判断）
    pub digest: [u8; 32],              // SHA-256(JCS(canonical fields))，审批绑定对象
    pub nonce: [u8; 16],
    pub issued_at: u64, pub expires_at: u64,
    pub signature: Option<Signature>,  // 由 agent 宿主的设备密钥签名
}

pub struct HookEvent { pub runtime: RuntimeId, pub stage: HookStage, pub tool: Option<String>, pub args: serde_json::Value, pub cwd: Option<PathBuf>, pub session: Option<String> }
pub enum HookDecision { Allow, Ask { reason: String, context: String }, Deny { reason: String }, Rewrite { args: serde_json::Value } }

pub trait RuntimeAdapter: Send + Sync {
    fn id(&self) -> RuntimeId;                                   // claude-code / codex / cursor / grok
    fn install_targets(&self) -> Vec<InstallTarget>;             // 来自 manifest：配置文件路径、合并方式、事件名、命令行
    fn parse_event(&self, stage: HookStage, raw: &[u8]) -> Result<HookEvent>;   // 各家 JSON → 统一事件
    fn render_decision(&self, d: &HookDecision) -> HookOutput;   // 统一决策 → 各家格式（JSON 或退出码）
    fn caps(&self) -> RuntimeCaps;                               // 能否 ask、能否改写参数、覆盖哪些工具
}

pub trait IdentityProvider: Send + Sync {
    fn device_id(&self) -> DeviceId;
    fn sign(&self, msg: &[u8]) -> Result<Signature>;
    fn public_key(&self) -> PublicKey;                  // P-256
    fn agent_identity(&self, ctx: &ClientContext) -> AgentIdentity;
}

pub enum Decision { Auto, Ask, Strong, Deny(String) }
pub struct Tier(pub u8); // T0..T3

pub trait PolicyEvaluator: Send + Sync {
    fn evaluate(&self, req: &UseRequest, cred: &CredentialMeta, grants: &GrantState) -> PolicyOutcome; // { tier, decision, matched_rules, budget_remaining }
}

pub enum ApprovalKind { Quick, Strong }
pub struct Approval { pub request_digest: [u8;32], pub nonce: [u8;16], pub approver: DeviceId, pub kind: ApprovalKind, pub scope: GrantScope, pub signature: Signature }

pub trait Approver: Send + Sync {
    fn capabilities(&self) -> ApproverCaps;  // 支持 Quick/Strong、是否远程、预计延迟
    async fn approve(&self, req: &UseRequest, display: &ApprovalDisplay, kind: ApprovalKind) -> Result<Approval, Denied>;
}

pub trait Issuer: Send + Sync {
    fn kinds(&self) -> &'static [Kind];
    async fn setup(&self, params: SetupParams, store: &dyn StorageBackend) -> Result<CredentialRecord>;
    async fn issue(&self, rec: &CredentialRecord, req: &UseRequest) -> Result<Issued>; // Issued = Header(s) | Token{value,exp} | AwsCreds | TotpCode | Bytes
    async fn refresh(&self, rec: &mut CredentialRecord) -> Result<()>;
}

pub enum DeliveryMode { ProxyExecute, FilePath, EnvInject, Plaintext }
pub trait Deliverer: Send + Sync {
    fn mode(&self) -> DeliveryMode;
    async fn deliver(&self, issued: Issued, req: &UseRequest, guards: &GuardChain) -> Result<DeliveryResult>;
}

pub trait Guard: Send + Sync {
    fn before(&self, req: &mut OutboundRequest) -> Result<()>;   // SSRF、host 白名单、方法限制
    fn after(&self, resp: &mut OutboundResponse, secrets: &[SecretFingerprint]) -> Result<()>; // 脱敏、二进制拒绝
}

pub trait StorageBackend: Send + Sync {
    fn id(&self) -> &str;
    async fn list(&self) -> Result<Vec<CredentialMeta>>;          // 只有元数据
    async fn load(&self, r: &CredentialRef) -> Result<Sealed<CredentialRecord>>; // 密文或后端句柄
    async fn store(&self, r: &CredentialRef, rec: Sealed<CredentialRecord>) -> Result<()>;
    fn capabilities(&self) -> StorageCaps;                        // 可写？支持引用？支持轮换通知？
}

pub trait AuditSink: Send + Sync {
    async fn append(&self, e: AuditEntry) -> Result<()>;
}

pub trait TemplateSource: Send + Sync {
    fn templates(&self) -> Vec<CredentialTemplate>;
}
```

### 4.2 注册表与加载

- **官方插件**：同一 Cargo 工作区，`features` 控制编译；`registry.rs` 在启动时按 `keyvalet.toml` 的 `[plugins]` 节实例化。零 IPC 开销，便于审计。阶段 0–3 全部走这一层。
- **运行时适配器**：不是代码，是 manifest（YAML）。`kv-hook` 读取 manifest 把运行时事件翻译成 `HookEvent`；`kv-mcp` 读取 manifest 决定工具注解与安装路径。
- **第三方插件**（阶段 4 预留）：子进程 + JSON-RPC over stdio（与 MCP、Terraform provider 同模式），接口与 trait 一一对应。不做动态库、不做 WASM。

注册表解析顺序：`keyvalet.toml` 显式声明 > 内置默认。同一扩展点允许多个实例（如两个 StorageBackend、三个 Approver），由流水线按能力和策略选择。

### 4.3 请求生命周期

```
1  接入   RuntimeAdapter 收到调用（MCP 工具 / 代理请求 / CLI），构造 UseRequest
2  身份   IdentityProvider 填 AgentIdentity，用设备密钥签名 digest
3  解析   StorageBackend.load 取元数据（不解密 value）
4  策略   PolicyEvaluator.evaluate → Tier + Decision
           Deny   → 返回 [POLICY_DENIED] 原因，审计
           Auto   → 跳到 7
           Ask    → 5（Quick 即可）
           Strong → 5（必须 Strong）
5  授权状态 GrantState 查已有授权（四种模式）能否覆盖；T2 永远不被 Remember 覆盖
6  审批   选 Approver：本机 Touch ID > TTY > 远程手机 > 团队路由；得到 Approval（绑定 digest+nonce）
7  nonce  记录 nonce 已用；拒绝重放
8  签发   Issuer.issue：解包 CEK → 解密 value → 生成可用凭据（header/token/STS/TOTP）
9  交付   Deliverer：ProxyExecute 默认；Guard.before（SSRF、host）→ 上游请求 → Guard.after（脱敏）
10 审计   AuditSink.append：请求摘要、策略决策、审批人设备、上游状态、trace id
```

错误语义：所有拒绝都带机器可读码（`POLICY_DENIED`、`APPROVAL_DENIED`、`APPROVAL_TIMEOUT`、`DEVICE_OFFLINE`、`BUDGET_EXCEEDED`、`HOST_NOT_ALLOWED`），MCP 层把它们映射为工具错误，`DEVICE_OFFLINE` 附带「CI 离线执行附加项」的提示。

### 4.4 数据模型

| 实体 | 关键字段 | 存放 |
| --- | --- | --- |
| Credential | 现有 `CredentialRecord` + `cek_id`、`sensitivity`（normal/sensitive）、`backend`、`tags` | vault 或后端 |
| Device | `device_id`、`pubkey`(P-256)、`kind`(mac/linux/iphone/android/enclave)、`capabilities`、`enrolled_at`、`umk_wrap` | 本机与 server |
| AgentIdentity | `runtime`(claude-code/codex/cursor/grok)、`runtime_version`、`host_device`、`session_id`、`repo`、`cwd`、`pid` | 内存，写入审计 |
| Grant | `scope = (credential, tier ≤ T1, allowed_hosts, methods, budget)`、`until`、`granted_by`、`mode`；T2 请求永远不被 grant 覆盖，必须逐次绑定摘要（§7.6） | helper 内存与本地文件 |
| Approval | §7 | nonce 库（本地 SQLite） |
| Capability（预授权令牌） | §7.5 | 本地与 server |
| PolicyRule | §6 | 文件 |
| AuditEntry | §12 | 本地哈希链；Team 同步到 server |
| Org / Member / SharedCredential | §14 | server |

---

## 5. 运行时适配层

### 5.1 MCP server（stdio）

- 用 MCP 规范 2026-07-28 的 Rust SDK 重写 `kv-mcp`（迁移路径见 §18.3）。stdio 模式按规范「从环境取凭据」，不实现 OAuth；远程模式见 §10.3。
- 工具集保持现有 `credential_*` 命名；全部加 annotations：`credential_list` / `credential_status` / `credential_audit_log` / `credential_templates` / `credential_list_types` 标 `readOnlyHint`；`credential_delete` / `credential_delete_type` 标 `destructiveHint`；`credential_http_request` / `credential_gateway` 标 `openWorldHint`。
- Touch ID 不可用（无 GUI、SSH 会话）时，用 MRTR：工具返回 `input_required`，让客户端收集确认；仅用于低风险 Quick 审批，Strong 审批必须走手机或本机生物识别。
- per-session 授权绑定 stdio 进程生命周期，不依赖已删除的 `Mcp-Session-Id`。
- 新增工具：`credential_scan`（§13.3）、`credential_policy`（查看当前生效策略）、`credential_pair`（配对手机，§8.3）。

### 5.2 hooks：一个二进制，四个 Rust 适配器，manifest 只管安装

`kv-hook` 是一个小型 Rust 二进制（无网络、无 vault 访问，只有一条 IPC 操作 `HookEvent` 用于查询已知密钥指纹）。每个运行时一个 `RuntimeAdapter` 实现（§4.1），负责把各家 JSON 翻译成统一的 `HookEvent`，再把统一的 `HookDecision` 渲染成各家接受的输出。manifest（附录 C）只记录**安装元数据**：配置文件路径、合并方式、事件名、命令行；不包含字段映射或输出模板。原因：Cursor 只能用退出码拒绝、不能 ask；Codex 的 `PreToolUse` 不覆盖全部 shell 路径；这些语义差异用 Rust 的类型和测试表达，比 YAML 解释器可靠。

```
运行时事件 JSON ──▶ kv-hook --runtime <name> --event <stage>
                      │ adapter.parse_event → HookEvent
                      │ 检测：正则密钥模式 + 向 helper 查询已知密钥指纹（HMAC，不传明文）
                      │ 决策：Allow / Ask / Deny / Rewrite（按 adapter.caps 降级：不能 ask 的运行时降为 deny）
                      └─▶ adapter.render_decision → stdout JSON 或退出码
```

四个运行时的适配要点：

| 运行时 | 配置位置 | 事件 | 决策输出 | 备注 |
| --- | --- | --- | --- | --- |
| Claude Code | 插件 `hooks.json` 或 `settings.json` | `UserPromptSubmit`、`PreToolUse`（Write/Edit/MultiEdit/NotebookEdit/Bash）、`PermissionRequest`、`PostToolUse` | JSON：`permissionDecision` allow/deny/ask/defer、`updatedInput`、`additionalContext` | 现有实现迁移为适配器 |
| Codex | `~/.codex/hooks.json` 或 `config.toml [hooks]` | `PreToolUse`（同名同结构） | 同 Claude Code | 官方文档承认不覆盖全部 shell 路径，文档标注为降级保护 |
| Cursor | `~/.cursor/hooks.json`、`.cursor/hooks.json` | `beforeShellExecution`、`beforeMCPExecution`（2026-10 核实：这两个是仅有的能拒绝的事件；`beforeReadFile` 是只读观察型，拿不到否决权，`preToolUse` 是更泛化的工具级事件，这次没有用它，直接挂在前两个专用事件上） | stdout 一段 JSON：`{"permission": "allow"\|"deny"\|"ask", "user_message", "agent_message"}`；退出码 2 也等价于 deny，但正常路径是 stdout | `permission: "ask"` 虽然在 schema 里但 Cursor 不强制执行，等于静默放行——所以 `kv-hook` 从不输出 `ask`，`tool` 模式里判定为 ask 的场景在这两个事件下一律变成 deny。实现没有做 §4.1 设想的通用 `RuntimeAdapter`/manifest 抽象，而是在 `kv-hook` 里直接加了 `cursor-shell`/`cursor-mcp` 两个专用 CLI 子命令，复用同一套密钥检测核心；`beforeMCPExecution` 的 `tool_input` 是 JSON 字符串而不是对象，且工具名不是 Claude Code 的五种已知形状之一，所以改用递归扫描所有字符串字段的办法，而不是按工具名取字段 |
| Grok | 待核实 | 待核实 | 待核实 | 先 MCP-only 接入；适配器为空实现，有 hook 能力后再填 |

安装：`keyvalet hooks install [--runtime all|claude-code|codex|cursor|grok]` 读 manifest 的安装元数据，检测已安装运行时，写入或合并配置文件，幂等。

hook 能做的三件事：拦截密钥写进文件或命令（现有）；拦截 agent 把 KeyValet 返回的 token 写进文件（现有 `returnedHits`）；把 `.env` 读取类命令改写为占位符建议（阶段 1）。hook 做不到的事写进文档：Codex 的部分 shell 路径、Copilot 的超时放行、嵌套调用。核心保证始终来自 `proxy_only`。

### 5.3 CLI

```
keyvalet run -- <cmd>          以占位符环境变量运行命令，占位符由透明代理替换（§5.4）
keyvalet exec <cred> -- <cmd>  为单条凭据注入到子进程（export_file / env，需审批）
keyvalet proxy [--port]        启动透明代理，打印需要设置的环境变量
keyvalet scan [paths]          扫描 .env、~/.claude.json、.cursor/mcp.json、~/.codex/config.toml，导入并替换占位符
keyvalet hooks install         安装运行时 hooks
keyvalet pair                  显示二维码，配对手机
keyvalet policy show|test      查看生效策略；对一个假想请求做策略求值
keyvalet audit tail|export     审计
keyvalet grant <cred> --hours  预授权（§7.5）
```

### 5.4 透明 HTTPS 代理（阶段 2，opt-in）

- **客户端认证**：`keyvalet run -- <cmd>` 为这次运行生成会话 token，写进子进程的 `HTTPS_PROXY=http://<token>@127.0.0.1:8788`；代理拒绝无 token 或 token 不匹配的连接；token 随会话过期。没有这一步，本机任何进程都能借代理拿到注入。
- **CA 归属**：CA 私钥由 helper 生成并持有；代理启动时请求 helper 为会话绑定的 host 签发短期（24 小时）叶证书，叶证书私钥只在代理进程内存中。用户态恶意软件读不到 CA 私钥，无法对其他流量做 MITM。
- **注入触发只有两种**：请求里出现占位符 `${KEYVALET:type/name}`；或 `keyvalet run --inject <cred>` 显式为本次会话指定凭据与 host。不做「按 host 自动注入」。
- 环境变量（`NODE_USE_ENV_PROXY=1`、`NODE_EXTRA_CA_CERTS`、`SSL_CERT_FILE`、`REQUESTS_CA_BUNDLE`、`AWS_CA_BUNDLE`、`CURL_CA_BUNDLE`、`GRPC_DEFAULT_SSL_ROOTS_FILE_PATH`）由 `keyvalet run` 只对子进程设置，不改用户全局环境。
- 代理只对会话绑定的 host 做 TLS 终止，其余域名 CONNECT 透传不解密；先支持 HTTP/1.1，h2 透传，gRPC 注入放后续。
- 代理不持有明文：匹配到注入的请求后经 IPC 交给 helper 执行（同 gateway 路径）。
- 已知坑写进文档：Octokit 不读代理变量；Go 1.27 设 `SSL_CERT_FILE` 会关闭系统验证器；忽略代理变量的工具需要配合 Claude Code `/sandbox` 的网络隔离。

### 5.5 SDK 网关

现有 `GatewayOpen` 保留：为单条凭据开一个本地 HTTP 端点，SDK 用 `OPENAI_BASE_URL` 指向它，支持流式；peer-uid 校验；URL 当会话 cookie 对待。阶段 1 把它纳入统一的 Deliverer::ProxyExecute。

### 5.6 远程 MCP 端点（阶段 4）

见 §10.4。ChatGPT、Claude App 等云端 agent 通过 OAuth 2.1（Ory Hydra 作授权服务器）连接 `https://<server>/mcp`，工具与本地一致，执行端由路由决定（§9）。

---

## 6. 策略引擎（阶段 1）

### 6.1 风险分级

| 层级 | 默认判定 | 默认决策 |
| --- | --- | --- |
| T0 只读 | GET/HEAD 到 `allowed_hosts`；MCP 工具带 `readOnlyHint`；`credential_list` 等元数据操作 | Auto（审计） |
| T1 写 | POST/PUT/PATCH 到 `allowed_hosts`；`access_token`（非敏感凭据）；TOTP | Ask（受四种授权模式覆盖） |
| T2 敏感 | DELETE；路径匹配 `/admin|/iam|/billing|/payments|/keys|/users|/secrets`；凭据标记 `sensitive`；`credential_get` 明文；`export_file`；AWS STS 换高权限 role；超出预算 | Strong（不被 Remember 覆盖） |
| T3 禁止 | host 不在白名单；私有 IP / 环回 / 链路本地；非 HTTPS；响应为含密钥的二进制 | Deny |

### 6.2 规则来源与合并

```
优先级（高 → 低）：
  org 策略（Team，服务端分发，只能收紧或设下限）
  用户策略（~/.config/keyvalet/policy.yaml）
  仓库策略（<repo>/.keyvalet/policy.yaml，只能收紧，不能放宽）
  内置默认
合并规则：对同一请求取最严格决策；Deny > Strong > Ask > Auto；预算取最小值。
仓库策略来自不可信目录，任何「放宽」条目被忽略并审计。
```

### 6.3 规则语法

见附录 B。匹配字段：`credential`、`host`、`method`、`path`（glob）、`runtime`、`repo`、`time`（时间窗）、`tier`；动作：`auto | ask | strong | deny`；预算：`calls_per_hour`、`calls_per_day`、`bytes_per_day`。

### 6.4 从历史推荐规则

helper 本地统计（不含明文）：某凭据 × host × method 连续 N 次被批准且无拒绝，则在下一次弹窗里提供「以后自动放行只读请求」的选项；接受后写入用户策略。只推荐降到 Ask → Auto 的 T0/T1，不推荐 T2。

---

## 7. 审批子系统

### 7.1 审批展示内容

弹窗（Touch ID 文案、TTY、手机）统一显示：凭据名、agent 声明的用途、**真实请求**、运行时与仓库、风险层级、本次授权范围（这一次 / 这个凭据本会话 / N 小时）。「真实请求」优先用模板的 `summarize` 规则生成人能读的摘要（如 OpenAI：`POST chat/completions · model=gpt-5 · 2.1 KB · 前 80 字…`；GitHub：`DELETE repos/x/y`）；没有规则的模板显示 method、host、path 和 body 大小。哈希只进审计，不给人看。

### 7.2 请求规范化与摘要

```
canonical = JCS(RFC 8785) of {
  v: 1, credential, action.kind, method, host(lowercase), path(normalized), query_keys(sorted),
  body_sha256, headers_digest(仅非凭据头的名字列表), agent.runtime, agent.repo, purpose, nonce, exp
}
digest = SHA-256(canonical)
```
审批签名覆盖 `digest || nonce || decision || scope`。执行端在执行前重算 digest，任何字段改动都会失配。

### 7.3 一次性 nonce

本地 SQLite 表 `nonces(nonce, digest, used_at, exp)`；执行前 `INSERT OR FAIL`；过期清理。远程审批时 nonce 由请求方生成，relay 不参与。

### 7.4 Approver 实现

| 实现 | 阶段 | Quick | Strong | 说明 |
| --- | --- | --- | --- | --- |
| `touchid` | 现有 | 是 | 是 | 包装现有 `touch_id_gate`（冷却、锁） |
| `tty` | 1 | 是 | 否 | Linux 无 GUI：在控制终端打印请求摘要，要求输入确认码；只用于 T0/T1。安全声明：它与 agent 在同一用户会话里，只防 agent 误用，不防 agent 被攻破；Linux 的 Strong 审批只有手机（阶段 3） |
| `remote-phone` | 2 | 是 | 是 | 经 relay 推送到 iPhone；Quick = 锁屏动作（设备解锁门禁，非生物识别密钥）；Strong = 打开 App Face ID |
| `auto` | 1 | — | — | 策略判定 Auto 时产生自签「审批」，审计标记 `auto` |
| `team` | 3 | 是 | 是 | 路由到凭据 owner 的手机；敏感凭据 N-of-M |

选择顺序：本机有 GUI 且凭据未要求手机 → `touchid`；无 GUI → 已配对手机 → `remote-phone`；否则 `tty`（仅 Quick）；Strong 且无可用 Strong Approver → 拒绝并说明。

### 7.5 预授权能力令牌

人不在场（CI、夜间任务）时使用：

```json
{
  "iss": "device:ab12…",          // 签发设备（Mac 或 iPhone）
  "sub": "user:…",
  "act": { "sub": "agent:ci/github/owner/repo" },
  "aud": "executor:*",
  "authorization_details": [{
    "type": "keyvalet:credential",
    "credential": "openai/default",
    "hosts": ["api.openai.com"], "methods": ["POST"], "paths": ["/v1/chat/completions"],
    "budget": { "calls": 500, "per": "24h" }
  }],
  "nbf": 1760000000, "exp": 1760086400, "jti": "01J…"
}
```
ES256 由设备密钥签名；执行端验签、校验范围、扣预算；吊销走本地与服务端的 `revoked_jti` 列表。令牌本身不含任何密钥；它只是「允许用」，密钥仍在 vault 或经 KMS 解包（§11.4）。

### 7.6 grant 范围的精确定义

四种授权模式决定的是「下一次同类请求是否免审批」，范围必须明确，否则绑定摘要只对第一次有效：

```
grant = { credential, max_tier: T1, allowed_hosts(来自凭据 http.allowed_hosts), methods(策略允许的集合), budget, until, mode }
覆盖判定：同一凭据 且 tier ≤ T1 且 host ∈ allowed_hosts 且 method ∈ methods 且 预算未超 → 免审批，审计记 grant_id
T2：永远不被任何 grant 覆盖，每次重新绑定摘要并要求 Strong
Remember：只是把 until 拉长，不改变上面的规则
```
`per_use` 不产生 grant；`per_credential` 产生到本会话结束；`per_session` 对会话内每条凭据各自产生；`remember` 产生到 `until`。弹窗节流：同一凭据 30 秒内的 T0/T1 并发请求合并为一次审批，实现为 `until = now + 30s` 的临时 grant；T2 不合并。

---

## 8. 密钥、身份与 vault 格式

### 8.1 设备身份密钥

| 平台 | 实现 | 说明 |
| --- | --- | --- |
| macOS | Security 框架 Secure Enclave P-256（`kSecAttrTokenIDSecureEnclave`） | 不可导出；签名与 ECDH |
| Linux | TPM 2.0 via `tss-esapi`（P-256 主密钥派生） | 无 TPM 时软件密钥落盘，`0600`，启动时警告并在审计里标记 `software_key` |
| iPhone | 两把 SE P-256：`quick`（`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`，无生物识别 ACL）、`strong`（`.biometryCurrentSet`） | SE 密钥不可 iCloud 同步，每台设备单独注册 |
| enclave | 启动时生成 P-256，公钥进证明文档 | 进程结束即销毁 |

所有签名 ES256；所有端到端加密用 HPKE（RFC 9180）`DHKEM(P-256, HKDF-SHA256) + HKDF-SHA256 + AES-128-GCM`，与 SE 的 ECDH 能力一致。

### 8.2 密钥层级

```
设备密钥 DK_i（每设备）
UMK（随机 256 位）──┬── wrap(DK_mac)      ─┐
                    ├── wrap(DK_iphone)   ─┤ 存本地 + server（密文）
                    ├── wrap(DK_linux)    ─┤
                    └── wrap(K_recovery)  ─┘ K_recovery = Argon2id(恢复码)
CEK_j（每凭据）── AES-256-GCM 包裹 by UMK
凭据密文 ── AES-256-GCM(CEK_j)
```
加设备：已注册设备解开 UMK，为新设备重新包裹，经配对通道（§8.3）传递。吊销设备：删除其包裹并轮换 UMK（重新包裹所有 CEK 的包裹，不必重加密凭据密文）。

### 8.3 配对协议（阶段 2）

```
Mac/Linux                                  iPhone
 生成 pairing_token(一次性, 10 分钟)
 二维码 = { relay_url, pairing_token, DK_pub, device_meta }
                              ── 扫码 ──▶
                                            生成/取出 DK_iphone_pub
                                            POST relay /pair { token, pub, App Attest 断言 }
 relay 转交 ◀──────────────────────────────
 两端各算 safety_code = SHA-256(DK_pub_a || DK_pub_b) 取 6 位十进制
 用户核对两端 6 位码一致后确认
 Mac 用 HPKE 加密 wrap(UMK) 给 DK_iphone，经 relay 送达
```
App Attest 让 relay 能拒绝非官方 App 的注册；自编译 App 用户可关闭该校验（自建 relay 配置项）。

### 8.4 vault 文件格式 v2

现有 `EncryptedFile` 升级为信封格式：

```json
{ "version": 2,
  "umk_wraps": { "<device_id>": { "alg": "HPKE-P256", "ct": "…" }, "recovery": { "alg": "argon2id+aesgcm", "params": {…}, "ct": "…" } },
  "credentials": { "<type/name>": { "cek_wrap": "…", "ct": "…", "meta": { /* 非敏感元数据明文：kind, template, allowed_hosts, created_at */ } } },
  "audit_head": "<hash>" }
```
迁移：首次以 v2 版本启动时读 v1，生成 UMK 与设备包裹，逐条生成 CEK 重加密，写 v2，v1 备份保留 30 天。元数据明文化是为了 `list` 不需解密；但上传服务端前整个文件再加一层 HPKE 加密（含元数据），服务端只见不透明 id 和密文，不知道用户用了哪些服务。

### 8.5 agent 身份

`AgentIdentity` 由 helper 根据 `ClientContext`（现有：客户端名、cwd）和进程信息填充，用宿主设备密钥签名。CI 场景（阶段 2，Team v1）：GitHub Actions 的 OIDC token 作为 agent 身份凭证，由服务端或本地 helper 验证 `iss/aud/sub` 后映射到能力令牌。

---

## 9. 执行端与路由

### 9.1 Executor trait

```rust
pub trait Executor: Send + Sync {
    fn id(&self) -> DeviceId;
    fn caps(&self) -> ExecCaps;          // 可执行的 Action 种类、是否流式、最大时长
    async fn execute(&self, sealed: SealedJob) -> Result<SealedResult>; // SealedJob = HPKE 加密给该执行端的 {UseRequest, Approval/Capability, CEK}
}
```

### 9.2 路由算法（请求方 helper 或远程 MCP 端点执行）

```
if 请求来自本机且本机可执行                 → 本机，不经 relay
elif relay 在线表中有用户的 helper 在线        → 该 helper（审批走本机 Touch ID 或推手机）
elif 手机在前台 且 动作短（非流式、< 20 s 预估） → 手机
elif 团队开通 CI 离线执行附加项 且 enclave 可用 → enclave（阶段 4；审批走手机或能力令牌）
else                                        → DEVICE_OFFLINE（附附加项提示）
```
在线表由 relay 的 WebSocket 心跳维护；路由决策写入审计。

### 9.3 流式与长请求

本机与 enclave 支持流式（SSE/分块）；手机不支持（后台 30 秒上限）；远程 MCP 端点把上游流式响应按块转发给云端 agent。

---

## 10. 服务端：relay、远程 MCP 端点、团队与计费

### 10.1 技术选型

Rust（axum + tokio）、Postgres（自建可用 SQLite）、不依赖 Redis（在线表与队列用 Postgres LISTEN/NOTIFY）、Caddy 或 ALB 做 TLS。单二进制 `kv-server`，功能用 feature 开关：`relay`、`team`、`billing`、`console`（Web 控制台，阶段 2）、`remote-mcp`（阶段 4）。OAuth 2.1 授权服务器**不自研**：用 Ory Hydra（开源，Docker 随 relay 部署），`kv-server` 只实现登录/同意页和资源服务器；OIDC SSO 也通过 Hydra 的联邦登录接入。

### 10.2 用户与账号模型

| 档位 | 身份 | 恢复 |
| --- | --- | --- |
| Free | 纯设备身份：第一台设备注册即创建匿名账号，后续设备经配对加入；无邮箱 | 恢复码 + 任一已注册设备 |
| Team | 邮箱魔法链接创建组织账号，设备签名绑定；成员受邀后用邮箱登录并注册设备 | 同上；owner 可吊销成员设备 |
| 远程 MCP（阶段 4） | Hydra 发放的 OAuth 令牌绑定 {user, agent client_id}；用户登录走设备授权（已配对手机确认） | — |

服务端存的用户数据只有：邮箱（Team）、设备公钥、权益、不透明 blob。

### 10.3 relay（阶段 2）

relay 的客户端是用户态的 `kv-relay-client` 进程，helper 不出网；它需要设备签名时经 IPC 请 helper 代签，自己不持有私钥。

| 功能 | 设计 |
| --- | --- |
| 设备注册 | `POST /v1/devices`：公钥、类型、能力、push token（仅 iPhone）、App Attest 断言 |
| 在线表 | `WS /v1/presence`：`kv-relay-client` 与 App 保持长连接，心跳 30 s；表项 `{user, device, caps, last_seen}` |
| 待审批队列 | `POST /v1/approvals`：请求方上传 HPKE 加密给目标审批设备的 blob + 元数据（仅 id、过期时间、目标设备）；TTL 默认 5 分钟 |
| 审批回执 | `POST /v1/approvals/{id}/reply`：审批设备上传加密给请求方的 Approval |
| 唤醒（阶段 3） | relay 向 `kv-push` 发 `{device_push_token, approval_id}`；`kv-push` 发 APNs（`mutable-content:1`），通知内容由 NSE 从 relay 拉取 blob 后解密展示（30 秒内） |
| 密文存储 | `PUT /v1/blobs/{id}`：vault 密文（含加密后的元数据）、UMK 包裹、共享 CEK 包裹；服务端不知道键名含义 |
| 限流 | 每设备每分钟审批请求数；每用户 blob 容量；Free 的合理使用额度 |

E2E 消息封装：`{ v, from_device, to_device, hpke_enc, ciphertext, sig }`，签名覆盖密文；relay 只校验 `from_device` 签名有效且属于同一用户或同一组织。

### 10.4 远程 MCP 端点（阶段 4）

- 遵循 MCP 授权规范 2026-07-28：`/.well-known/oauth-protected-resource` 发布 PRM；授权服务器为 Ory Hydra（OAuth 2.1 + PKCE，`resource` 参数必填，`iss` 校验）；客户端注册优先 CIMD（在 `keyvalet.dev` 托管客户端元数据文档），Hydra 的 DCR 作为兜底。
- 用户登录：设备授权（扫码用已配对手机确认），不设密码；Team 用户可用 SSO。
- 访问令牌绑定 `{user, agent client_id, scopes}`；每个工具调用变成一个 `UseRequest`，由 §9 路由到执行端；端点本身无密钥。
- 云端 agent 的工具调用通常 60 秒超时，审批延迟需控制在 30 秒内；推荐会话级 grant 或能力令牌，而不是逐次手机审批。
- 流式工具输出经 HTTP 分块转发。

### 10.5 团队模块

见 §14。

### 10.6 计费模块（阶段 2）

- Stripe Checkout 与 Customer Portal；webhook 更新 `entitlements(user|org, tier, seats, addons, valid_until)`。
- 服务端签发**权益令牌**（ES256，7 天有效）给设备，helper 本地缓存并离线校验，网络中断不影响已付费功能 7 天。
- 计量：机器身份数（只用于合理使用判定，不计费）；enclave 执行（阶段 4）由父实例上报按日汇总，超额按 0.5 美元/千次。

### 10.7 部署与托管地

| 模式 | 组成 | 说明 |
| --- | --- | --- |
| A 自建 | `docker compose`: kv-server、hydra、postgres、caddy | 一键脚本；`KV_RELAY_PUSH_GATEWAY` 可改为自建推送或关闭 |
| 官方实例 | 同 A，部署在美国（us-east-1 或美国 VPS），由海外主体运营 | 对美国开发者的信任要求；国内托管即便只存密文也是红旗 |
| B AWS（阶段 4） | kv-server 于 ECS；RDS Postgres；ALB；另有 enclave 执行端（§11） | 客户 BYO 账号可用同一套 Terraform |

`kv-push` 单独部署在美国，只持 APNs 密钥；接口 `POST /wake { push_token, approval_id }`，不接受其他字段。

---

## 11. Nitro enclave 执行端（阶段 4）

### 11.1 组成

```
EC2 c7g.large（父实例，不可信）                 Nitro enclave（kv-enclave）
  relay 客户端（作为 executor 设备在线）           NSM 取证明文档（含临时公钥 + nonce）
  vsock-proxy（白名单：relay、KMS、上游 API）       HPKE 解封 SealedJob → 取 CEK
  kmstool 代理（IMDS 凭据转给 enclave）            解密凭据 → 注入 → TLS 直连上游（经 vsock L4 转发）
  用量上报                                        Guard 脱敏 → 结果 HPKE 加密给请求方 → 销毁 CEK
```
父实例看到的只有 TLS 密文和 enclave 的加密输出。

### 11.2 远程证明

- enclave 启动后请求 NSM 证明文档，`public_key` = 临时 P-256 公钥，`nonce` 由 relay 分发；文档上传 relay。
- 请求方（Mac helper 或 iPhone）在首次向该 enclave 发任务前验证：COSE_Sign1 签名 → 证书链到 AWS Nitro 根证书（固定指纹）→ `PCR0` 在允许列表内 → `public_key` 匹配。验证通过后才用 HPKE 把 CEK 加密给它。
- 实现：Rust 用 `aws-nitro-enclaves-cose` + `x509-cert`；Swift 用 SwiftCOSE + swift-certificates + CryptoKit P384（约 1–2 周工作量）。

### 11.3 可复现构建与 PCR 发布

- 用 kaniko `--reproducible` 或 Nix（monzo/aws-nitro-util）构建 Docker 镜像，`nitro-cli build-enclave` 生成 EIF；同一镜像 PCR 一致。
- 每次发布：在 CI 中构建、记录 `PCR0/1/2`、签名发布到 `https://keyvalet.dev/attestation/pcrs.json` 和 GitHub Release。
- **客户端的 PCR0 允许列表随客户端二进制发布，不在线更新**：更换 enclave 版本必须伴随客户端更新，运营方不能单方面让客户端接受新镜像。阶段 4 评估替代方案：允许列表由 Simvito Limited 与独立审计方两方签名后在线分发。
- debug 模式（PCR 全零）的 enclave 永远不被客户端接受。

### 11.4 两条取密钥路径与信任声明

| 路径 | 场景 | 机制 | 信任的是谁 |
| --- | --- | --- | --- |
| 在线审批 | 手机或 Mac 在场 | 审批设备解包 CEK，HPKE 加密给已验证的 enclave 公钥，随任务下发 | enclave 代码（PCR）+ AWS Nitro；运营方拿不到 CEK |
| 预授权，BYO-KMS（默认） | 设备全离线；客户自己的 AWS 账号持有 KMS key | CEK 由客户 KMS 数据密钥包裹并存于 relay；key policy 条件 `kms:RecipientAttestation:ImageSha384 = <PCR0>`；enclave 调用 `kms:Decrypt` 带 `Recipient{AttestationDocument}`，得到 `CiphertextForRecipient`，只能在 enclave 内解开；任务必须附带有效能力令牌（§7.5） | 客户自己的 AWS 账号治理 + enclave 代码 |
| 预授权，托管 KMS（可选） | 客户没有 AWS 账号 | 同上，但 KMS key 在 Simvito Limited 的 AWS 账号 | **Simvito Limited 的 AWS 账号治理**。账号管理员可以修改 key policy、去掉证明条件、直接解密存在 relay 上的 CEK。这一点在产品内和文档中明示，不写成「只有经证明的 enclave 能解」 |

托管 KMS 的缓解措施：独立 AWS 账号、最少管理员、key policy 变更的 CloudTrail 告警并公开摘要、能力令牌仍由用户设备签名（限制范围与预算）、默认推荐 BYO-KMS。

enclave 永远拿不到 UMK，只拿单任务的单条 CEK。

### 11.5 容量、成本与高可用

- 单实例 c7g.large 可并发数百请求；Auto Scaling 组固定 1–2 台，Spot 优先、按需兜底；按需约 53 美元/月/台，1 年 Savings Plan 约 35–38。
- enclave 无状态，可随时替换；PCR 不变则客户端无需重新信任。
- 上游超时 60 秒；流式最长 10 分钟。

---

## 12. 审计

### 12.1 条目

```json
{ "seq": 1842, "ts": "2026-10-08T03:12:45Z", "prev": "<sha256>", "hash": "<sha256>",
  "event": "use", "credential": "openai/default", "kind": "static",
  "agent": { "runtime": "claude-code", "version": "2.1.3", "repo": "github.com/x/y", "cwd_hash": "…" },
  "action": { "type": "http", "method": "POST", "host": "api.openai.com", "path": "/v1/chat/completions", "body_sha256_8": "a1b2c3d4" },
  "purpose": "Summarize meeting notes", "digest_8": "9f8e7d6c",
  "policy": { "tier": 1, "decision": "ask", "rules": ["user:openai-write"] },
  "approval": { "kind": "quick", "approver": "device:iphone-…", "mode": "per_credential" },
  "executor": "device:mac-…", "upstream": { "status": 200, "bytes": 4120, "ms": 812, "redactions": 0 },
  "trace": { "traceparent": "00-…" } }
```
`hash = SHA-256(prev || JCS(entry without hash))`；每 100 条由设备密钥签一个检查点。明文、token、完整 URL query 值永不入审计。

### 12.2 OTel 映射

导出 OTLP 时映射：`gen_ai.tool.name` ← MCP 工具名；`gen_ai.agent.name` ← runtime；`gen_ai.tool.call.id` ← MCP 调用 id；保留 MCP `_meta.traceparent`。自有字段放 `keyvalet.*` 命名空间。约定仍是 Development，映射层独立成模块便于跟进。

### 12.3 Team 同步

条目用组织审计密钥（HPKE 给组织审计设备集合）加密后上传 server；server 只做存储与按时间导出；SIEM 导出在客户端或组织审计设备上解密后推送（阶段 2 的 Team v1 提供 JSONL 与 OTLP 两种）。

---

## 13. 存储后端与导入

### 13.1 后端

| 后端 | 阶段 | 读 | 写 | 说明 |
| --- | --- | --- | --- | --- |
| `local` | 现有 | 是 | 是 | vault v2 |
| `keychain` | 2 | 是 | 是 | macOS 钥匙串条目；可选 `kSecAttrSynchronizable` 走 iCloud（仅凭据密文，不含 SE 密钥） |
| `onepassword` | 2 | 是 | 否 | `op` CLI；存 `op://vault/item/field` 引用，使用时实时读取，不缓存；需要 1Password 已解锁 |
| `bitwarden` | 3 | 是 | 否 | `bw` CLI，需 `bw unlock` 会话 |
| `infisical` | 2 | 是 | 否 | API；可直接消费其 dynamic secrets |
| `github-oidc` | 2 | 是 | — | CI：OIDC token → 能力令牌，不存任何静态值 |

`StorageBackend.load` 返回 `Sealed`：本地后端返回密文，外部后端返回「句柄」，解密或读取都只在 Issuer 内部发生。

### 13.2 引用语法

`keyvalet://<type>/<name>` 指 vault 内凭据；`op://…` 透传给 1Password 后端；占位符 `${KEYVALET:type/name}` 用于文件与环境变量。

### 13.3 `keyvalet scan`

扫描对象：`.env*`、`~/.claude.json`、`~/.claude/settings*.json`、`.cursor/mcp.json`、`~/.cursor/mcp.json`、`~/.codex/config.toml`、`~/.config/grok/*`（待核实）、shell rc 中的 `export`。
流程：正则 + 模板 `test` 请求验证有效性（需用户确认）→ 原生窗口勾选 → helper 侧写入 vault → 原文件替换为占位符 → 复用 `delete_source_file` 的确认流程删除备份。明文不经过 MCP 与模型上下文。

---

## 14. Team 功能

### 14.1 Team v1（阶段 2，不依赖手机）

| 功能 | 设计 |
| --- | --- |
| 组织与成员 | 邮箱魔法链接创建组织；表 `orgs`、`members(role: owner/admin/member)`、`devices`；邀请链接；成员注册设备 |
| 共享凭据 | 凭据密文由 owner 上传 relay；CEK 用每个被授权成员的设备公钥各包裹一份；成员在自己的 Mac/Linux 上用本机 Touch ID / TTY 审批使用；移除成员即删除其包裹并轮换 CEK |
| 新增成员时的 CEK 包裹 | 二选一（阶段 2 定）：A 任一在线持有者设备确认后重新包裹，零知识但有摩擦；B 组织托管设备（一台常驻 helper）持有 org CEK 并代为包裹，低摩擦但它持有密钥，需在产品里明示。默认 A，B 作为 Team 完整版选项 |
| 组织策略 | admin 维护 policy 文件，服务端签名分发；成员 helper 作为最高优先级合并（只能收紧） |
| CI 身份 | GitHub Actions OIDC → server 校验 → 发能力令牌（范围由 org 策略限定）→ 成员在线设备或自建执行端执行；CI 中无静态密钥 |
| 审计导出 | 条目加密给组织审计设备集合；导出 JSONL / OTLP |
| 计费 | 按席位；机器身份不限量（合理使用） |

### 14.2 Team 完整版（阶段 3）

| 功能 | 设计 |
| --- | --- |
| 审批路由 | 共享凭据的 T1/T2 请求推送到 owner 或指定审批人的手机 |
| N-of-M | `sensitive` 凭据需 2/3 等多人审批，Approval 聚合后才可执行 |
| Linux / CI 的 Strong 审批 | 走手机 |
| SSO | OIDC（Okta、Entra、Google）经 Ory Hydra 联邦；SAML 视设计合作伙伴需求（阶段 4） |
| 90 天加密审计留存 | 服务端只存密文 |
| 凭据轮换 | 模板增加轮换端点，定期换上游 API key 并同步给成员（阶段 3 末或阶段 4） |

### 14.3 附加项：CI 离线执行（阶段 4）

见 §11 与 §15。

---

## 15. 官方 relay 额度与 CI 离线执行附加项

- Free 用户使用官方 relay 的合理使用额度：3 台设备、每月 2,000 次远程审批、待审批保留 7 天；超出时提示加入 Team。
- Team：托管 relay 不限额度；密文跨设备同步；完整版含 90 天加密审计留存。
- CI 离线执行附加项（阶段 4）：设备全离线时在 enclave 执行；默认 BYO-KMS；0.5 美元/千次计量，每席位每月含 2,000 次；`DEVICE_OFFLINE` 错误提示开通该附加项。
- 不设个人 Cloud SKU；个人用户的离线需求用自建 relay 或加入一个 Team 解决。
- 数据驻留：官方 relay 在美国；审计与密文均为用户密钥加密，服务端无法读取。

---

## 16. 安全设计要点

| 主题 | 设计 |
| --- | --- |
| 特权 helper | 保留现有 root（Mac）模型与 `verify_root_environment`；Linux 用系统用户 `keyvalet` + systemd 服务 + Unix socket，连接方 peer-uid 校验；阶段 1 把 Mac 也迁到 Unix socket，stdin/stdout 模式保留一个版本周期。helper 不出网、不维持长连接，relay 客户端在用户态 |
| 重放与篡改 | digest 绑定 + 一次性 nonce + 过期；审批签名覆盖决策与范围；grant 范围精确定义（§7.6） |
| 时钟 | 令牌与审批允许 ±5 分钟偏差；enclave 以 relay 时间为准 |
| SSRF | Guard.before：只 HTTPS、拒绝私有/环回/链路本地地址、DNS 重绑定防护（解析后再比对）、只允许 `allowed_hosts` |
| 脱敏 | 现有 `redact.rs`（多种编码变体）+ 二进制含密钥即拒绝；脱敏指纹用 HMAC 比对，不在用户态保存明文 |
| 透明代理 | 会话 token 认证；CA 私钥在 helper，代理只拿短期叶证书；只有占位符或显式 `--inject` 才注入；用户可随时 `keyvalet proxy uninstall-ca` |
| 丢手机 | 恢复码 + 其他已注册设备；server 侧吊销设备公钥；UMK 轮换 |
| 吊销 | 设备、能力令牌 `jti`、共享凭据成员三类吊销列表；helper 每 10 分钟同步，离线时沿用缓存并缩短令牌有效期 |
| 供应链 | Rust 最小依赖、`cargo-deny`、`cargo-vet`；发布物 Sigstore 签名；安装脚本校验哈希；enclave 可复现构建；拒绝不受信任的 Node 运行时（现有） |
| hook 绕过 | 文档明示：Codex 部分 shell 路径、Copilot 超时放行、嵌套调用；核心保证是 `proxy_only` |
| 服务端被攻破 | 攻击者获得密文、设备公钥、元数据（设备在线时间、审批次数、Team 邮箱）；无法伪造审批（无设备私钥）、无法解密；补救：轮换 relay 令牌，必要时轮换 UMK |
| KMS 托管路径 | 信任的是运营方 AWS 账号治理，产品内明示；默认 BYO-KMS；独立账号、变更告警、公开摘要 |
| PCR 允许列表 | 随客户端二进制发布，不在线单方更新 |
| 恶意用户态进程 | 现有 SECURITY.md 结论不变：以用户身份运行的恶意软件可以触发审批；绑定真实请求的展示和模板 `summarize` 降低误批概率 |
| TTY 审批 | 与 agent 同一用户会话，只防误用不防攻破；仅 T0/T1 |

---

## 17. 可观测性与运维

- helper 与 server 的日志不含密钥、不含完整 URL；默认 `info`。
- server 指标：在线设备数、待审批队列长度、审批中位延迟、推送失败率、enclave 任务成功率与时长、Stripe webhook 失败。
- 健康检查：`/healthz`（存活）、`/readyz`（DB、推送网关可达）。
- 备份：Postgres 每日快照（全部为密文与元数据）；enclave 无状态。
- 事件响应：公开 `SECURITY.md` 的报告渠道；关键事件（relay 入侵、PCR 泄露）预案：吊销 PCR 允许列表、强制客户端更新。

---

## 18. 工程计划

### 18.1 仓库布局（目标）：单一仓库

官方网站、Web 控制台、iOS/Android App、服务端、helper、插件、模板、部署脚本全部放在同一个仓库里，按目录分语言，按路径过滤 CI。

```
keyvalet/                         monorepo
  rust/                           Cargo workspace：全部 Rust crate
    crates/
      kv-core        流水线、注册表、traits、策略引擎、审批、能力令牌
      kv-vault       vault v2、密钥层级
      kv-protocols   Issuer 实现（现有）
      kv-proxy       Deliverer/Guard：gateway、透明代理、脱敏、SSRF
      kv-ipc         IPC v4
      kv-platform    设备密钥（SE/TPM2/软件）、Authenticator、trust
      kv-touchid     Mac 生物识别进程（现有）
      kv-helper      特权守护进程
      kv-mcp         Rust MCP server（阶段 2 起替代 TS）
      kv-hook        共用 hook 二进制 + 四个 RuntimeAdapter + manifests/（安装元数据）
      kv-cli         keyvalet 命令行
      kv-relay-client relay 协议、HPKE 封装、配对；唯一出网的用户态进程
      kv-audit       哈希链、OTel 映射、导出
      kv-storage-*   keychain / onepassword / infisical / bitwarden
      kv-server      axum 服务端：relay、team、billing、console（Web 控制台，askama + htmx，静态资源 rust-embed 内嵌）、remote-mcp
      kv-push        推送网关
      kv-enclave     enclave 二进制
      kv-ffi         UniFFI 绑定 → 生成 Swift / Kotlin 包
  ee/                源码可见商业许可：kv-team、kv-billing、控制台团队页；经 kv-server 的 feature 编译进同一二进制（边界见开源规划 §1）
  apps/
    ios/             SwiftUI App（Xcode 工程，SwiftPM 依赖由 kv-ffi 生成的 KeyValetCore 包）
    android/         Kotlin App（阶段 4，同样经 UniFFI）
    macos/           可选：菜单栏状态与设置（阶段 3 以后）；Touch ID 对话框仍在 kv-touchid
    web/             Web 控制台的前端资产（TypeScript：WebCrypto 设备密钥、HPKE、htmx 扩展），构建产物嵌入 kv-server
  site/              官方网站（Zola 静态站，zh/en）：落地页、文档、定价、对比、下载、安全页、博客、模板目录、attestation/pcrs.json、CIMD 文档
  claude-plugin/     Claude Code 插件（hooks → kv-hook、skills、commands）
  templates/         模板目录（helper 与官网模板页共用同一份 JSON）
  deploy/            docker-compose、Terraform（EC2 + enclave + KMS）、Nix/kaniko 构建、Caddyfile
  scripts/           install.sh、uninstall.sh、release 脚本（现有）
  docs/              设计文档（本文、战略文档、ADR）；网站内容迁到 site/ 后，GitHub Pages 的源改为 Actions 构建产物
  .github/workflows/ 按路径过滤：rust、ios、android、site、server-image、enclave
  justfile           跨语言任务入口（build、test、release、site）
```

现状到目标：`src/`（TS）在迁移期保留；`docs/index.html`、`docs/guide.md`、`docs/install.sh` 已迁到 `site/`，`docs/` 现在只留设计文档（这也是 GitHub Pages 的发布路径从 `docs/` 改成 `site/` 的直接原因，见上）；`marketing/` 的文案以后并入 `site/content/`。

### 18.2 IPC v4

在 v3 的 24 个操作上增量新增（附录 F），协议版本号 4；helper 同时接受 v3 客户端一个版本周期。

### 18.3 从 TS 到 Rust 的迁移（strangler）

1. 阶段 0：TS MCP server 不动；Rust helper 替换 TS helper（已在进行），IPC v3 兼容。
2. 阶段 1：**功能先于重写**。策略引擎、审批绑定、Linux 都在 Rust helper 里实现，TS server 只透传新的 IPC 操作；hook 改为 `kv-hook` + 适配器，`claude-plugin/hooks/run.sh` 只做转发。
3. 阶段 2：`kv-mcp`（Rust）上线，与 TS server 功能对齐后，安装脚本默认切到 Rust；TS 保留一个版本。
4. 阶段 3：TS 代码移出默认构建。

### 18.4 测试策略

- 单元：策略合并、digest 规范化、nonce、HPKE 封装、脱敏模糊测试（`cargo-fuzz`）。
- 集成：假运行时（录制的 Claude Code/Codex/Cursor hook 事件回放）、假上游（wiremock）、假 relay。
- 端到端：真实运行时的 smoke（CI 中启动 Claude Code/Codex/Cursor CLI 跑脚本）；真实 Nitro 用 nightly job。
- 安全：SSRF 用例表、重放用例、授权模式矩阵（4 模式 × 4 层级）。

### 18.5 发布

- Mac：公证的 pkg 与 `install.sh`；Linux：静态二进制 + `.deb/.rpm`；iOS：App Store；server：容器镜像（签名）；enclave：EIF + PCR 公告；网站：GitHub Pages。
- 版本兼容矩阵写进文档：MCP server ↔ helper ↔ App ↔ server ↔ 控制台。

### 18.6 官方网站（`site/`，阶段 0 改版）

| 页面 | 内容 | 来源 |
| --- | --- | --- |
| 首页 | 一句话定位、60 秒演示、三条差异点、安装命令 | `marketing/` 文案 |
| Why | 事故复盘系列（s1ngularity、Comment and Control、GhostSplice、CVE-2026-21852、DuneSlide）各对应一个控制点 | 博客 |
| 对比 | vs 1Password、vs Infisical Agent Vault、vs 直接用 .env | 战略文档 §3 |
| 定价 | Free / Team v1 / Team 完整版 / 附加项；FAQ | 战略文档 §8 |
| 文档 | 安装、概念、全部工具、模板、网关、CLI、策略语法、自建 relay、hooks 安装 | 现有 `guide.md` 迁入 |
| 模板目录 | 从 `templates/catalog.json` 构建时生成，每个服务一页 | 共用数据 |
| 安全 | 渲染 `SECURITY.md`、威胁模型、PCR 允许列表、可复现构建说明、漏洞报告渠道 | 仓库文件 |
| 下载 | `install.sh`、各平台二进制、sha256、Sigstore 签名 | release 产物 |
| 法律 | 隐私政策、服务条款、数据处理说明（Team 需要） | — |
| 机器可读 | `/attestation/pcrs.json`（签名）、`/oauth/client.json`（CIMD，阶段 4）、`/.well-known/security.txt` | CI 生成 |

技术：Zola（Rust 生态静态站生成器，零 Node 依赖），多语言 zh/en，内置搜索索引；GitHub Actions 构建后发布到 GitHub Pages（现有托管），自定义域名；阶段 2 起同一产物也部署到美国 VPS 的 Caddy 作为镜像。网站不含任何用户数据和后端逻辑；定价页的「开始使用」跳转到控制台。

### 18.7 Web 控制台（`kv-server` 的 `console` feature + `apps/web/`，阶段 2 起）

Team v1 的管理面，服务端渲染，不引入 SPA 框架：askama 模板 + htmx，少量 TypeScript 只做 WebCrypto。安全基线：同站 cookie、CSRF token、严格 CSP、无内联脚本。

| 功能 | 阶段 | 说明 |
| --- | --- | --- |
| 登录 | 2 | 邮箱魔法链接 + 设备确认；无密码 |
| 组织与成员 | 2 | 创建组织、邀请链接、角色、移除成员（触发 CEK 轮换任务，由在线设备执行） |
| 席位与账单 | 2 | 显示权益与用量；「管理账单」跳 Stripe Customer Portal |
| 策略 | 2 | org `policy.yaml` 编辑器，服务端校验（只能收紧）、版本历史、签名分发 |
| 设备 | 2 | 列表、最后在线、吊销 |
| 共享凭据 | 2 | 只有元数据：名称、后端、持有者、授权成员；「共享给成员」在控制台发起，加密包裹由 owner 的在线设备完成；控制台永远不见明文和 CEK |
| 审计 | 2 | 元数据统计（次数、设备、时间）与导出任务；条目内容是加密的，控制台此时不能解密 |
| 浏览器作为设备 | 3 | WebCrypto 生成不可导出的 P-256 密钥存 IndexedDB，经手机配对注册为一台设备后：解密审计条目、做 Quick 审批（不能 Strong）、查看共享凭据的解密元数据 |
| SSO 设置 | 3 | 对接 Ory Hydra 的联邦登录（OIDC） |
| 附加项与 enclave 状态 | 4 | CI 离线执行开通、BYO-KMS 配置、当前 PCR |

### 18.8 客户端 App（`apps/`）

| App | 阶段 | 技术 | 共享核心 |
| --- | --- | --- | --- |
| iOS | 3 | SwiftUI；Secure Enclave 两把密钥；App Attest；Notification Service Extension；二维码配对 | `kv-ffi` 经 UniFFI 生成 Swift 包：HPKE、审批签名与摘要校验、配对、审计解密、能力令牌签发 |
| Android | 4 | Kotlin；StrongBox + BiometricPrompt；Key Attestation | 同一 `kv-ffi` 生成 Kotlin 包 |
| macOS 菜单栏 | 3 以后，可选 | SwiftUI 菜单栏：状态、授权模式切换、最近审批、配对入口 | 经 IPC 与 helper 通信；Touch ID 对话框仍由 `kv-touchid` 独立进程负责 |

规则：所有加密与协议逻辑只在 Rust 里写一次，App 不自行实现 HPKE、摘要或签名格式；UniFFI 接口在 `kv-ffi` 里有契约测试，Swift/Kotlin 侧只做 UI 与系统 API（SE、Keystore、推送）。

### 18.9 单仓库的构建与发布流水线

- 任务入口 `justfile`：`just build`、`just test`、`just site`、`just release <version>`。
- CI 按路径过滤：`rust/**` 跑 cargo test 与 clippy；`apps/ios/**` 用 macOS runner + fastlane 跑单测与 TestFlight；`site/**` 用 Zola 构建并发布 Pages；`deploy/**` 校验 Terraform 与 compose；`rust/crates/kv-enclave/**` 跑可复现 EIF 构建并比对 PCR。
- Rust 交叉编译：macOS arm64/x86_64、Linux x86_64/arm64（musl 静态）；server 与 push 的容器镜像签名。阶段 2 起 Rust 发布物可复现（固定工具链版本、`SOURCE_DATE_EPOCH`、去除构建路径），CI 双机构建比对哈希。
- 版本：仓库根目录单一 `VERSION`，所有产物同号；兼容矩阵在 `docs/compat.md`。
- release 脚本：生成 `install.sh` 的 sha256 与 Sigstore 签名、更新 `site/static/attestation/pcrs.json`、推送 GitHub Release。

---

## 19. 阶段交付对照

| 阶段 | 新增模块 | 关键接口 |
| --- | --- | --- |
| 0（0–1 月）发布 | 审批展示真实请求 + digest 绑定（Touch ID 文案）；工具 annotations；`kv-hook` 覆盖 Claude Code / Codex，Cursor 适配器原型，Grok 核实；`keyvalet scan`；SDK 升级到 2026-07-28；官网改版（定价、对比、安全页），网站内容从 `docs/` 迁到 `site/` | `UseRequest`、`Approval`、`RuntimeAdapter`、manifest（安装元数据） |
| 1（1–4 月）策略与 Linux | 策略引擎；grant 范围定义；模板 `summarize`；Linux helper（系统用户、Unix socket、TPM2 可选、TTY 仅 Quick）；`keyvalet hooks install --all`；审计哈希链；能力令牌（Mac 签发，CI 使用） | `PolicyEvaluator`、`Approver` 升级、IPC v4 |
| 2（4–8 月）relay 与 Team v1 | `kv-server`（relay、team、billing）+ Ory Hydra + Docker 部署，官方实例美国托管；`kv-relay-client`；vault v2 与多设备 UMK 包裹；Team v1；Stripe 与权益令牌；Web 控制台 v1（组织、成员、账单、策略、设备）；透明代理 opt-in（会话 token、CA 在 helper）；`kv-mcp` Rust 版；`keychain`、`onepassword`、`infisical`、`github-oidc` 后端 | relay 协议、HPKE 封装、`StorageBackend`、`Deliverer`、团队数据模型 |
| 3（8–14 月）iPhone 与 Team 完整版 | iPhone App 上架（两级审批、配对、NSE、App Attest）；`kv-push`；控制台「浏览器作为设备」（审计解密、Quick 审批）；`remote-phone` Approver；审批路由、N-of-M；Linux / CI 手机强审批；OIDC SSO；`bitwarden` 后端；第三方安全审计 | 配对协议、推送唤醒、N-of-M 聚合 |
| 4（14–24 月）CI 离线执行、远程 MCP、Enterprise | enclave 执行端（BYO-KMS 默认、托管 KMS 信任声明、可复现 EIF、客户端固定 PCR 列表）；远程 MCP 端点（Hydra 作 AS、PRM、CIMD）；Enterprise 自托管 Terraform；SCIM；Okta Cross-App Access；Vault / OpenBao 后端；凭据轮换；Android App；Windows 审批端；macOS 菜单栏（可选） | `Executor`、KMS 条件策略、远程 MCP 资源服务器 |

---

## 20. 未决问题

1. **Grok**：xAI 编码 agent 的 MCP 与 hook 能力未核实；按 MCP-only 接入，manifest 留空。需要在阶段 0 补一次调研。
2. **Linux 的交互审批**：TTY 确认码的安全性弱于生物识别，只允许 Quick；是否接受依赖 `pinentry` 一类 GUI 工具待定。
3. **Mac helper 从 stdin/stdout 迁到 Unix socket** 的时机：涉及 launchd 与 `sudo` 流程改造，建议阶段 1 末。
4. **iOS 端 Nitro 证明验证库**：无现成库，需自行拼装并做互操作测试。
5. **SAML**：实现成本高，阶段 3 优先 OIDC，SAML 视设计合作伙伴需求。
6. **KMS 成本与配额**：预授权路径每次解密一次 KMS 调用，按量计费可忽略，但需监控节流。
7. **FTO**：IETF user-mediated delivery 草案声明专利申请中；KeyValet 为代理端模型，仍需排查权利要求范围。
8. **透明代理与 HTTP/2、gRPC**：阶段 2 先支持 HTTP/1.1 终止，h2 透传不解密；gRPC 注入放后续。
9. **Team 新成员的 CEK 包裹**：在线持有者确认（零知识、有摩擦）还是组织托管设备（低摩擦、持有密钥），阶段 2 由设计合作伙伴反馈决定。
10. **商标**：KeyValet 的商标检索与潜在冲突，阶段 0 完成。

---

## 附录 A：`keyvalet.toml` 示例

```toml
[core]
default_grant_mode = "per_credential"
strong_tier = 2            # T2 及以上强制 Strong

[plugins]
identity  = ["secure-enclave"]              # 或 "tpm2" / "software"
approvers = ["touchid", "remote-phone", "tty", "auto"]
issuers   = ["static", "oauth2", "jwt", "github-app", "google-sa", "aws", "totp"]
deliverers = ["proxy", "file", "env"]       # 不含 "plaintext" 即禁止 credential_get 明文
guards    = ["ssrf", "redact"]
storage   = ["local", "onepassword"]
audit     = ["local-chain", "otlp"]
templates = ["catalog", "n8n", "custom:~/.config/keyvalet/templates"]

[runtimes]
enabled = ["claude-code", "codex", "cursor", "grok"]

[relay]
url = "https://relay.example.com"           # 自建或官方
push_gateway = "https://push.keyvalet.dev"  # 可设为 "" 关闭推送

[proxy]
transparent = false                          # opt-in
listen = "127.0.0.1:8788"
require_session_token = true                 # 不可关闭：无 token 的连接一律拒绝
leaf_cert_ttl = "24h"                        # 叶证书由 helper 签发，CA 私钥不出 helper

[audit.otlp]
endpoint = "http://localhost:4318"
```

## 附录 B：`policy.yaml` 示例

```yaml
version: 1
defaults:
  tier_decisions: { T0: auto, T1: ask, T2: strong, T3: deny }
rules:
  - name: openai-readonly-auto
    match: { credential: "openai/*", host: "api.openai.com", method: [GET, HEAD] }
    decision: auto
  - name: github-delete-strong
    match: { credential: "github/*", method: [DELETE] }
    decision: strong
  - name: payments-sensitive
    match: { host: "api.stripe.com", path: ["/v1/charges*", "/v1/payouts*"] }
    tier: T2
  - name: ci-budget
    match: { runtime: "ci/*", credential: "openai/default" }
    budget: { calls_per_day: 500 }
  - name: night-block
    match: { time: { not_between: ["09:00", "23:00"], tz: "Asia/Shanghai" }, tier: [T2] }
    decision: deny
```
仓库级策略只允许 `decision` 比默认更严格、`budget` 更小、`tier` 更高；违反的条目被忽略并审计。

## 附录 C：运行时 manifest 示例

manifest 只含安装元数据；事件解析与决策渲染在对应的 `RuntimeAdapter`（Rust）里实现。

```yaml
# kv-hook/manifests/claude-code.yaml
runtime: claude-code
detect:
  paths: ["~/.claude/settings.json", "~/.claude.json"]
install:
  target: "~/.claude/settings.json"
  merge: json
  hooks:
    - event: PreToolUse
      matcher: "Write|Edit|MultiEdit|NotebookEdit|Bash"
      command: "kv-hook --runtime claude-code --event pre-tool"
      timeout: 10
    - event: UserPromptSubmit
      command: "kv-hook --runtime claude-code --event prompt"
mcp:
  target: "~/.claude.json"
  entry: { command: "kv-mcp", args: [] }
```

```yaml
# kv-hook/manifests/cursor.yaml
runtime: cursor
install:
  target: "~/.cursor/hooks.json"
  merge: json
  hooks:
    - event: beforeShellExecution
      command: "kv-hook --runtime cursor --event shell"
    - event: preToolUse
      command: "kv-hook --runtime cursor --event pre-tool"
mcp:
  target: "~/.cursor/mcp.json"
  entry: { command: "kv-mcp", args: [] }
```

Codex 的 manifest 与 Claude Code 几乎相同（目标文件 `~/.codex/hooks.json`，MCP 写入 `~/.codex/config.toml`）；Grok 的 manifest 只有 `runtime: grok` 与 `mcp` 节，hook 部分待核实后补。

## 附录 D：审批请求与能力令牌示例

审批请求（展示给人）：
```
KeyValet 请求使用凭据 openai/default（T1 写操作）
用途（agent 声明）：Summarize meeting notes
真实请求：POST api.openai.com /v1/chat/completions  body 2.1 KB  sha256 a1b2c3d4
来源：claude-code 2.1.3 · github.com/x/y · 本机
授权范围：[这一次] [这个凭据，本会话] [记住 4 小时]
```
能力令牌见 §7.5。

## 附录 E：服务端 API 一览

| 方法 | 路径 | 用途 | 认证 |
| --- | --- | --- | --- |
| POST | `/v1/devices` | 注册设备 | 配对令牌或已注册设备签名 |
| WS | `/v1/presence` | 在线与消息通道 | 设备签名挑战 |
| POST | `/v1/approvals` | 提交加密审批请求 | 设备签名 |
| POST | `/v1/approvals/{id}/reply` | 审批回执 | 设备签名 |
| GET | `/v1/approvals/{id}` | NSE 拉取 blob | 设备签名 |
| PUT/GET | `/v1/blobs/{id}` | 密文存储 | 设备签名 |
| POST | `/v1/accounts/magic-link`、`/v1/accounts/verify` | Team 邮箱账号（阶段 2） | 邮件令牌 + 设备签名 |
| GET | `/.well-known/oauth-protected-resource` | PRM（阶段 4） | 公开 |
| — | `/oauth2/auth`、`/oauth2/token`、`/.well-known/openid-configuration` | 由 Ory Hydra 提供（阶段 3 SSO、阶段 4 远程 MCP） | — |
| POST | `/mcp` | 远程 MCP（Streamable HTTP） | Bearer |
| POST | `/v1/orgs`、`/v1/orgs/{id}/members`、`/v1/orgs/{id}/shares` | 团队 | 成员设备签名 + 角色 |
| GET | `/v1/orgs/{id}/policy` | 签名的 org 策略 | 成员 |
| POST | `/v1/billing/webhook` | Stripe | Stripe 签名 |
| GET | `/v1/entitlements` | 权益令牌 | 设备签名 |
| POST | `/v1/attestation` | enclave 上传证明文档 | 执行端设备签名 |
| GET | `/attestation/pcrs.json` | 当前允许的 PCR 列表 | 公开，签名 |

## 附录 F：IPC v4 新增操作

| 操作 | 说明 |
| --- | --- |
| `PolicyEvaluate` | 对给定请求返回 tier/decision（`keyvalet policy test` 与 hook 使用） |
| `ApprovalRequest` / `ApprovalStatus` | 发起远程审批、查询状态 |
| `CapabilityIssue` / `CapabilityRevoke` | 能力令牌 |
| `PairStart` / `PairComplete` | 配对 |
| `DeviceList` / `DeviceRevoke` | 设备管理 |
| `HookEvent` | hook 上报事件并查询已知密钥指纹（HMAC） |
| `ProxyRegister` | 透明代理注册与会话 |
| `Scan` | 扫描与导入 |
| `BackendList` | 存储后端与凭据来源 |
| `AuditVerify` | 校验哈希链 |
