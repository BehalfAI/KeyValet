# KeyValet 产品规划（阶段 0 到阶段 3）

- 日期：2026-10-08
- 决策更新：2026-10-09，平台支持与密钥保护顺序已确认，见 §1.4；macOS 硬件 vault 已实现并完成本机迁移，其他平台仍为规划，现有能力以 `SECURITY.md` 为准。
- 配套：`docs/strategy-2026-10.zh-CN.md`（市场、定价、路线图）、`docs/architecture-2026-10.md`（技术架构）
- 范围：产品定义、用户旅程、功能清单与验收标准、UX 规范、指标、发布节奏；阶段 4（enclave、远程 MCP、Enterprise）只列非目标和预留
- 主体与品牌：Simvito Limited 运营，产品 KeyValet，主域名 keyvalet.dev

## 目录

1. 产品定义
2. 用户画像与任务
3. 核心用户旅程
4. 产品面
5. 功能清单与验收标准（按阶段）
6. UX 规范
7. 审批疲劳：产品对策与量化目标
8. 模板与集成策略
9. Free 到 Team 的升级路径
10. 指标体系
11. 非目标
12. 发布节奏与版本
13. 用户研究与反馈机制
14. 文档与内容的信息架构
15. 产品层面的风险与开放问题
- 附录 A：审批弹窗文案规范与示例
- 附录 B：面向 agent 的错误码与提示
- 附录 C：MCP 工具描述规范
- 附录 D：设计合作伙伴访谈提纲

---

## 1. 产品定义

### 1.1 一句话

KeyValet 让 AI agent 替你用 API key、OAuth 账号和私钥，却永远拿不到它们：每次使用都经过策略、你的指纹或人脸、短期签发和代理注入，并留下带用途的审计。

- 给开发者的话：「你的 agent 永远看不到密钥。」
- 给团队负责人的话：「一个 vault，所有 agent，所有运行时；策略即代码；CI 里没有静态密钥。」
- 和 1Password 的关系：「1Password 管你的登录，KeyValet 管你的 API。」

### 1.2 解决的问题

| 现状 | 后果 | KeyValet 的回答 |
| --- | --- | --- |
| 密钥躺在 `.env`、`~/.claude.json`、`.cursor/mcp.json`、shell 历史里 | 恶意依赖和被注入的 agent 直接读走（s1ngularity、Comment and Control、GhostSplice 都是这条路） | `keyvalet scan` 一键收进 vault，文件里只剩占位符 |
| agent 调 API 时拿着明文 key | prompt injection 一句话就能外泄 | 代理注入：agent 只拿到响应 |
| 「允许 / 拒绝」弹窗只写工具名 | 93% 盲批（业内说法，来源待补） | 弹窗显示真实请求（method、host、path、人能读的摘要）和 agent 声明的用途 |
| OAuth 刷新、JWT、AWS STS、GitHub App 每个都要自己写 | agent 拿到长期凭据 | 内置签发，agent 只拿短期 token |
| 团队里 key 靠聊天工具传 | 没人知道谁在用、用来做什么 | 共享凭据按成员设备加密，审计带用途 |

### 1.3 产品原则

1. **零明文**：录入走原生对话框，使用走代理，导出只给路径；明文出现在聊天或文件里是失败。
2. **每一次弹窗都值得看**：显示真实请求；不值得看的请求由策略自动放行并审计。
3. **默认安全，放宽要指纹**：默认按凭据授权；放宽授权模式需要生物识别；敏感操作不被「记住」覆盖。
4. **本地优先，离线可用**：没有账号、没有服务器也能用全部本机功能。
5. **对 agent 友好**：工具描述、错误信息和提示都为模型写，让 agent 第一次就用对。
6. **一个产品，多个运行时**：Claude Code、Codex、Cursor、Grok 用同一个 vault、同一套策略。

### 1.4 平台支持与密钥保护

**决策日期：2026-10-09；状态：macOS 首版已实现，其他平台按以下顺序推进。** macOS 硬件保护先行，Linux / CI 是下一阶段重点；Windows 原生支持按明确用户需求排期；云端隔离执行首选 AWS Nitro Enclaves + KMS。目标用户、付费触发点与实施顺序保持一致，执行环境按用户需求逐项增加。

| 支持项 | 顺序与范围 | 产品理由 |
| --- | --- | --- |
| macOS Secure Enclave + Touch ID | 当前唯一支持的 macOS vault 模式；安装直接初始化硬件 vault 或迁移旧 vault，停用文件密钥运行模式 | 沿用现有审批体验，不要求云账号；加强 vault 文件被复制后的保护 |
| Linux / CI | 下一阶段优先做调用与身份接入；长期凭证可以留在 Mac 或远程执行端，远程路径依赖配对与 relay；本地 helper 保留兼容路径，TPM 2.0 可选 | 覆盖服务器和自动化场景，不把 TPM 作为安装前置条件，也不要求每台 runner 保存长期凭证 |
| Windows TPM + Windows Hello | 有明确用户或客户需求后排期，覆盖本地保存、系统认证、后台服务、安装与更新 | 扩展桌面覆盖；TPM 密钥保护与 Hello 审批的绑定必须实际验证（候选做法与 session 0 限制见架构 §8.1） |
| AWS Nitro Enclaves + KMS | 团队 / 企业首个云端隔离执行方案，随设备离线和无人值守执行需求推进；默认 BYO-KMS | 提供宿主机管理员无法直接读取执行环境内存的保护，兼顾团队部署与治理 |
| Windows VBS Enclaves、Linux SGX、Azure / GCP 机密计算 | 当前仅保留扩展接口，按客户需求再增加 | 每一种都会增加硬件、部署、验证与维护成本 |

**运行位置与保护能力分别说明。** 用户看到的是本地保存、连接已有凭证库或远程执行，以及当前实际生效的保护状态；ECDH、HKDF、PCR 等实现细节留在技术文档。

2026-10-09 已整合为 macOS 必需模式：安装与升级运行 `keyvalet setup-enclave`，通过终端或本机隐藏输入框设置独立恢复口令，新 vault 直接初始化硬件密钥，旧 vault 更换主密钥后删除 `master.key`。每个新会话认证，`remember` 也不跳过；取消设置或硬件失败不会降级，旧文件密钥 vault 仅能进入迁移。换机可通过恢复口令重新绑定硬件密钥；`migrate-to-enclave` 保留为迁移命令别名。当前实现与本机验证范围见架构 §8.0。

| 保护能力 | 对用户的说明 | 保证边界 |
| --- | --- | --- |
| 本地保护 | 凭证留在自己的电脑，审批后由 KeyValet 使用 | 信任操作系统与 helper；现有 root 妥协仍在威胁模型之外 |
| 硬件密钥保护 | 使用硬件保护的密钥，降低复制 vault 文件后离线解密的风险 | Enclave / TPM 内的私钥不可导出，不代表解封或派生到普通进程中的 AES 主密钥也不可读取。强度因平台而异：macOS SE 每次使用都要求用户在场（Touch ID / 密码）；TPM 没有用户在场机制，未设 PIN 时同机 root 可静默使用，只防 vault 被复制到别处 |
| 隔离执行 | 秘密在通过证明的隔离环境内使用，宿主机管理员不能直接读取其内存 | 授权检查、解密、凭证注入和 TLS 留在隔离环境；仍信任硬件、固件、执行代码和密钥策略治理，不承诺“无论如何都拿不到” |

**本地方案的准确承诺。** Secure Enclave 的 ECDH + HKDF 方案若把固定 AES 主密钥交给 `kv-helper`，该主密钥就存在于普通进程内存中。攻击者若在一次合法解锁时截获它，直到密钥轮换前仍可离线解密其保护的 vault；退出会话、清零内存和下一次 Touch ID 都不能撤回已经复制出去的密钥。因此该方案可以作为第一步，但不能宣传为实际解密密钥永不离开硬件，或已经防住 root。硬件密钥的加密表示只绑定这台 Mac，不绑定 KeyValet 签名：被攻破的 root 无需等待合法解锁，可以自己发起认证，用户批准一次即可取得主密钥。会话弹窗只显示固定的范围文字，其他程序可以模仿，所以用户的防线是：留意不是自己刚触发的认证弹窗，并查看审计记录。新设置或轮换过的 vault 带设备绑定：密钥还依赖一个只有 root 可读、不进 Time Machine 的绑定文件，单有 vault 文件副本加一次获批弹窗无法解密；旧 vault 运行 `keyvalet rotate-recovery` 即可启用，该命令同时更换恢复口令。

SE 不可用时（例如系统更新后无法完成硬件认证）不降级：`keyvalet recovery-read` 用恢复口令只读访问凭证，`keyvalet recovery-check` 不用硬件、只验证恢复口令，换到正常的 Mac 后用 `recover-vault` 恢复。这些都是用户显式发起的 CLI 应急路径，helper 不接受。

**商业与体验要求：**

1. 本地硬件保护属于基础安全能力，Free / Team 不以是否启用它区分安全等级。团队收费点放在共享、撤销、策略、CI 身份和审计；云端隔离执行可作为有部署与运维成本的付费能力。
2. macOS 必须具备 Secure Enclave，不提供文件密钥或软件回退。后续 Linux 等平台可按平台决策提供明确标注的软件兼容方案，状态显示“硬件密钥保护”或“软件保护”；硬件访问失败必须报错，不能静默切回文件密钥。
3. Linux / CI 优先通过受限身份和能力令牌调用持有凭证的执行端。远程审批后把主密钥或长期凭证交回 runner，仍不能防该机器的 root。
4. 换机、备份、硬件损坏和恢复与硬件绑定方案一起设计，迁移前让用户了解并验证恢复路径。恢复码、软件备份或额外设备包裹形成独立解密路径，其安全边界必须单独说明。
5. 普通 KMS 可以作为企业后端，但不能把“主密钥不可导出”宣传成“调用方拿不到明文”。BYO-KMS 与托管 KMS 的策略管理权分别说明，见架构 §11.4。

技术边界参考：[Apple Secure Enclave](https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave)、[Windows TPM](https://learn.microsoft.com/en-us/windows/security/hardware-security/tpm/how-windows-uses-the-tpm)、[Windows VBS Enclaves](https://learn.microsoft.com/en-us/windows/win32/trusted-execution/vbs-enclaves)、[Linux Trusted Keys](https://www.kernel.org/doc/html/latest/security/keys/trusted-encrypted.html)、[AWS Nitro Enclaves](https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave.html)、[KMS Decrypt / Recipient](https://docs.aws.amazon.com/kms/latest/APIReference/API_Decrypt.html)。

---

## 2. 用户画像与任务

| 画像 | 是谁 | 触发场景 | 要完成的任务 | 付费 |
| --- | --- | --- | --- | --- |
| Dev：重度 agent 开发者 | 每天用 Claude Code / Codex / Cursor，手里 10–30 个 API key 和几个 OAuth 账号，Mac 为主，部分有 Linux 服务器 | 看到 s1ngularity 类新闻；agent 把 key 写进了文件；换电脑时找不到 key 在哪 | 把 key 收起来；让 agent 继续能用；知道 agent 用了什么 | 不付费，是漏斗和口碑来源 |
| Lead：3–30 人团队的负责人或平台工程 | 团队都在用 agent；共享 key 在 Slack 里传；CI 里有静态 secret；要向老板交代 agent 用了什么 | 新人入职要发 key；有人离职要换 key；审计或客户问「agent 怎么管的」 | 共享与撤销；CI 无静态密钥；策略统一；审计导出 | Team，15–18 美元/席位 |
| Sec：安全负责人（阶段 4 才服务） | 要求自托管、SSO、SCIM、SOC 2 | 合规与采购 | 不在前 14 个月范围 | Enterprise |

Dev 是产品的第一用户，Lead 是第一付费者；所有阶段 0–2 的决策以 Dev 的体验和 Lead 的付费触发点为准。

---

## 3. 核心用户旅程

### J1 首次安装到首次代理调用（目标：5 分钟内）

1. 官网或 README：一条 `curl … | sh`。安装脚本检测 Claude Code / Codex / Cursor / Grok，询问是否为每个已安装的运行时配置 MCP 与 hooks（默认全选）。
2. 第一次输入密码（安装特权 helper），之后全部 Touch ID。
3. 在 agent 里说 `/keyvalet:add openai`：原生对话框让用户粘贴 key，模板自动配置代理和验证请求，验证通过显示「已就绪」。
4. 对 agent 说「用 KeyValet 列出我的 OpenAI 模型」：Touch ID 弹窗显示「使用 openai（本会话）」及这次授权放开的能力（proxy_only 凭证为「仅代理请求」）；按一下，agent 拿到响应。逐次授权时显示真实操作及全部参数。
5. 结束时 agent 用一句话告诉用户发生了什么：哪条凭据、什么请求、审计里能查。

验收：新用户从安装到第一次成功代理调用的中位时间 < 5 分钟；每步都有单一明确动作。

### J2 把现有密钥迁进来

1. `keyvalet scan` 或 agent 说「把我的 .env 迁到 KeyValet」。
2. 扫描 `.env*`、`~/.claude.json`、`.cursor/mcp.json`、`~/.codex/config.toml`、shell rc；列出候选（服务、文件、行号），不显示值。
3. 原生窗口勾选；每条匹配模板并（经用户确认后）发一次验证请求；无效的标灰。
4. 写入 vault，原文件对应行替换为 `${KEYVALET:openai/default}`；备份文件由用户确认后删除。
5. 之后 agent 读到占位符时，hook 提示它用 `credential_http_request` 或 `keyvalet run`。

验收：10 条密钥的迁移在 2 分钟内完成；迁移后原文件 `grep` 不到任何有效密钥。

### J3 日常使用与审批

1. agent 发起 `credential_http_request`（或经网关 / 透明代理）。
2. 策略判定：T0 只读自动放行并审计；T1 按授权模式决定是否弹窗；T2 必须逐次强审批；T3 直接拒绝并告诉 agent 原因。
3. 弹窗内容见附录 A；用户可选「这一次 / 这个凭据本会话 / 记住 N 小时」。
4. 响应脱敏后返回；审计写入。
5. `/keyvalet:audit` 或控制台查看：谁、什么时候、哪条凭据、为什么、真实请求、结果。

### J4 控制审批疲劳

- 连续 N 次批准同一凭据的只读请求后，弹窗出现「以后自动放行 api.openai.com 的只读请求」；接受后写入用户策略。
- `/keyvalet:mode` 切换授权模式；放宽需要指纹；状态栏或 `credential_status` 显示当前模式与到期时间。
- T2 永远弹窗；用户不能把支付、删除、IAM 变成自动。

### J5 Linux 与服务器

- 优先提供调用与身份接入，长期凭证可以保留在 Mac 或远程执行端；远程执行随配对与 relay 能力上线，无 TPM 的 runner 也可使用。
- `install.sh` 在 Linux 上安装系统用户 `keyvalet` 的 helper；无 GUI 时审批走 TTY 确认码（只允许只读与普通写入）。
- 本地保存是兼容路径，TPM 可选，保护状态按 §1.4 明示；远程审批不会让普通 Linux helper 获得抵御 root 的隔离能力。
- 阶段 3 起配对手机后，Linux 上的敏感操作走手机 Face ID。
- CI：GitHub Actions 用 OIDC 换一张限定范围的能力令牌，没有任何静态 secret 进入仓库设置。

### J6 团队（阶段 2）

1. Lead 在控制台用邮箱创建组织，邀请成员；成员安装 KeyValet 并注册设备。
2. Lead 把 `openai/team` 共享给 3 个成员：选择成员 → Touch ID → 共享完成；成员的 agent 下一次请求时自己的 Touch ID 弹窗显示「团队凭据 openai/team」。
3. 新人入职：邀请即可；离职：移除成员，凭据自动轮换 CEK，可选触发上游 key 轮换提醒。
4. Lead 在控制台维护 `policy.yaml`（只能比成员本地策略更严），保存后 1 分钟内下发。
5. 每月导出审计 JSONL 给审计方。

验收：从创建组织到第一个成员用上共享凭据 < 15 分钟；移除成员后其设备在 1 分钟内无法再用。

### J7 手机审批（阶段 3）

1. `keyvalet pair` 显示二维码；iPhone App 扫码；两端核对 6 位安全码。
2. 之后 Linux 或远程会话上的请求推送到手机：锁屏长按批准只读 / 普通写入；敏感操作要打开 App 用 Face ID。
3. 手机丢失：用恢复码或另一台设备吊销。

### J8 应急：泄露、失效、轮换

- 怀疑泄露：`/keyvalet:lock` 立即锁定；控制台或 CLI 吊销设备与能力令牌；审计导出最近 24 小时该凭据的全部使用。
- 上游 key 失效：模板的验证请求失败时，agent 收到结构化错误「凭据失效，请让用户更新」，用户通过 `/keyvalet:add` 覆盖。
- 轮换（阶段 3 末）：模板带轮换端点的服务可一键换新 key 并同步到团队成员。

---

## 4. 产品面

| 面 | 用户 | 作用 | 阶段 |
| --- | --- | --- | --- |
| MCP 工具（`credential_*`） | agent | 全部能力的程序接口；工具描述和错误信息是「写给模型的 UI」 | 现有 |
| 斜杠命令与 skill（`/keyvalet:add`、`mode`、`status`、`lock`、`audit`） | 用户在 agent 里 | 最常用的五个动作不需要离开对话 | 现有 |
| 原生对话框（录入、确认） | 用户 | 零明文录入；删除确认 | 现有 |
| 审批弹窗（Touch ID / TTY / 手机） | 用户 | 核心交互；见 §6 与附录 A | 现有，阶段 0 改版 |
| hooks 提示 | agent | 密钥即将落地时拦截并给出替代方案 | 现有，阶段 0–1 扩到 Codex / Cursor |
| CLI `keyvalet` | 用户 / 脚本 | scan、run、proxy、hooks install、policy、audit、grant、pair | 阶段 0–2 |
| 透明代理与 SDK 网关 | 不走 MCP 的程序 | 让任意 SDK 和 CLI 受保护 | 网关现有；代理阶段 2 |
| Web 控制台 | Lead | 组织、成员、共享、策略、账单、审计 | 阶段 2 |
| iPhone App | 用户 | 远程审批与配对 | 阶段 3 |
| 官网与文档 | 所有人 | 转化与自助 | 阶段 0 改版 |

---

## 5. 功能清单与验收标准

优先级：M 必须、S 应该、C 可以。每条附验收标准（AC）。

### 阶段 0（0–1 月）：发布与「每一次弹窗都值得看」

| 优先级 | 功能 | AC |
| --- | --- | --- |
| M | macOS Secure Enclave 本地主密钥保护：先验证，再显式迁移；保护状态与换机恢复同步设计（§1.4） | spike 不接触真实 vault；临时 vault 完成迁移、解锁与恢复验证；硬件访问失败不静默降级；产品准确说明 helper 内存边界 |
| M | 审批弹窗显示真实请求（method、host、path、摘要）并绑定请求摘要 | 任一字段改动后旧审批失效；弹窗在 Touch ID 文案字数限制内可读 |
| M | 模板 `summarize` 规则（先覆盖 OpenAI、Anthropic、GitHub、Stripe、AWS、Slack） | 这些服务的弹窗显示业务语义（model、repo、金额）而非路径 |
| M | 工具 annotations（readOnly / destructive / openWorld） | 客户端能区分只读工具；Claude Code 权限提示减少 |
| M | hooks 覆盖 Codex，Cursor 适配器原型 | 在 Codex 里把 key 写进 `.env` 会被拦下并提示 |
| M | `keyvalet scan` | J2 验收 |
| M | 官网改版：定价、对比、安全页；GitHub Pages 切到 `site/` | 首页首屏有安装命令和 60 秒演示 |
| S | Grok 核实与 MCP 接入 | 文档写明支持程度 |
| S | 商标检索、Simvito Limited 开 Stripe 与 Apple 账号、注册 keyvalet.dev | 完成 |
| C | 安装脚本检测四个运行时并一次配置 | 安装后无需手动改配置 |

### 阶段 1（1–4 月）：策略与 Linux

| 优先级 | 功能 | AC |
| --- | --- | --- |
| M | 策略引擎 v1：T0–T3、host/method/path 规则、预算、`.keyvalet/policy.yaml`、`keyvalet policy test` | 只读 GET 默认不弹窗但有审计；仓库策略不能放宽 |
| M | grant 范围明确化；T2 永不被记住 | 用例矩阵（4 模式 × 4 层级）全部通过 |
| M | 「以后自动放行」推荐 | 连续 5 次批准后出现；接受后写入用户策略 |
| M | Linux / CI 调用与身份接入、本地 helper 兼容路径（系统用户、Unix socket、TTY 审批；TPM 可选，见 §1.4） | Ubuntu 22.04+ 与 Debian 12 上 J1 可完成；无 TPM 可用并显示保护状态，硬件访问失败不静默降级 |
| M | `keyvalet hooks install --all` | 幂等；卸载可逆 |
| M | 审计哈希链与 `keyvalet audit export` | `audit verify` 可检出篡改 |
| S | 能力令牌：Mac 签发、CI 使用（GitHub Actions 示例工作流） | 示例仓库跑通，无静态 secret |
| S | 中英文完整覆盖（弹窗、CLI、错误） | 两种语言的截图走查 |
| C | 模板目录页（官网自动生成） | 每个服务一页，含「如何添加」 |

### 阶段 2（4–8 月）：relay 与 Team v1 收费

| 优先级 | 功能 | AC |
| --- | --- | --- |
| M | 自建 relay（Docker）与官方 relay（美国托管）；设备注册与密文同步 | 换电脑后用恢复码 + 旧设备恢复 vault < 10 分钟 |
| M | Team v1：邮箱账号、组织、邀请、共享凭据、移除即轮换 | J6 验收 |
| M | 组织策略下发（只能收紧） | 成员本地 `policy show` 显示 org 规则来源 |
| M | CI 身份：GitHub OIDC → 能力令牌 | 示例工作流在团队账号下跑通 |
| M | Web 控制台 v1：组织、成员、账单、策略、设备、审计统计与导出 | Lead 不用 CLI 完成 J6 |
| M | Stripe 订阅、14 天试用、权益令牌、7 天离线宽限 | 断网 7 天内功能不降级 |
| M | 法律页：隐私政策、服务条款、数据处理说明（收费前完成） | 定价页可链接；Stripe 账户审核通过 |
| S | 透明代理 opt-in（会话 token、CA 在 helper）与 `keyvalet run` | Python / Node SDK 示例不改代码即受保护 |
| S | 1Password、Infisical 后端（引用，不复制） | 在 1Password 里轮换后 KeyValet 自动生效 |
| S | `kv-mcp` Rust 版替换 TS | 功能对齐，安装体积与启动时间下降 |
| C | 用量与账单页的升级提示 | 见 §9 触发点 |

### 阶段 3（8–14 月）：iPhone 与 Team 完整版

| 优先级 | 功能 | AC |
| --- | --- | --- |
| M | iPhone App：配对、两级审批、通知内容解密、App Attest | J7 验收；锁屏批准 < 5 秒，打开 App 强审批 < 15 秒 |
| M | 审批路由到 owner；敏感凭据 N-of-M | 2/3 审批聚合后执行 |
| M | Linux / CI 的敏感操作走手机 | TTY 不再能批 T2 |
| M | OIDC SSO | 用 Okta 或 Google 登录控制台 |
| S | 控制台「浏览器作为设备」：审计解密、Quick 审批 | 不需要安装任何东西就能看审计明细 |
| S | 凭据轮换（模板带轮换端点） | 一键换 key 并同步成员 |
| S | Bitwarden 后端 | 引用可用 |
| C | macOS 菜单栏 | 状态、模式切换、最近审批 |

---

## 6. UX 规范

### 6.1 审批弹窗

- 普通 Touch ID 弹窗默认一句话：凭据与授权范围，例如「使用 openai（本会话）」。逐次授权才补充真实请求（method + host + path）；明文读取等非代理操作保留具体动作。来源和完整用途留在审计中。
- 会话授权覆盖该凭据在会话中的使用，不以某条请求或 agent 自述用途暗示更窄的权限。
- 真实请求不显示哈希、不显示完整 URL 的查询值、不显示任何 header 值。
- T2 弹窗加一行红色提示「敏感操作，不会被记住」。
- Touch ID 文案有长度限制：保留凭据、授权范围，以及逐次授权或明文读取时必要的操作信息；用途与来源目录不放入紧凑弹窗。
- 中英文各一套措辞（附录 A）。

### 6.2 错误与拒绝

- 给 agent 的错误是机器可读码加一句人话（附录 B），并告诉它下一步能做什么（换工具、请用户批准、让用户添加凭据）。
- 给用户的拒绝原因出现在审计和 `credential_status` 里，不弹第二个窗。
- `DEVICE_OFFLINE` 之类的商业提示只出现一次，不在每次请求重复。

### 6.3 默认值

- 授权模式默认 `per_credential`；T0 自动放行开启；透明代理关闭；`credential_get` 明文需要凭据未标 `proxy_only` 且策略允许。
- 新增凭据默认 `proxy_only = true`，模板能确定 host 的默认填 `allowed_hosts`。
- 审计默认本地保存 90 天。

### 6.4 零明文的界面表现

- 录入永远是原生对话框，agent 工具的 `value` 参数只在用户已经把 key 贴进聊天时使用，并在存入后提示「下次用 `/keyvalet:add`，key 就不会经过聊天」。
- 任何界面不回显 key 的任何部分；需要区分时用「尾号」四位的 HMAC 指纹，不用明文尾号。
- 导出只返回路径；路径文件在会话结束时删除。

### 6.5 对 agent 的写法

- 工具描述先说「什么时候用我」，再说参数；每个工具带一个最小示例。
- 系统提示（skill）明确优先级：代理调用 > 导出文件 > 明文。
- 失败时鼓励 agent 向用户解释，而不是重试绕过。

### 6.6 国际化

- 中英文同等优先；第一批运行时用户以英文为主，Show HN 用英文；中文文档同步维护。
- 日期、金额按用户区域格式化；审计导出用 ISO 8601。

### 6.7 可访问性与平台一致性

- macOS 用系统原生对话框与 Touch ID 文案；iOS 用系统通知与 Face ID；不自绘假弹窗。
- 颜色之外必有文字提示层级（T2 的「敏感」字样）。

---

## 7. 审批疲劳：产品对策与量化目标

| 对策 | 机制 | 目标 |
| --- | --- | --- |
| 只读自动放行 | T0 不弹窗，只审计 | 弹窗次数下降 50% 以上 |
| 显示真实请求与摘要 | 弹窗有信息量，用户会读 | 拒绝率 ≥ 5%（有拒绝说明用户在看） |
| 推荐规则 | 从历史生成「以后自动放行」 | 第 2 周起每天弹窗 ≤ 3 次 / 周活 |
| 任务级授权 | 「这个凭据本会话」是默认选中项 | 会话内重复弹窗接近零 |
| 敏感操作不可记住 | T2 永远弹 | T2 请求 100% 有人工审批记录 |
| 弹窗节流 | 同一凭据 30 秒内的 T0/T1 请求合并为一次「批准接下来 30 秒的请求」，等价于一个 30 秒的临时 grant；T2 不合并 | 并发请求不连弹 |

监测：每周活每天审批次数、拒绝率、Remember 模式占比（过高说明策略不够用）、T2 占比。

---

## 8. 模板与集成策略

- 现有约 50 个模板（`catalog.json`）加 n8n 目录导入。阶段 1 目标 100 个，阶段 3 目标 150 个。
- 优先级按 agent 用户最常用的 API：OpenAI、Anthropic、Google AI、GitHub、AWS、GCP、Azure、Stripe、Slack、Notion、Linear、Vercel、Supabase、Cloudflare、Twilio、SendGrid、Resend、PostHog、Sentry、Datadog。
- 每个模板必填：字段、注入规则、`allowed_hosts`、验证请求、`summarize` 规则、敏感路径（进 T2）、文档链接；可选：OAuth 配置、轮换端点。
- 社区贡献：模板是 JSON，PR 需附验证请求的脱敏录屏或测试；官网模板页自动生成。
- 非 HTTP 协议：SSH 私钥、IMAP XOAUTH2、文件型凭据继续用 `export_file` 与协议签发，这是对 Infisical 的差异点，文档单独一章。

---

## 9. Free 到 Team 的升级路径

| 触发点 | 用户看到什么 | 升级后得到 |
| --- | --- | --- |
| 第二个人要用同一个 key | 「共享凭据需要 Team」 | 共享、撤销、轮换 |
| CI 里要用 key | 「CI 身份需要 Team」；Free 用户可用能力令牌但要手动续签 | GitHub OIDC 自动换令牌 |
| 官方 relay 超过 3 台设备或每月 2,000 次远程审批 | 额度提示，一次 | 不限额度 |
| 想看团队的审计 | 「审计导出需要 Team」 | JSONL / OTLP 导出 |
| 设备离线（阶段 4） | `DEVICE_OFFLINE` 一次性提示 | CI 离线执行附加项 |
| 想先试试 Team | 「14 天免费试用，不需要信用卡」 | 全部 Team v1 功能，到期不自动扣款 |

规则：Free 功能不设时间限制、不加水印、不降级安全性；升级提示只在触发点出现一次；Team 有 14 天免费试用，不要信用卡，不做限时折扣。

---

## 10. 指标体系

| 层 | 指标 | 目标（阶段 2 末） |
| --- | --- | --- |
| 北极星 | 每周受保护的 agent 调用数（经代理或签发的调用） | 周环比增长 > 10% |
| 获取 | 安装数、GitHub star、官网到安装转化 | 1 万安装（第 4 个月）；2 万（阶段 2 末） |
| 激活 | 首次代理调用的中位时间；有 ≥3 条凭据的周活占比 | < 5 分钟；≥ 20% |
| 留存 | D30 留存；周活 | ≥ 25%；4,000（阶段 3 末 8,000） |
| 安全价值 | `proxy_only` 占比；hooks 拦截次数；scan 迁移的密钥数 | ≥ 60% |
| 审批质量 | 每周活每天审批次数；拒绝率；T2 占比 | ≤ 3；≥ 5% |
| 收入 | 付费团队数；席位数；Free→Team 转化 | 3 家（第 6 个月）→ 20 家（第 14 个月） |

遥测原则：opt-in；只计数与时长，不含凭据名以外的任何内容；本地可查看将上报什么；自建 relay 用户默认关闭。

---

## 11. 非目标（前 14 个月）

- 浏览器自动填充与网页登录（1Password 的领域）。
- 人用的密码管理器功能（密码生成、表单、家庭共享）。
- 企业 NHI 控制平面（Keycard、Aembit 的领域）。
- Windows 原生客户端目前不承诺版本或月份，按 §1.4 在明确需求出现后排期；VBS Enclaves、Linux SGX、Azure / GCP 机密计算当前只保留接口。
- Android App、SAML、SCIM、enclave 离线执行、远程 MCP 端点（阶段 4）。
- 自研 OAuth 授权服务器（用 Ory Hydra）。
- 个人付费档。

---

## 12. 发布节奏与版本

| 版本 | 时间 | 内容 | 渠道 |
| --- | --- | --- | --- |
| v0.1 | 第 1–2 周 | 现有功能 + 真实请求弹窗 | Show HN、X、r/ClaudeAI、MCP 目录（按 `marketing/launch-plan.md`） |
| v0.2 | 第 1 月 | scan、Codex/Cursor hooks、annotations、官网改版 | Claude Code 插件市场、Codex plugins、cursor.directory |
| v0.3 | 第 3 月 | 策略引擎、推荐规则 | 博客「为什么 93% 的弹窗被批准」（来源核实后） |
| v0.4 | 第 4 月 | Linux、能力令牌、审计链 | r/selfhosted、Linux 社区 |
| v0.5 | 第 6 月 | relay、Team v1、控制台、收费 | Product Hunt；设计合作伙伴案例 |
| v0.6 | 第 8 月 | 透明代理、1Password/Infisical 后端 | Infisical / 1Password 社区 |
| v0.7 | 第 11 月 | iPhone App、手机审批 | App Store；视频 |
| v1.0 | 第 14 月 | Team 完整版、SSO、第三方审计报告 | 安全社区、OWASP Agentic |

每月一篇事故复盘内容；每个版本一则 release note 同时发中英文。

---

## 13. 用户研究与反馈机制

- 设计合作伙伴 10 家（第 6 个月前找到）：重度 Claude Code 团队，优先金融科技与开发者工具公司；免费 6 个月 Team，每月一次 30 分钟访谈（附录 D）。
- GitHub Discussions 作为主要社区；Issue 模板区分「安全问题请走 SECURITY.md」。
- 每次 Touch ID 拒绝后，可选一键「这次为什么拒绝」（三个选项），本地统计，opt-in 上报。
- 季度一次「agent 配置里的密钥」统计文章，复现 GitGuardian 的 MCP 配置扫描方法，既是研究也是内容。

---

## 14. 文档与内容的信息架构

```
keyvalet.dev
  /                首页：定位、演示、安装、三条差异点
  /why             事故复盘系列与「agent 永不持有密钥」原理
  /compare         vs 1Password · vs Infisical Agent Vault · vs .env
  /pricing         Free / Team v1 / Team 完整版 / 附加项 / FAQ
  /docs
    quickstart     5 分钟上手（按运行时分页：Claude Code、Codex、Cursor、Grok）
    concepts       凭据、授权模式、风险层级、grant、代理注入、审计
    tools          全部 MCP 工具与斜杠命令
    cli            keyvalet 命令
    policy         策略语法与示例
    templates      模板目录（自动生成）与贡献指南
    team           组织、共享、CI 身份、控制台
    self-host      自建 relay
    security       威胁模型、SECURITY.md、可复现构建、PCR
  /blog
  /download        install.sh、二进制、校验和、签名
  /legal           隐私、条款、数据处理
```

---

## 15. 产品层面的风险与开放问题

| 风险 | 对策 |
| --- | --- |
| 弹窗文案在 Touch ID 的长度限制下放不下真实请求 | 阶段 0 验证实际字数上限；超限时用原生确认框替代系统 Touch ID 文案 |
| 只读自动放行被滥用（GET 也能泄露数据） | T0 只对 `allowed_hosts` 内的 GET；响应脱敏；用户可在策略里关闭 |
| 用户不理解「用途」是 agent 的声明 | 弹窗用「agent 说：」前缀；文档解释 |
| Cursor 不能 ask 只能拒绝，体验比 Claude Code 差 | 拒绝信息里给出替代命令；文档标注各运行时支持程度 |
| Grok 的能力未知 | 阶段 0 核实；MCP-only 先接入 |
| Team v1 没有手机，Linux 上的敏感操作只能拒绝 | 文档明示；阶段 3 补 |
| 新成员需要在线持有者包裹 CEK 的摩擦 | 阶段 2 用设计合作伙伴验证两种方案 |
| 遥测会被安全用户质疑 | opt-in、可查看上报内容、自建 relay 默认关 |
| 「93% 盲批」数据来源待补 | 核实前不在官网使用该数字 |

---

## 附录 A：审批弹窗文案规范与示例

规范：普通 Touch ID 审批默认一句话，保留凭据和授权范围；逐次授权和非代理操作补充必要的操作信息。T2 敏感操作和 TTY 等界面使用独立的完整模板。

中文示例（T1，OpenAI）：
```
使用 openai/default（本会话）
```

English (planned T2 approval interface, GitHub):
```
KeyValet · github/work · sensitive
Agent says: clean up old branches
DELETE repos/x/y/git/refs/heads/release-2025
codex · github.com/x/y
Sensitive action — never remembered.   [Approve once] [Deny]
```

TTY 示例（Linux，仅 T0/T1）：
```
KeyValet approval  openai/default (write)
  agent says : summarize meeting notes
  request    : POST api.openai.com /v1/chat/completions · 2.1 KB
  from       : codex · /srv/app
Type the code 4F2K to approve this once, or press Enter to deny:
```

## 附录 B：面向 agent 的错误码与提示

| 码 | 人话 | 建议 agent 的下一步 |
| --- | --- | --- |
| `POLICY_DENIED` | 策略禁止：host 不在白名单 / 敏感路径 / 超预算 | 告诉用户原因；不要换 host 重试 |
| `APPROVAL_DENIED` | 用户拒绝了这次请求 | 停止该操作，询问用户 |
| `APPROVAL_TIMEOUT` | 5 分钟内没有人审批 | 提醒用户查看手机或终端 |
| `STRONG_APPROVAL_UNAVAILABLE` | 需要强审批但本机没有生物识别且未配对手机 | 请用户在 Mac 上操作或配对手机 |
| `HOST_NOT_ALLOWED` | 请求的 host 不在凭据的 `allowed_hosts` | 让用户用 `credential_configure_http` 添加 |
| `CREDENTIAL_INVALID` | 上游拒绝了凭据 | 让用户用 `/keyvalet:add` 更新 |
| `DEVICE_OFFLINE` | 没有可执行的设备在线 | 稍后重试；团队可开通 CI 离线执行（阶段 4） |
| `BUDGET_EXCEEDED` | 本时段预算用尽 | 等待或请用户放宽策略 |
| `PLAINTEXT_FORBIDDEN` | 该凭据为 proxy_only | 改用 `credential_http_request` |

## 附录 C：MCP 工具描述规范

- 第一句：什么时候用这个工具（而不是它做什么）。
- 第二句：它不会做什么（如「不会返回密钥明文」）。
- 参数说明里标出哪些需要 `purpose`，并给一个好的 `purpose` 示例（「调用 OpenAI 生成会议摘要」）和一个坏的（「测试」）。
- 每个工具一个最小调用示例。
- 只读工具标 `readOnlyHint`，删除类标 `destructiveHint`，发网络请求的标 `openWorldHint`。

## 附录 D：设计合作伙伴访谈提纲（30 分钟）

1. 团队里 agent 用到的凭据现在放在哪里、怎么传给新人（5 分钟）。
2. 过去 6 个月有没有 key 泄露或接近泄露的事（5 分钟）。
3. 看三张弹窗截图：哪一张你会认真看，为什么（5 分钟）。
4. 共享凭据的流程演示；新成员加入时你愿意接受「需要一台在线设备确认」吗（5 分钟）。
5. CI 里的 secret 现在怎么管；OIDC 换令牌的方案能不能接受（5 分钟）。
6. 15 美元/席位是否合理；什么功能会让你付 18（5 分钟）。
