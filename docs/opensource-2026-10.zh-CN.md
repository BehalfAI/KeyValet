# KeyValet 开源规划（阶段 0 到阶段 3）

- 日期：2026-10-08
- 配套：`docs/strategy-2026-10.zh-CN.md`（商业模式）、`docs/architecture-2026-10.zh-CN.md`（单仓库布局）、`docs/marketing-2026-10.zh-CN.md`（社区渠道）、现有 `CONTRIBUTING.md`、`SECURITY.md`、`LICENSE`（Apache-2.0）、`NOTICE`
- 现状：仓库 `KeyValet/KeyValet`（已从 BehalfAI 迁移），11 次提交，单一维护者；有 `CONTRIBUTING.md`（Setup、Ground rules、Templates、Localization、Reporting security issues）、`SECURITY.md`、`.github/workflows/test.yml` 与 `pages.yml`；没有 CODE_OF_CONDUCT、GOVERNANCE、issue/PR 模板、DCO、依赖许可检查、签名发布

## 目录

1. 为什么开源，开源到哪
2. 许可与法务
3. 对用户的承诺
4. 治理
5. 贡献路径
6. 安全流程
7. 发布与供应链
8. 社区运营
9. 生态与上游
10. 度量
11. 维护者单点风险
12. 前 90 天清单
- 附录 A：`GOVERNANCE.md` 草案
- 附录 B：商标政策草案
- 附录 C：模板贡献规范
- 附录 D：Issue / PR 模板要点

---

## 1. 为什么开源，开源到哪

开源是产品的信任基础，不是营销手段：一个替用户保管密钥、以 root 运行的本地程序，只有代码可读、构建可复现、发布可验证，用户才会装。战略文档把「可验证」定为品牌根基，这里落实为规则。

| 开源（Apache-2.0） | 源码可见、商业许可（`ee/`） | 不开源 |
| --- | --- | --- |
| 全部 Rust 核心：helper、vault、协议签发、代理与脱敏、策略引擎、审批、能力令牌、审计链 | Team 功能：组织与成员、共享凭据、组织策略分发、审批路由与 N-of-M、SSO、审计导出到 SIEM、控制台的团队管理页 | 官方 relay 与推送网关的部署配置和密钥 |
| `kv-mcp`、`kv-hook`、`kv-cli`、`kv-relay-client`、运行时 manifest | 计费与权益签发 | 商标与 logo（受商标政策约束） |
| relay 服务端（`kv-server` 的 relay feature）、推送网关 `kv-push` 的代码、Docker 自建部署 | CI 离线执行附加项的服务端部分（阶段 4） | — |
| iPhone / Android App、`kv-ffi` | — | — |
| enclave 二进制与可复现构建脚本（阶段 4，用户必须能验证 PCR） | — | — |
| 模板目录、文档、官网源码 | — | — |

原则：**凡是用户为了信任产品需要读的代码都开源**；`ee/` 只放「多人协作」和「收费」两类功能。

---

## 2. 许可与法务

| 事项 | 决定 |
| --- | --- |
| 核心许可 | Apache-2.0（现状不变）。不选 AGPL：它会让企业法务卡住安装，与「让尽可能多的开发者装上」矛盾 |
| `ee/` 许可 | 源码可见的商业许可，参照 Infisical 与 Elastic License 2.0 的写法：可读、可修改、可自用；不可对外提供为服务、不可绕过权益校验。文件头统一标注 |
| 贡献者协议 | 核心用 DCO（`Signed-off-by`），不用 CLA，对个人贡献者摩擦最小；`ee/` 目录默认不接受外部贡献，确有需要时签一份轻量 CLA（授予 Simvito Limited 再许可权） |
| 商标 | `KeyValet` 名称与 logo 不在 Apache-2.0 授权范围内；附录 B 的政策允许「兼容 KeyValet」「基于 KeyValet」的描述性使用，禁止用于 fork 的产品名；阶段 0 做商标检索 |
| 依赖许可 | `cargo-deny` 在 CI 检查：允许 MIT / Apache-2.0 / BSD / ISC / Zlib / MPL-2.0（文件级 copyleft，静态链接可用，修改其文件需公开）；拒绝 GPL / AGPL / SSPL 进入核心 |
| 第三方代码 | `NOTICE` 维护引用；n8n 模板目录的来源与许可注明 |
| 出口与加密 | 阶段 2 收费前咨询一次律师：美国 EAR 对公开可用加密源码的例外（含通知义务）与香港《进出口（战略物品）规例》；结论记在 `docs/compliance.md` |

承诺写进 `GOVERNANCE.md`：**已经在 Apache-2.0 下发布的功能，不会移入 `ee/` 或改为更严格的许可。** 这是对 HashiCorp 式换许可争议的预先回答。

---

## 3. 对用户的承诺

1. 本机全部功能永远免费、永远开源，没有时间限制和降级。
2. 自建 relay 永远可用，不依赖官方账号。
3. 密文格式、IPC 协议、策略语法、审计格式有版本号和文档，用户可以自己写工具读。
4. 发布物可复现（阶段 2 起 Rust 二进制，阶段 4 起 enclave）并签名。
5. 遥测 opt-in，可以在本地看到上报内容。
6. 若项目停止维护，提前 90 天公告，并发布最后一个可自建的完整版本（见 §11）。

---

## 4. 治理

- 现阶段：单一维护者（Guang），决策公开在 Issue 与 Discussions；不设委员会。
- 决策记录：影响用户或协议的改动写 ADR（`docs/adr/NNNN-title.md`，一页），PR 引用它。
- RFC：只对协议级改动（IPC、密文格式、策略语法、审批协议）开 RFC issue，公开评论至少 7 天。
- 版本：semver；`0.x` 期间 minor 可破坏兼容但必须附迁移说明；`1.0` 起 major 才破坏。兼容矩阵在 `docs/compat.md`。
- 分支：`main` 可发布；功能分支 PR 合并；release 打 tag。
- 备用维护者：阶段 2 前邀请 1–2 位活跃贡献者成为 maintainer（拥有合并权，不拥有发布密钥）；发布密钥与商标归 Simvito Limited。

---

## 5. 贡献路径

从易到难，每一级都要有文档和示例。

| 级别 | 贡献什么 | 需要会什么 | 入口 |
| --- | --- | --- | --- |
| 1 | 模板（JSON：字段、注入、`allowed_hosts`、验证请求、`summarize`） | 会用那个服务的 API | `templates/CONTRIBUTING.md`，附录 C |
| 2 | 翻译（中英文之外的语言）、文档修正 | 语言 | `kv-i18n` 的字符串表 |
| 3 | 运行时 manifest 与适配器（新的 agent 运行时） | 读该运行时的 hooks 文档、少量 Rust | `kv-hook/manifests/`，适配器 trait |
| 4 | 存储后端插件 | Rust | `kv-storage-*` 示例 crate |
| 5 | 核心（策略、审批、协议） | Rust、安全意识 | RFC 流程 |

- `good first issue` 永远保持 5 个以上，多为模板和文档。
- 每个 PR 必须：通过 CI、`Signed-off-by`、不含任何密钥（CI 用 gitleaks 扫）。
- 更新 `CONTRIBUTING.md`：加 DCO、Rust 代码规范（rustfmt、clippy 零警告）、模板测试要求、禁止把真实密钥写进测试。

---

## 6. 安全流程

| 环节 | 做法 |
| --- | --- |
| 报告渠道 | GitHub Private Vulnerability Reporting（发布前开启）+ `security@keyvalet.dev`；`SECURITY.md` 已写明 |
| 响应 | 24 小时确认，7 天内给出评估，高危 30 天内修复并发公告 |
| 公告 | GitHub Security Advisories + 官网 `/security/advisories`；每条附 CVE（如有）、影响版本、修复版本、缓解 |
| 赏金 | 阶段 2 有收入后设小额赏金（高危 500 美元、中危 100 美元），范围只含核心与 relay |
| 第三方审计 | 阶段 3 第一次，报告公开 |
| 威胁模型 | `SECURITY.md` 的「保证 / 不防」两节随每个大版本更新；架构文档 §16 同步 |
| 测试 | 脱敏模糊测试、SSRF 用例表、授权模式矩阵进 CI |

---

## 7. 发布与供应链

- 单一 `VERSION`，所有产物同号；release 由 CI 从 tag 构建，维护者本机不出产物。
- Rust 二进制：macOS arm64/x86_64、Linux x86_64/arm64（musl）；SBOM（CycloneDX）随发布；Sigstore（cosign keyless）签名；`install.sh` 校验 sha256 与签名。
- 依赖：`cargo-deny`（许可与漏洞）、`cargo-vet` 逐步覆盖、Dependabot 或 Renovate 每周；锁文件入库。
- 可复现：阶段 2 起 Rust 二进制可复现（固定工具链、`SOURCE_DATE_EPOCH`）；阶段 4 enclave EIF 可复现并公开 PCR。
- 安装脚本：拒绝不受信任的 Node 运行时（现有）；迁到 Rust 后不再依赖 Node。
- 发布说明：中英文，列出安全相关改动在最前。

---

## 8. 社区运营

- 场所：GitHub Issues（bug、feature）、Discussions（Q&A、Show and tell、Templates、Ideas）；不开 Discord。
- 模板：bug、feature、template-request、security（指向私密报告）四种 issue 模板；PR 模板含 DCO、测试、文档、`ee/` 声明四个勾选项（附录 D）。
- 行为准则：Contributor Covenant 2.1，`CODE_OF_CONDUCT.md`。
- 响应：48 小时内回复；每月发一条「本月进展」discussion。
- 致谢：release notes 点名；官网模板页标注贡献者；年度贡献者页。
- 语言：Issue 与 PR 用英文；中文用户可以用中文提问，维护者双语回答。

---

## 9. 生态与上游

- MCP：跟进 2026-07-28 规范；在 `modelcontextprotocol/ext-auth` 提「credential delivery」扩展讨论（阶段 3 后）；工具注解与 MRTR 的实现经验回馈到 SDK issue。
- 运行时：向 Claude Code、Codex、Cursor 的 hooks 文档提交修正和示例；Grok 的 hooks 能力核实后同样处理。
- 模板格式：公开 JSON schema，鼓励其他工具复用；接受 n8n 目录的上游更新。
- 存储后端：与 Infisical、1Password 以集成方身份合作，在它们的文档里出现。
- 标准：跟踪 IETF OAuth WG 的 agent 相关草案；不采用声明专利申请中的草案术语。

---

## 10. 度量

star 不是北极星。

| 指标 | 目标（阶段 2 末） |
| --- | --- |
| 外部贡献者数（合并过 PR） | 15 |
| 社区模板 PR 数 | 30 |
| Issue 首次响应中位时间 | < 24 小时 |
| 自建 relay 的部署数（opt-in 上报） | 50 |
| 下游使用（引用 `kv-core` 或模板格式的项目） | 3 |
| 安全报告处理时长中位 | < 7 天 |

---

## 11. 维护者单点风险

一个人维护的安全工具，用户最怕的是「作者消失」。预案：

- 文档先于代码：架构、协议、密文格式有文档，别人能接手。
- 备用维护者（§4）与发布密钥托管在 Simvito Limited 的密码库，紧急联系人可取。
- 可复现构建让任何人能验证发布物，不依赖维护者的个人机器。
- 停更承诺（§3 第 6 条）写进 `GOVERNANCE.md`。
- 公司被收购时的开源承诺：Apache-2.0 代码不可撤回；`ee/` 的许可条款对已发布版本不可追溯更改。

---

## 12. 前 90 天清单

- [ ] 第 1 周：开启 Private Vulnerability Reporting；加 `CODE_OF_CONDUCT.md`；加 issue / PR 模板；`CONTRIBUTING.md` 加 DCO 与 Rust 规范
- [ ] 第 1 周：GitHub 组织改名 `keyvalet`；仓库描述与 topics 按 `marketing/repo-metadata.md`；占住 npm / crates.io / PyPI 包名
- [ ] 第 2 周：`GOVERNANCE.md`（附录 A）；商标政策页（附录 B）；`templates/CONTRIBUTING.md`（附录 C）
- [ ] 第 2–3 周：CI 加 `cargo-deny`、gitleaks、Rust 测试矩阵（macOS、Linux）；Dependabot
- [ ] 第 3–4 周：Sigstore 签名发布与 `install.sh` 校验；SBOM
- [ ] 第 4 周：`good first issue` 10 个（模板为主）；提交 awesome 列表与 MCP 目录
- [ ] 第 6–8 周：第一篇 ADR（审批绑定真实请求）；RFC 流程说明
- [ ] 第 8–12 周：邀请第一位备用维护者；发布第一期「本月进展」；复盘贡献指标

---

## 附录 A：`GOVERNANCE.md` 草案

```
# Governance

KeyValet is maintained by Simvito Limited. Decisions are made in public issues and discussions.

Promises
- Everything released under Apache-2.0 stays Apache-2.0. We will not move released features into `ee/` or relicense them.
- All local functionality is free forever, without time limits or degraded security.
- A self-hosted relay will always be available and will never require an account with us.
- If the project is discontinued, we will announce it 90 days in advance and publish a final version that can be fully self-hosted.

Roles
- Maintainers merge pull requests and triage issues. Release keys and trademarks are held by Simvito Limited.
- Protocol-level changes (IPC, vault format, policy syntax, approval protocol) go through an RFC issue open for at least 7 days and are recorded as an ADR.

Licensing
- Core: Apache-2.0. `ee/`: source-available commercial license (see ee/LICENSE).
- Contributions: Developer Certificate of Origin (Signed-off-by).
```

## 附录 B：商标政策草案

- 「KeyValet」名称和 logo 由 Simvito Limited 持有，不在 Apache-2.0 授权内。
- 允许：描述性使用（「兼容 KeyValet」「基于 KeyValet 的插件」「KeyValet 的 fork」）；在文章、教程、目录中使用名称与 logo 指代本项目。
- 不允许：把 fork 或衍生产品命名为 KeyValet 或近似名；在未修改的发布物之外使用 logo 暗示官方发布；域名或账号名冒用。
- 模板与插件：可用「for KeyValet」后缀，不得用「KeyValet 官方」。

## 附录 C：模板贡献规范

- 文件：`templates/catalog.json` 中新增一项，或 `templates/community/<service>.json`。
- 必填：`id`、`name`、`docs`、`kind`、`fields`（标出哪些是 secret）、`inject`、`allowed_hosts`、`test`（一个只读的验证请求）、`summarize`（至少覆盖最常见的两个端点）、`sensitive_paths`（进 T2 的路径）。
- 证据：PR 描述附验证请求成功的脱敏输出（遮住所有值），或 CI 可运行的录制响应。
- 禁止：真实密钥、个人账号信息、写操作的验证请求。
- 评审：维护者 7 天内回复；合并后下一个版本的 release notes 点名。

## 附录 D：Issue / PR 模板要点

- bug：版本、运行时与版本、操作系统、复现步骤、期望与实际、`keyvalet status` 输出（自动脱敏）；提醒不要贴密钥。
- feature：问题场景、现在怎么绕、期望行为、是否愿意实现。
- template-request：服务名、文档链接、认证方式、是否愿意自己提 PR。
- security：只放一句话——请使用私密报告渠道。
- PR：改了什么、为什么；测试；文档；`Signed-off-by`；是否涉及 `ee/`（外部贡献默认不接受，需先联系维护者签 CLA）；是否涉及协议或格式（需 ADR）。
