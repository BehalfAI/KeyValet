# KeyValet 行动指南：从今天到第 24 个月

- 日期：2026-10-08
- 用法：这是五份规划文档（战略、产品、架构、营销、开源）的执行版。每一条都写明做什么、产出是什么、怎么算完成。按顺序做，遇到门槛先复盘再往下走。
- 时间假设：一个人，每周约 40 小时投入 KeyValet（其余时间自由职业），其中约 8 小时营销与社区。
- 章节索引：战略 S、产品 P、架构 A、营销 M、开源 O，例如「A §7.6」指架构文档第 7.6 节。

## 目录

0. 怎么用这份指南
1. 第 0 周：今天就能做的
2. 阶段 0（第 1–4 周）：发布
3. 阶段 1（第 2–4 月）：策略与 Linux
4. 阶段 2（第 5–8 月）：relay 与 Team v1 收费
5. 阶段 3（第 9–14 月）：iPhone 与 Team 完整版
6. 阶段 4（第 15–24 月）：CI 离线执行、远程 MCP、Enterprise
7. 门槛与决策树
8. 每周与每月的固定节奏
9. 第 24 个月的结局与准备
- 附录 A：账号与工具清单
- 附录 B：任务依赖关系
- 附录 C：每月复盘模板

---

## 0. 怎么用这份指南

- 每条任务格式：**做什么 → 产出 → 完成标准**。没写完成标准的任务不算任务。
- 顺序就是优先级。同一周内的任务可以并行，跨周的不要提前，除非前面的全部完成。
- 三类任务用标记区分：`代码` `产品/文档` `市场/运营`。每周三类都要有，否则营销会被无限推后。
- 每个阶段末有门槛（§7）。门槛不达标，不进入下一阶段，先按决策树处理。
- 这份文档本身每月更新一次：勾掉完成项、改时间、记录偏差。

---

## 1. 第 0 周：今天就能做的

| # | 任务 | 产出 | 完成标准 |
| --- | --- | --- | --- |
| 0.1 | `代码` 提交五份规划文档和本文 | 一次 commit：`docs/*-2026-10.zh-CN.md` | `git log` 可见；不要提交 `rust/` 以外的半成品 |
| 0.2 | `运营` 商标检索：USPTO、WIPO Global Brand Database、UKIPO、CNIPA、香港知识产权署，第 9 类与第 42 类，查 "KeyValet" 与 "Key Valet" | ✅ 初步检索已完成：`docs/trademark-check.md`——没查到软件/SaaS 类的注册商标冲突；"Key Valet" 这个名字被几家不相关的小公司在用（新泽西一家做汽车防盗硬件的 Key Valet Inc.、卡塔尔一家代客泊车公司），均非软件领域，WIPO 库被验证码挡住没能直接查。**这只是网络搜索式的初筛，不是专业检索**，真要正式注册商标或大规模投广告前建议花钱找律师或检索服务做一次正式查询 | 初筛无直接冲突，可以继续用这个名字；正式注册前再做一次专业检索 |
| 0.3 | `运营` ~~注册 keyvalet.dev~~ **已完成**；防御性注册 .ai / .io / .app（可选，非阻塞）；DNS 托管；提交 HSTS 预加载；开 DNSSEC；设 CAA | 域名可解析到 GitHub Pages | `https://keyvalet.dev` 返回官网 |
| 0.4 | `运营` GitHub 组织 `KeyValet` **已创建**；仓库 **已转移**到 `KeyValet/KeyValet`；本机 remote、README、`package.json`、两个插件 manifest、`install.sh`、`docs/index.html` 里的地址 **已更新为 keyvalet.dev** | 旧链接自动重定向 | `curl -fsSL https://keyvalet.dev/install.sh` 可用（待 DNS 生效） |
| 0.5 | `运营` 占住 npm、crates.io、PyPI 的 `keyvalet` 包名（发布占位版本） | — | ⏸ 2026-10-09 决定暂不占位：三个包名目前都还没人用，优先级不高，先放着；想占的时候 npm 已登录，crates.io/PyPI 还需单独登录 |
| 0.6 | `运营` D-U-N-S **已完成**；开 Apple Developer Program 组织账号（待办）；开 Stripe 账号（待办——Antom 已配置好但技术选型复盘后改用 Stripe 作为 Team 自助订阅的主要收款渠道，理由见下方说明；Antom 保留配置，以后若做 APAC 场景可用） | 两个账号 | Stripe 可创建 Product；Apple 账号可建 App ID |
| 0.7 | `开源` 开启 GitHub Private Vulnerability Reporting；加 `CODE_OF_CONDUCT.md`（Contributor Covenant 2.1）；加 issue 模板 4 种与 PR 模板（O 附录 D）；`CONTRIBUTING.md` 加 DCO 与 Rust 规范 | 文件进仓库 | 新建 issue 时出现模板选择 |
| 0.8 | `开源` 写 `GOVERNANCE.md`（O 附录 A）与商标政策页（O 附录 B） | 两个文件 | 从 README 链接到它们 |
| 0.9 | `市场` 写事故复盘第一篇（Nx s1ngularity）和 vs 1Password 对比页初稿 | 两篇 Markdown 放 `site/content/` | 各 1,200 字以内，全部一手来源 |

---

## 2. 阶段 0（第 1–4 周）：发布

目标：v0.1 发布进 HN 首页；500 star；500 安装；每一次弹窗都显示真实请求。

### 第 1 周

| # | 任务 | 产出 | 完成标准 |
| --- | --- | --- | --- |
| 1.1 | `代码` 在 `rust/crates/kv-core` 新增 `request.rs`：`UseRequest`、JCS 规范化、`digest`（A §7.2）；在 `src/helper/protocols/http.ts` 与 `kv-core/dispatch.rs` 的 HTTP 路径上生成它 | 结构体与单测 | 同一请求两次 digest 相同，改任一字段 digest 不同 |
| 1.2 | `代码` Touch ID 文案改为四行结构（P 附录 A）：凭据与层级、「agent 说：」用途、真实请求、来源；先用 method + host + path，`summarize` 下周接 | `auth-gate.ts` / `auth_gate.rs` 文案改动 | ⏳ 部分完成：`credential_http_request`/`credential_test` 的 Grant 弹窗现在会在用途前多显示一行「请求：method host/path」（`kv-core/dispatch.rs` 的 `grant_credential` + `kv-mcp/session.rs` 的 `request_value`/`grant`，已过 `cargo fmt`/`clippy -D warnings`/`build`/`test`，新增单测）；还没做的：风险层级标注、「agent 说：」前缀框出用途、`summarize` 人类可读摘要——这些要等策略引擎（见下）落地 |
| 1.3 | `代码` 审批绑定：审批结果带 digest 与一次性 nonce，执行前复核；nonce 存本地 SQLite（A §7.3） | `kv-core/approval.rs` | 重放同一审批第二次被拒；审批后改 body 被拒 |
| 1.4 | `代码` 把 `rust/` 工作区提交进 git，CI 跑 `cargo test` 与 clippy | `.github/workflows/rust.yml` | CI 绿 |
| 1.5 | `市场` 官网改版：Zola 项目 `site/`，首页（主张、GIF 占位、安装命令、三条支撑）、定价页、对比页、安全页；GitHub Pages 源切到 Actions 构建 | `site/` 与 `pages.yml` | keyvalet.dev 显示新站 |

### 第 2 周

| # | 任务 | 产出 | 完成标准 |
| --- | --- | --- | --- |
| 2.1 | `代码` 模板 `summarize` 规则：先写 OpenAI、Anthropic、GitHub、Stripe、AWS、Slack 六个（P §8） | `templates/catalog.json` 字段 + 渲染函数 | OpenAI 请求弹窗显示 `POST chat/completions · model=…` |
| 2.2 | `代码` 全部 MCP 工具加 annotations（A §5.1） | 工具定义改动 | `credential_list` 等在 Claude Code 中不再触发写操作级权限提示 |
| 2.3 | `代码` `kv-hook` 二进制 + Claude Code 适配器，替换 `claude-plugin/hooks/secrets.mjs` 的逻辑；`run.sh` 只做转发（A §5.2） | `rust/crates/kv-hook` | 现有三个 hook 场景行为不变 |
| 2.4 | `代码` Codex 适配器（同一 JSON 结构，目标 `~/.codex/hooks.json`） | 适配器 + manifest | 在 Codex 里把 key 写进 `.env` 被拦下 |
| 2.5 | `市场` 录 60 秒演示（`marketing/demo-script.md`）；GIF 进 README 顶部；社交预览图 | GIF + MP4 | README 首屏可见 |
| 2.6 | `市场` 按 `marketing/*.md` 定稿 Show HN、X 长帖、Reddit、Product Hunt 文案；附录 B 的质疑回答写成 FAQ 草稿 | 文案定稿 | 另一个人读一遍无歧义 |

### 第 3 周：发布周

| # | 任务 | 产出 | 完成标准 |
| --- | --- | --- | --- |
| 3.1 | `代码` 打 tag `v0.1.0`，GitHub Release（`marketing/release-notes.md`），安装脚本指向 release 产物 | Release 页 | 全新 Mac 上 `curl … | sh` 到首次代理调用 < 5 分钟 |
| 3.2 | `市场` D-3 预热帖（不提产品） | X 一条 | — |
| 3.3 | `市场` D0 周二或周三美西 8–10 点 Show HN；1 小时后 X 长帖；同日 r/ClaudeAI、r/mcp | 三处帖子 | 前两小时每条评论都回；安全质疑引用 SECURITY.md 条目 |
| 3.4 | `市场` D1 r/selfhosted、r/macapps、r/cursor；D2 dev.to 长文 | 帖子与文章 | — |
| 3.5 | `代码` 当天修 bug，当天发补丁版本，回帖附提交链接 | `v0.1.x` | HN 讨论里的可复现 bug 24 小时内修复 |
| 3.6 | `市场` D3 起提交 MCP 目录与 awesome 列表（`marketing/directories.md`） | PR 与提交记录 | 至少 5 处收录 |

### 第 4 周

| # | 任务 | 产出 | 完成标准 |
| --- | --- | --- | --- |
| 4.1 | `代码` `keyvalet scan`：扫描 `.env*`、`~/.claude.json`、`.cursor/mcp.json`、`~/.codex/config.toml`、shell rc；原生窗口勾选；导入；替换占位符；确认后删备份（P J2） | `kv-cli scan` + MCP 工具 `credential_scan` | 10 条密钥 2 分钟内迁完；原文件 grep 不到有效密钥 |
| 4.2 | `代码` Cursor 适配器原型（`~/.cursor/hooks.json`，退出码 2） | 适配器 | 在 Cursor 里写 key 进文件被拒并给出替代命令 |
| 4.3 | `代码` 核实 Grok 的 MCP 与 hook 能力；MCP 配置写进安装脚本 | `docs/runtimes.md` 一节 | 文档写明支持程度 |
| 4.4 | `代码` MCP SDK 升级到 2026-07-28 规范；per-session 绑 stdio 进程 | 依赖升级 | 现有测试通过 |
| 4.5 | `市场` 提交 Claude Code 官方插件市场、Codex plugins、cursor.directory | 三处提交 | 至少一处上架 |
| 4.6 | `市场` Product Hunt（star 与反馈攒够后）；事故复盘第二篇（Comment and Control） | PH 页 + 博客 | — |
| 4.7 | `市场` 开始外联设计合作伙伴：从 HN/Reddit 评论和 GitHub issue 里挑 20 个目标，每周 5 封（M 附录 A） | 外联记录表 | 第 8 周前至少 3 次通话 |
| 4.8 | `运营` 发布 v0.2，中英文 release notes；第一次月度复盘（附录 C） | Release + 复盘页 | — |

阶段 0 门槛：发布完成；安装 ≥ 500；首批反馈归类进 issue。未达标见 §7。

---

## 3. 阶段 1（第 2–4 月）：策略与 Linux

目标：1 万安装；有 ≥3 条凭据的周活占比 ≥ 20%；每周活每天审批 ≤ 3 次且有拒绝率数据；Linux 可用。

### 第 2 月

| # | 任务 | 产出 | 完成标准 |
| --- | --- | --- | --- |
| 5.1 | `代码` 策略引擎 v1：T0–T3 分级、`policy.yaml` 语法（A 附录 B）、三级来源合并（org 预留、用户、仓库只能收紧）、`keyvalet policy show/test` | `kv-core/policy.rs` + `kv-policy` | 用例矩阵 4 模式 × 4 层级全过；仓库策略放宽条目被忽略并审计 |
| 5.2 | `代码` grant 范围精确化与 30 秒节流（A §7.6）；T2 永不被 Remember 覆盖 | `dispatch.rs` 改动 | T2 在 remember 模式下仍弹窗 |
| 5.3 | `代码` 「以后自动放行」推荐：连续 5 次批准同一凭据只读请求后出现选项，接受写入用户策略 | 弹窗选项 | 本地统计不含明文 |
| 5.4 | `代码` opt-in 遥测：安装、周活、凭据数、审批次数、拒绝率、`proxy_only` 占比；本地可查看将上报内容；自建 relay 默认关 | `kv-cli telemetry show` | 上报内容无凭据名以外的字段 |
| 5.5 | `市场` 博客「让审批弹窗值得看」；X 长帖；v0.3 发布 | 博客 + Release | — |

### 第 3 月

| # | 任务 | 产出 | 完成标准 |
| --- | --- | --- | --- |
| 6.1 | `代码` Linux helper：系统用户 `keyvalet`、systemd 服务、Unix socket + peer-uid、TPM2 可选、软件密钥回退并警告（A §8.1、§16） | `install.sh` Linux 分支 | Ubuntu 22.04 与 Debian 12 上 J1 可完成 |
| 6.2 | `代码` TTY Approver（仅 T0/T1）；无 GUI 时自动选用 | `kv-core/approvers/tty.rs` | T2 在无手机的 Linux 上被拒并说明 |
| 6.3 | `代码` `keyvalet hooks install --all`：检测四个运行时，幂等写入 | CLI | 卸载可逆 |
| 6.4 | `代码` 审计哈希链 + `keyvalet audit export/verify`（A §12） | `kv-audit` | 篡改一条后 `verify` 报错 |
| 6.5 | `市场` 事故复盘第三篇（GhostSplice）；5 分钟演示视频；争取第一个播客 | 内容 | — |
| 6.6 | `市场` r/selfhosted 与 Linux 社区发 Linux 支持；v0.4 发布 | Release | — |

### 第 4 月

| # | 任务 | 产出 | 完成标准 |
| --- | --- | --- | --- |
| 7.1 | `代码` 能力令牌（A §7.5）：Mac 签发、CI 使用、`keyvalet grant`；GitHub Actions 示例工作流 | `kv-core/capability.rs` + 示例仓库 | 示例 CI 跑通且仓库 secrets 为空 |
| 7.2 | `代码` Mac helper 迁到 Unix socket（stdin/stdout 保留一个版本） | 改动 | 两种模式都能跑现有测试 |
| 7.3 | `代码` 中英文全覆盖走查：弹窗、CLI、错误 | 截图清单 | 无遗漏 |
| 7.4 | `开源` CI 加 `cargo-deny`、gitleaks、Dependabot；`good first issue` 10 个（模板为主）；写 `templates/CONTRIBUTING.md`（O 附录 C） | 配置 + issue | 首个外部模板 PR 合并 |
| 7.5 | `市场` 季度研究「agent 配置里的密钥」第一期；vs Infisical 对比页；模板页上线 | 内容 | — |
| 7.6 | `运营` 阶段 1 门槛复盘；第 9 个月融资复盘的指标口径定下来 | 复盘页 | — |

阶段 1 门槛：安装 ≥ 1 万；≥3 凭据周活占比 ≥ 20%；审批次数与拒绝率有 4 周数据；Linux 上有真实用户。

---

## 4. 阶段 2（第 5–8 月）：relay 与 Team v1 收费

目标：第 6 个月 3 家付费团队；D30 留存 ≥ 25%；`proxy_only` 占比 ≥ 60%；10 家设计合作伙伴在用。

### 第 5 月

| # | 任务 | 产出 | 完成标准 |
| --- | --- | --- | --- |
| 8.1 | `代码` vault v2（A §8.4）：UMK、每设备包裹、CEK、恢复码；v1 迁移 | `kv-vault` v2 | 迁移后旧备份保留 30 天；恢复码能解 |
| 8.2 | `代码` `kv-server` relay feature：设备注册、在线表、待审批队列、blob 存储、限流（A §10.3）；`docker compose` 自建部署；Postgres | 服务端 + `deploy/` | 自建一键起；两台 Mac 经 relay 同步密文 |
| 8.3 | `代码` `kv-relay-client` 用户态进程；helper 代签（A §3.2） | crate | helper 无出网连接（`lsof` 验证） |
| 8.4 | `运营` 官方 relay 部署到美国 VPS，Caddy TLS，备份；法律页初稿（隐私、条款、数据处理） | relay.keyvalet.dev | 可用；法律页上线 |
| 8.5 | `市场` 事故复盘第四篇（CVE-2026-21852）；设计合作伙伴通话继续 | 内容 | 累计 ≥ 6 家在谈 |

### 第 6 月：开始收费

| # | 任务 | 产出 | 完成标准 |
| --- | --- | --- | --- |
| 9.1 | `代码` Team v1（A §14.1，`ee/`）：邮箱魔法链接、组织与成员、共享凭据（成员设备包裹 CEK）、移除即轮换、org 策略签名分发、GitHub OIDC CI 身份、审计导出 | `ee/crates/kv-team` | J6 验收：创建组织到成员用上共享凭据 < 15 分钟 |
| 9.2 | `代码` Web 控制台 v1（A §18.7）：登录、组织、成员、席位与账单、策略、设备、共享凭据元数据、审计统计 | `kv-server` console feature + `apps/web` | Lead 不用 CLI 完成 J6 |
| 9.3 | `代码` Stripe：Checkout、Portal、webhook、权益令牌、14 天试用、7 天离线宽限 | `ee/crates/kv-billing` | 断网 7 天功能不降级；试用到期不扣款 |
| 9.4 | `市场` v0.5 发布；Product Hunt 第二次（Team）；第一篇设计合作伙伴案例；定价页上线 | Release + 案例 | 3 家付费团队 |
| 9.5 | `运营` 法律页定稿；Stripe 账户审核通过 | — | 可收款 |

### 第 7 月

| # | 任务 | 产出 | 完成标准 |
| --- | --- | --- | --- |
| 10.1 | `代码` 透明代理 opt-in（A §5.4）：会话 token、CA 在 helper、叶证书、占位符与 `--inject`、`keyvalet run` | `kv-proxy` 改动 + CLI | Python 与 Node SDK 示例不改代码即受保护；无 token 连接被拒 |
| 10.2 | `代码` 存储后端：keychain、1Password（`op://` 引用）、Infisical、github-oidc | `kv-storage-*` | 1Password 里轮换后下一次请求自动生效 |
| 10.3 | `市场` 在 Infisical 与 1Password 社区发集成教程；事故复盘第五篇（DuneSlide） | 内容 | — |
| 10.4 | `开源` 邀请第一位备用维护者；发布可复现构建（Rust，双机比对）与 Sigstore 签名；SBOM | 配置 | `install.sh` 校验签名 |

### 第 8 月

| # | 任务 | 产出 | 完成标准 |
| --- | --- | --- | --- |
| 11.1 | `代码` `kv-mcp` Rust 版替换 TS server；安装脚本默认切换；TS 保留一个版本 | crate | 功能对齐；安装体积下降 |
| 11.2 | `代码` 控制台与 Team 的打磨：邀请流程、移除成员的轮换任务、审计导出格式 | 改动 | 设计合作伙伴反馈闭环 |
| 11.3 | `运营` 决定新成员 CEK 包裹方案（在线持有者 vs 组织托管设备）（A §14.1） | ADR | 记录 |
| 11.4 | `市场` v0.6 发布；季度研究第二期；月度「本月进展」 | 内容 | — |
| 11.5 | `运营` 阶段 2 门槛复盘 | 复盘页 | — |

阶段 2 门槛：付费团队 ≥ 3（第 6 月）且 ≥ 8（第 8 月）；D30 ≥ 25%；`proxy_only` ≥ 60%；10 家设计合作伙伴在用。

---

## 5. 阶段 3（第 9–14 月）：iPhone 与 Team 完整版

目标：20 家付费团队；周活 8,000；手机审批上线；第 9 个月融资复盘。

### 第 9 月：融资复盘

| # | 任务 | 产出 | 完成标准 |
| --- | --- | --- | --- |
| 12.1 | `运营` 融资复盘（S §1.3）：周活 ≥ 8,000？设计合作伙伴 ≥ 10？付费团队 ≥ 5？三条全达标则开始接触 3–5 家投资人（a16z、boldstart、Acrew 一类投过 agent 身份的），否则继续自举 | 一页决定 | 记录 |
| 12.2 | `代码` `kv-ffi`（UniFFI）：HPKE、审批签名、配对、审计解密的 Swift 包；契约测试 | crate + 生成包 | Swift 单测过 |
| 12.3 | `代码` iPhone App 骨架：配对（二维码 + 6 位安全码）、两把 SE 密钥、注册设备（A §8.3） | `apps/ios` | 真机配对成功 |
| 12.4 | `市场` 事故复盘继续（新事件）；播客 | 内容 | — |

### 第 10–11 月

| # | 任务 | 产出 | 完成标准 |
| --- | --- | --- | --- |
| 13.1 | `代码` `kv-push` 推送网关（美国托管，只转发 id）；relay 唤醒；NSE 解密展示（30 秒内）；App Attest | 服务 + App | 锁屏批准 < 5 秒；打开 App 强审批 < 15 秒 |
| 13.2 | `代码` `remote-phone` Approver；Linux 与 CI 的 T2 走手机；审批路由到 owner；N-of-M 聚合（A §14.2） | `kv-core/approvers/remote.rs` | 2/3 审批后执行 |
| 13.3 | `代码` 手机前台短请求执行（可选，不做流式） | App | — |
| 13.4 | `市场` App Store 提审；v0.7 发布；视频 | 上架 | 通过审核 |

### 第 12–14 月

| # | 任务 | 产出 | 完成标准 |
| --- | --- | --- | --- |
| 14.1 | `代码` Ory Hydra 部署；OIDC SSO（Okta、Entra、Google）接入控制台（A §10.1） | 配置 + 页面 | 用 Google 登录控制台 |
| 14.2 | `代码` 控制台「浏览器作为设备」：WebCrypto 不可导出密钥、审计解密、Quick 审批（A §18.7） | `apps/web` | 不装任何东西能看审计明细 |
| 14.3 | `代码` Bitwarden 后端；凭据轮换（模板轮换端点） | crate | 一键换 key 并同步成员 |
| 14.4 | `运营` 第一次第三方安全审计（范围：核心、relay、App）；公开报告；修复 | 报告 | 高危清零 |
| 14.5 | `市场` Team 完整版定价（18/15）上线；v1.0 发布；安全社区分享（OWASP Agentic 映射文档） | Release + 文档 | 20 家付费团队 |
| 14.6 | `运营` 阶段 3 门槛复盘；写阶段 4 的详细计划 | 复盘页 | — |

阶段 3 门槛：付费团队 ≥ 20；周活 ≥ 8,000；App 上架；审计报告公开。

---

## 6. 阶段 4（第 15–24 月）：CI 离线执行、远程 MCP、Enterprise

目标：5 家企业合同，或附加项收入 ≥ 5 万美元/年。按季度列。

| 季度 | 代码 | 运营与市场 |
| --- | --- | --- |
| 第 15–17 月 | `kv-enclave`：Rust 核心跑在 Nitro；可复现 EIF；PCR0 随客户端发布；iOS 与 Mac 端证明验证（A §11）；BYO-KMS 路径；托管 KMS 信任声明进产品 | 找 3 家有 CI 离线需求的付费团队试用；Terraform 文档 |
| 第 18–20 月 | 远程 MCP 端点（Hydra 作 AS、PRM、CIMD）（A §10.4）；ChatGPT 与 Claude App 接入测试；Android App（StrongBox） | Enterprise 自托管 Terraform 发布；SOC 2 Type I 启动；第一份企业合同 |
| 第 21–24 月 | SCIM；Okta Cross-App Access；Vault/OpenBao 后端；Windows 审批端；macOS 菜单栏（可选） | SOC 2 Type I 完成；参与 MCP ext-auth 讨论；第 24 个月结局评估（§9） |

---

## 7. 门槛与决策树

| 检查点 | 达标 | 不达标 |
| --- | --- | --- |
| 阶段 0 末（第 1 月）：安装 ≥ 500 | 进阶段 1 | 问题在定位还是分发？HN 无反应则重写首屏与 Show HN 文案，两周后再发一次；安装有但不用则先修 J1 |
| 阶段 1 末（第 4 月）：安装 ≥ 1 万、≥3 凭据周活占比 ≥ 20% | 进阶段 2 | 安装不够：加大内容与目录提交，延长阶段 1 一个月；凭据数不够：`scan` 和模板是瓶颈，优先补 |
| 第 6 月：付费团队 ≥ 3 | 继续 | 0 家：访谈 10 个 Lead 找原因，调整 Team v1 范围，再给两个月；两个月后仍为 0 → **降级为 side project**（§9 D） |
| 阶段 2 末（第 8 月）：付费团队 ≥ 8、D30 ≥ 25% | 进阶段 3 | 付费 3–7 家：继续但推迟 iPhone App，先把 Team v1 做深；D30 低：审批疲劳或稳定性问题，先修 |
| 第 9 月融资复盘：周活 ≥ 8,000、合作伙伴 ≥ 10、付费团队 ≥ 5 | 接触投资人，目标 200–400 万美元种子轮，同时继续自举 | 不融资，按基准线继续；缩减阶段 3 范围（先手机审批，后 SSO） |
| 阶段 3 末（第 14 月）：付费团队 ≥ 20、周活 ≥ 8,000 | 进阶段 4 | 10–19 家：阶段 4 只做 BYO-KMS 的 CI 离线执行，不做 Enterprise；< 10 家：停止新功能，维护模式，评估出售 |
| 第 24 月 | §9 | §9 |

通用规则：任何阶段门槛连续两次复盘不达标，就触发 §9 的结局评估，不再往下投入。

---

## 8. 每周与每月的固定节奏

### 每周

| 日 | 做什么 |
| --- | --- |
| 周一 | 看指标（安装、周活、审批次数、拒绝率、付费）；定本周三类任务各至少一项 |
| 周二至周四 | 代码；每天最后 30 分钟回 issue 与 discussion |
| 周三 | 发一条有内容的 X 帖（事故、changelog、安全提示） |
| 周五 | 内容写作 2 小时；外联 5 封；更新本文的勾选项 |
| 任意 | 安全报告 24 小时内确认 |

### 每月

- 发版本与中英文 release notes；发「本月进展」discussion。
- 一篇事故复盘或技术文。
- 复盘（附录 C），更新本文时间表。
- 设计合作伙伴每家一次 30 分钟通话。

### 每季度

- 「agent 配置里的密钥」研究一期。
- 对比页更新。
- 依赖与许可审计（cargo-deny 报告）。
- 决定下季度内容系列。

---

## 9. 第 24 个月的结局与准备

| 结局 | 信号 | 从现在开始的准备 |
| --- | --- | --- |
| A 继续自举 | ARR 30–50 万美元，增长稳定，一个人加一两个合作者能维持 | 保持成本结构；第 18 月起招第一位工程师或 GTM 合伙人 |
| B 融资扩张 | 第 9 月或第 14 月门槛达标；投资人主动接触 | 数据室：指标、安全审计报告、设计合作伙伴案例、架构文档；法务整理（Simvito Limited 持有 IP、商标、域名） |
| C 被收购 | 收购方主动来（GitGuardian、Infisical、Doppler、Bitwarden、Teleport、Snyk、1Password、运行时厂商） | 只接受主动找上门的；保持代码与文档可交接；IP 归属干净；开源承诺写在 GOVERNANCE 里，收购不能撕毁 |
| D 降级为开源项目 | 第 6 月零付费且两个月未改善，或连续两次门槛不达标 | 提前 90 天公告；发布最后一个可自建的完整版；把维护交给备用维护者；个人把项目当作作品与简历 |

无论哪种结局，以下资产都有价值：开源代码与文档、安装基数、模板目录、事故复盘内容、安全审计报告、设计合作伙伴关系。前 8 个月的工作都在积累这些。

---

## 附录 A：账号与工具清单

| 类别 | 项目 |
| --- | --- |
| 域名与 DNS | keyvalet.dev 主域名；.dev/.io/.app 防御；HSTS 预加载；DNSSEC；CAA |
| 代码与发布 | GitHub 组织 `keyvalet`；Actions；Sigstore；npm / crates.io / PyPI 包名 |
| 公司与收款 | Simvito Limited；D-U-N-S；Apple Developer Program（组织）；Stripe |
| 托管 | 美国 VPS（relay、push、Hydra、站点镜像）；阶段 4 AWS 账号（EC2、KMS、Nitro） |
| 安全 | Private Vulnerability Reporting；security@keyvalet.dev；赏金规则页 |
| 市场 | X 账号；dev.to；Product Hunt；MCP 目录账号；Claude Code / Codex / Cursor 插件提交账号 |
| 分析 | 无 cookie 的服务端站点统计；opt-in 遥测后端（随 relay 部署） |
| 法律 | 隐私政策、服务条款、数据处理说明；商标检索记录；律师一次咨询（出口合规） |

## 附录 B：任务依赖关系

```
UseRequest/digest → 弹窗显示真实请求 → 审批绑定与 nonce → 策略引擎 → grant 范围 → 推荐规则
kv-hook(Claude Code) → Codex 适配器 → Cursor 适配器 → hooks install --all
vault v2 → relay → relay-client → Team v1 共享凭据 → 控制台 → Stripe → 收费
Linux helper → TTY approver → 能力令牌（CI）→ GitHub OIDC（Team）
kv-ffi → iPhone 配对 → kv-push → remote-phone approver → 审批路由 / N-of-M → Linux 强审批
Hydra → SSO → 远程 MCP（阶段 4）
可复现 Rust 构建 → 可复现 EIF → PCR 发布 → enclave（阶段 4）
官网改版 → 发布周 → 插件市场 → 设计合作伙伴 → 付费团队
```

## 附录 C：每月复盘模板

```
# YYYY-MM 复盘

指标：安装 / 周活 / ≥3 凭据周活占比 / D30 / 每周活每天审批次数 / 拒绝率 / proxy_only 占比 / 付费团队 / 席位 / MRR
本月完成：（勾选行动指南条目）
本月未完成与原因：
用户反馈前三条：
内容效果：哪篇带来安装，哪个渠道该停
下月三类任务：代码 / 产品文档 / 市场运营
门槛距离：下一个检查点还差什么
风险变化：竞品动作（Infisical PR #434、1Password）、平台变化、依赖漏洞
```
