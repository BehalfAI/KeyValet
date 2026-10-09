# KeyValet 战略方案：调研汇总、最终架构与商业模式

- 日期：2026-10-07
- 决策更新：2026-10-09，平台支持与密钥保护按[产品 §1.4](product-2026-10.zh-CN.md#14-平台支持与密钥保护)执行：Mac 硬件保护先行，Linux / CI 下一阶段优先，Windows 按需求排期，云端隔离执行先做 AWS。
- 作者：Guang（调研与整理由 Claude 协助）
- 状态：决策已定，见 §1.3；数据截至 2026-10-07。第三版（2026-10-08）按整体 review 改为「独立开发者版本」：Free + Team 先行，手机阶段 3，enclave 与远程 MCP 阶段 4；第二版（10-07）对第一版的「未核实清单」逐项复核，已核实项去掉了标记并改为官方数字；仍标 [未核实] 的内容没有在一手来源上确认，见 §15.2 和 §15.3
- 注意：`docs/` 目录由 GitHub Pages 对外发布，本文含定价与财务假设，提交前请确认是否要公开
- 配套：技术架构见 `docs/architecture-2026-10.md`（阶段 0–3，首批运行时 Claude Code、Codex、Cursor、Grok）；产品规划见 `docs/product-2026-10.zh-CN.md`；营销规划见 `docs/marketing-2026-10.zh-CN.md`；开源规划见 `docs/opensource-2026-10.zh-CN.md`；执行版行动指南见 `docs/action-plan-2026-10.zh-CN.md`

## 目录

1. 摘要与已拍板决策
2. 市场与需求
3. 竞品全景
4. 平台与分发
5. 标准与协议
6. 技术可行性核实
7. 最终架构
8. 产品分层与定价
9. 商业模型与财务假设
10. 路线图
11. GTM
12. 风险与对策
13. 融资与退出
14. 未来 90 天行动清单
15. 来源与未核实清单

---

## 1. 摘要与已拍板决策

### 1.1 一句话定位

KeyValet 是 AI agent 的「凭据运行时」（credential runtime）：agent 在笔记本、CI、远程服务器和云端使用人持有的凭据时，必须经过策略、审批、短期签发和代理注入，自己永远拿不到密钥。个人版全部免费，收入来自 Team 与 Enterprise；服务端只做自建 Docker 或 AWS EC2 + Nitro Enclaves 两种部署，任何情况下都看不到明文。

- 对开发者：「1Password 管你的登录，KeyValet 管你的 API。」
- 对企业：「AI agent 在终端和 CI 上的运行时访问控制与审计」，挂「AI 安全」或「NHI」预算线，而不是「又一个密钥库」。

截至 2026-10-07 这个位置没有成熟玩家，窗口估计 12–18 个月。

**独立开发者版本（第三版定稿）**：产品压成 Free + Team 两档先行，第 6 个月起靠 Team v1 自助付费；iPhone App 放阶段 3；enclave 离线执行和远程 MCP 端点放阶段 4，并且只作为 Team 的 CI 附加项；个人 Cloud SKU 取消。理由见 §8、§10 和 §12。

### 1.2 五条核心判断

1. 四起真实攻击（Nx s1ngularity、Claude Code CVE-2026-21852、Comment and Control、GhostSplice）都依赖「agent 能读到原始密钥」这一前提，KeyValet 的核心性质让这一类攻击失效。
2. 泄露在加速：GitGuardian 2026 报告称 Claude Code 参与的提交泄密率 3.2%，是人工基线 1.5% 的两倍多；公开 MCP 配置里有 24,008 个密钥，2,117 个仍有效。
3. 平台不做本地这一层：八个运行时都把 secret 管理放在云侧沙箱，本地人工授权一致外包给 1Password，而 1Password 只覆盖浏览器登录；Anthropic 在 issue #70716 明确拒绝做账号级密钥库。
4. 个人不为安全付费（Bitwarden Premium 1.65 美元/月，1Password 消费者收入不到 25%），团队愿为 SSO、共享凭据、CI 身份和审计付 15–20 美元/席位/月。
5. 退出市场活跃：9 个月内 6 笔并购，金额 1.28 亿到 10 亿美元；Natoma 27 人、成立两年，以 1.28 亿美元卖给 Snowflake。

### 1.3 已拍板的决策

| 决策 | 结论 | 理由 |
| --- | --- | --- |
| 产品档位 | 独立开发者版本：Free + Team 先行；取消个人 Cloud SKU；enclave 离线执行作为 Team 的「CI 附加项」放阶段 4；iPhone App 放阶段 3 | 收入最早来自 Team 自助付费；个人为安全付费的意愿极低；enclave 是最重的工程，不能排在收入前面 |
| 开源许可 | 核心与 relay 保持 Apache-2.0；Team 功能放 `ee/` 目录，源码可见的商业许可 | 「可验证」是品牌根基，闭源与之矛盾；Infisical 同一模式已被市场接受 |
| 公司主体 | 用现有的 Simvito Limited 作为运营主体；Stripe、Apple 开发者账号（组织账号需 D-U-N-S）、Team 合同都挂在它下面；品牌仍为 KeyValet | 已有主体省去注册与开户时间；收款、上架、收购谈判都需要一个海外实体 |
| 官方 relay | 免费提供，合理使用额度：3 台设备、每月 2,000 次远程审批、待审批请求保留 7 天；部署在美国（us-east-1 或美国 VPS），由海外主体运营 | 推送网关反正要运营；边际成本接近零；对美国开发者，国内托管即便只存密文也是信任红旗 |
| 价格 | Team v1 15 美元/席位/月，年付 12，机器身份不限量（合理使用）；手机审批路由与 SSO 上线后 Team 完整版 18/15；enclave 执行按 0.5 美元/千次计量（阶段 4，每席位每月含 2,000 次）；Enterprise 5 万美元/年起（阶段 4 以后） | 锚点：GitGuardian 约 18、Infisical 20、Doppler 21；CI 重度团队不能被按个计费的机器身份卡住 |
| 优先级 | 阶段 1 策略引擎 + 绑定真实请求的审批 + Linux + Codex/Cursor hooks → 阶段 2 relay（无推送）+ Team v1 收费 → 阶段 3 iPhone App → 阶段 4 enclave 与远程 MCP | 先把能收费的做出来；手机和 enclave 都不是收费的前置条件 |
| 融资 | 默认自举。第 9 个月复盘：周活 ≥ 8,000、设计合作伙伴 ≥ 10 家、付费团队 ≥ 5 家，达标则融 200–400 万美元种子轮；并购只接受主动找上门的 | 投资人有明确论点（a16z 的 KYA、YC RFS），但估值取决于安装基数 |
| 技术栈 | 服务端 Rust；OAuth 2.1 授权服务器用 Ory Hydra，不自研；iOS 用 Swift，Android 用 Kotlin；首发 us-east-1 | 一份核心三端复用；授权服务器是高风险安全组件，一个人不该自己写 |
| 默认安全策略 | 默认授权模式保持「按凭据」；T2 敏感操作即使在 remember 模式也强制逐次强审批；透明代理 opt-in 且必须带会话 token | 不降低现有默认安全性；对抗审批疲劳（业内引用的「93% 弹窗被批准」说法来源待补） |
| 近期主要对手 | Infisical Agent Vault 列为 Team 细分的近期主要对手，1Password 为企业侧威胁；对 Infisical 两手：抢它没有的（生物识别逐次审批、token 签发、hooks、手机），同时把它做成存储后端 | 它开源、有融资、人工审批 PR 已存在，一旦合并再补 MCP server 就覆盖团队价值的大半 |
| 命名 | 法律主体 Simvito Limited，产品品牌 KeyValet；GitHub 组织建议在发布前从 BehalfAI 改为 `keyvalet`（GitHub 自动重定向，此时成本最低），把三个名字减到两个；主域名 keyvalet.dev（.com 自 2004 年被他人持有；.dev 是开发者工具惯例，整个顶级域强制 HTTPS，比 .ai 便宜且不与"AI"重复造信号——产品名和标语已经说明这是 AI agent 的工具），防御性注册 .ai/.io/.app 并 301 到主域名（可选，非阻塞）；注册后提交 HSTS 预加载、开 DNSSEC 与 CAA；阶段 0 做一次商标检索（USPTO、WIPO、UKIPO、CNIPA、HK IPD，第 9/42 类）；协议暂名 KeyValet Delegation Protocol v0。IETF 的 user-mediated delivery 草案是资源方模型且声明专利申请中，只作参考，不采用其术语 | 已有品牌、域名和落地页资产；避开专利风险 |

### 1.4 两处对此前方案的纠正（来自 Apple 文档核实）

1. iPhone 不能在后台执行 30–60 秒的 API 调用（后台唤醒约 30 秒）。手机的角色是审批和释放密钥，执行请求的是 Mac/Linux helper、自建执行端或 Nitro enclave；手机只有在前台时才顺手执行短请求。
2. 锁屏上的「快速批准」不是 Face ID 绑定的。`authenticationRequired` 只强制设备解锁，Secure Enclave 里绑定生物识别的密钥在后台无法使用。审批分两级：锁屏快速批准（设备解锁门禁，低风险）和打开 App 的强批准（Face ID 绑定密钥，高风险）。Duo 和 Okta Verify 都是这个模式。

---

## 2. 市场与需求

最硬的需求证据是攻击者已经在真实事件中专门利用「agent 可读原始密钥」，而治理工具几乎空白：79% 的企业在生产环境运行 agent，仅 2% 部署了专用安全工具。

### 2.1 攻击事件链

四条路径（恶意依赖、不可信 CI 输入、受信任的 MCP 通道、恶意仓库配置）都依赖同一个前提，而且 Anthropic、Google、Microsoft 三家都为此付了漏洞赏金。

| 事件 | 日期 | 要点 | 来源 |
| --- | --- | --- | --- |
| GhostSplice | 2026-08-11 | 恶意 MCP 服务器把外泄指令拆到工具描述与结果中，Codex CLI 自行完成窃取；前作 Ghostcommit（2026-06） | [ASSET](https://asset-group.github.io/disclosures/ghostsplice/) |
| Cursor DuneSlide 等 CVE | 2026-02 至 07 | 零点击提示注入到 RCE（CVSS 9.8）；工作区 `.claude/settings.local.json` 钩子无需批准即执行 | [Cato Networks](https://www.catonetworks.com/blog/duneslide-two-critical-rce-vulnerabilities/) |
| Comment and Control | 2026-04-15 | PR 标题和 Issue 评论劫持 Claude Code、Gemini CLI、Copilot 的 CI agent 外泄 GITHUB_TOKEN 等；Anthropic 评 CVSS 9.4 | [SecurityWeek](https://www.securityweek.com/claude-code-gemini-cli-github-copilot-agents-vulnerable-to-prompt-injection-via-comments/) |
| Claude Code 源码泄露加三个 CVE | 2026-03-31 至 04 | 512k 行源码经 source map 外泄；CVE-2026-35020/21/22 链至凭证外泄 | [Phoenix Security](https://phoenix.security/claude-code-leak-to-vulnerability-three-cves-in-claude-code-cli-and-the-chain-that-connects-them/) |
| Claude Code CVE-2026-21852 | 2026-02 | 仓库 settings 设置 `ANTHROPIC_BASE_URL`，信任提示弹出前即泄露 API key（Check Point） | [The Hacker News](https://thehackernews.com/2026/02/claude-code-flaws-allow-remote-code.html) |
| Nx s1ngularity | 2025-08-26 | 恶意 npm 包调用本机 claude/gemini/q CLI（加 `--dangerously-skip-permissions`）搜刮 SSH、.env、token；2,300+ 密钥、225 个组织、6,700 个私有库被公开；Wiz 称约半数受害者装有 AI CLI | [GitGuardian](https://blog.gitguardian.com/the-nx-s1ngularity-attack-inside-the-credential-leak/) · [SecurityWeek](https://www.securityweek.com/over-6700-private-repositories-made-public-in-nx-supply-chain-attack/) |
| Amazon Q VS Code 扩展 1.84.0 被植入恶意提示 | 2025-07 | 攻击者 PR 注入「清空文件系统与云资源」提示，约 100 万安装 | [ReversingLabs](https://www.reversinglabs.com/blog/aws-amazonq-ai-incident) |

### 2.2 泄露与治理缺口的数据

- [GitGuardian State of Secrets Sprawl 2026](https://www.gitguardian.com/state-of-secrets-sprawl-report-2026)：2025 年公开 GitHub 新增 2,865 万条硬编码密钥（+34%，史上最大年增）；Claude Code 协作提交的泄密率 3.2%，人工基线 1.5%；公开 MCP 配置文件中 24,008 个唯一密钥，2,117 个仍有效；AI 服务密钥泄露 +81%。[后续博文](https://blog.gitguardian.com/ai-coding-agents-credential-security/)直接点名 Cursor、Claude Code、Copilot 把凭证散落在配置、环境变量、日志、shell 历史和临时文件中。
- [SailPoint Horizons 2026](https://www.globenewswire.com/news-release/2026/10/06/3375448/0/en/sailpoint-report-finds-79-of-enterprises-run-ai-agents-in-production-yet-only-2-have-deployed-purpose-built-security.html)（2026-10-06）：79% 企业在生产运行 agent，2% 有专用安全工具，43% 有成熟的 agent 访问流程。厂商调查，可能偏向身份成熟度高的企业。
- [Gravitee 2026](https://www.gravitee.io/state-of-ai-agent-security)：45.6% 的团队仍用共享 API key 做 agent 认证，88% 发生过事件。
- [Akeyless 2026](https://www.akeyless.io/blog/2026-ai-agent-identity-security-survey/)：仅 44% 知道 agent 密钥存放位置；83% 认为单个 agent 凭证失陷可横向多个核心系统。
- [Okta CISO Insights 2026](https://www.okta.com/newsroom/articles/global-ciso-insights-2026/)：81% 的 CISO 担忧 AI 过度访问，不到一半有信心识别和控制 agent。
- [CSA](https://cloudsecurityalliance.org/press-releases/2026/04/21/new-cloud-security-alliance-survey-reveals-82-of-enterprises-have-unknown-ai-agents-in-their-environments)（2026-04-21）：82% 企业环境中存在未知 agent；33% 不知道 agent 凭证的轮换频率。
- [VentureBeat 调查](https://venturebeat.com/ai/the-agent-security-gap-54-of-enterprises-have-already-had-an-ai-agent-incident-and-most-still-let-agents-share-credentials)：54% 企业已有 agent 事件或险情；仅 32% 给每个 agent 独立身份；18% 隔离高危 agent。
- [Gartner](https://www.gartner.com/en/newsroom/press-releases/2026-04-28-gartner-identifies-six-steps-to-manage-artificial-intelligence-agent-sprawl)（2026-04-28）：2028 年 25% 的企业泄露与 agent 滥用相关，F500 平均 15 万个 agent；「一刀切禁用 agent 只会制造影子 AI」，为「治理而非禁用」背书。
- 预算：[IANS 2026](https://iansresearch.com/resources/all-blogs/post/security-blog/2026/04/19/ai-agents-are-creating-an-identity-security-crisis-in-2026) 安全预算仅 +5%，但 69% 的 CISO 把 AI 列为新增预算首位，24% 已设独立 AI 安全预算线；[Open Future Forum](https://openfutureforum.com/research/ciso-ai-leverage-report-september-2026)（2026-09）37% 有专项 AI 安全预算，「保护 AI agent 及其访问」被三分之二受访者列为头号问题。
- 审批疲劳：调研中引用的「Claude Code 权限弹窗 93% 被批准」标注为 Anthropic 披露，但复核时在 Anthropic 官方页面（含 Managed Agents 博客）未找到原文 [来源待补]。无论具体数字如何，审批疲劳都是这个赛道最大的产品风险。

**谁买单，哪条预算线**：Team 档由平台或 DevEx 负责人刷卡购买，对标 Doppler、Infisical、Tailscale；Enterprise 由 CISO 下属的 IAM/NHI 或 AppSec 负责人购买，挂「NHI / 机器身份」或新设的「AI 安全」预算线。端点预算（EDR）基本分不出来，传统密钥管理预算被 Vault 和 Doppler 占着。最顺的叙事是「agent 身份与运行时访问控制」。

### 2.3 市场规模与采用

- 密钥管理市场 2025–2026 年约 42–51 亿美元，CAGR 13.4–14.2%（Mordor、KBV、ResearchAndMarkets）；NHI 市场广义 82–122 亿（2026），狭义专用工具 36–45 亿。
- [Stack Overflow 2026](https://survey.stackoverflow.co/2026/ai/data/ai-select)（2026-10-06，17k+ 答卷）：83% 用 AI 工具，66% 用编码助手或 agent，26% 用自主 agent；agent 用户中 Claude Code 66%、Copilot 59%，73% 每日使用。
- [JetBrains](https://blog.jetbrains.com/research/2026/08/ai-coding-agent-adoption-2026/)（2026-08，15k 专业开发者）：90% 每周用编码 agent，68% 每日；Claude Code 全球渗透 39%，美国 47%。
- 企业生产使用率：SailPoint 79%，KPMG 52%。GitHub 1.8 亿开发者，Copilot coding agent 2025 年 5–9 月产出 100 万+ PR。Octoverse 2026 截至 2026-10-07 尚未发布，最新仍是 2025 年 10 月那份。

### 2.4 并购与融资（2025-10 至 2026-09）

| 交易 | 日期 | 金额（美元） | 要点 |
| --- | --- | --- | --- |
| [Cyera 收购 Oasis](https://www.businesswire.com/news/home/20260903933820/en/Cyera-Completes-Acquisition-of-Oasis-Security) | 2026-09-03 完成 | 约 10 亿（7 亿现金） | NHI；Oasis 累计融资 1.95 亿+ |
| [Sequoia 投 Cymphony](https://techcrunch.com/2026/09/09/sequoia-doubles-down-on-cymphony-as-ai-agents-create-new-enterprise-security-risks/) | 2026-09-09 | 3,000 万 | agent 安全 |
| [SailPoint 收购 Entro](https://www.securityweek.com/sailpoint-to-acquire-entro-in-reported-200-million-deal/) | 2026-06 | 约 2 亿 | NHI |
| [1Password 收购 Apono](https://1password.com/blog/1password-acquires-apono) | 2026-06-15 | 未披露（媒体传 2–3 亿，无一手依据） | 即时访问授权；2026-07-28 已化为 1Password Privileged Access 产品 |
| Arcade.dev A 轮 | 2026-06 | 6,000 万 | agent 授权运行时 |
| NewCore 种子 | 2026-06 | 6,600 万，估值 3 亿 | agent 身份 |
| [Cisco 收购 Astrix](https://blogs.cisco.com/news/cisco-announces-intent-to-acquire-astrix-security) | 2026-05 | 约 3–4 亿 | NHI |
| [Snowflake 收购 Natoma](https://www.sec.gov/Archives/edgar/data/0001640147/000164014726000037/snow-20260731.htm) | 2026-05 | 1.283 亿（10-Q 披露） | MCP 网关与身份；27 人、融资 700 万、成立 2 年 |
| [CrowdStrike 收购 SGNL](https://ir.crowdstrike.com/news-releases/news-release-details/crowdstrike-acquire-sgnl-transform-identity-security-ai-era) | 2026-01-08 | 7.4 亿 | 人、NHI、AI 身份的实时授权 |
| [Twilio 收购 Stytch](https://www.sec.gov/Archives/edgar/data/1447669/000144766926000021/R69.htm) | 2025-10-30 签约，2025-11-14 交割 | 1.041 亿（Twilio FY2025 10-K） | agent 身份 |
| [Keycard 出 stealth](https://www.securityweek.com/keycard-emerges-from-stealth-mode-with-38-million-in-funding/) | 2025-10-22 | 3,800 万（a16z/boldstart 种子 800 万 + Acrew A 轮 3,000 万） | 「移除密钥而非更好地存密钥」 |

**投资人论点与巨头动作**：a16z Big Ideas 2026 提出 KYA（Know Your Agent）与「secrets-as-a-service」；Sequoia 把身份视为 agent 经济的问责层；YC S2026 RFS「Software for Agents」明确包含身份系统与权限层。巨头同步入场：Okta for AI Agents GA（2026-04-30）、Auth0 Token Vault、AWS AgentCore Identity、1Password 定价页出现「Runtime credentials for AI agents」、GitGuardian `ggshield machine setup`（2026-09-07，一键为本机所有 agent 装钩子）。TechCrunch 2026-09 的标题是「AI agent 安全赛道越来越挤」。

### 2.5 付费意愿

- 开发者为生产力付 10–20 美元/月（Cursor Pro 20、Copilot Pro 10、Raycast Pro 10、Warp Build 20），为安全付费极少：Bitwarden Premium 1.65 美元/月（2026-01 翻倍后仍如此）；1Password ARR 4 亿+，75% 以上来自企业。
- Tailscale 个人版免费 6 用户并砍掉付费的 Personal Plus：个人层是漏斗，不是收入。
- 转化基准：OpenView 开发者工具 6 个月中位 5%；ChartMogul 2026（200 个产品）freemium「好」3–5%、「优」8–12%，四分之一产品低于 2.5%；Supabase 约 1,000 万注册、25 万付费（约 2.5%）；PostHog 90% 以上用户免费。
- 弱信号：Gartner 没有专门针对「企业因凭证风险限制编码 agent」的统计；Snyk、Legit、Apiiro 的 2026 调查数字未检索到。

---

## 3. 竞品全景

企业侧真正的竞争者是 1Password 的平台级签约，而不是任何运行时；在 KeyValet 要赚钱的「开发团队自助付费」细分里，近期主要对手是 Infisical Agent Vault（§3.4）。SynAuth 的想法和 KeyValet 最接近但已停滞。没有一个产品同时做到「手机生物识别逐次审批并显示用途」「代理注入」「本地优先」三件事。

### 3.1 竞品总表

| 名称 | 定位 | 目标客户 | 定价（美元） | 融资 / 并购 | 与 KeyValet 重叠 |
| --- | --- | --- | --- | --- | --- |
| [1Password](https://1password.com/press/2026/mar/1password-unified-access) | Agentic Autofill、1Password for Claude、Environments MCP、Credential Broker、Privileged Access（基于 Apono，2026-07-28） | 个人 + 企业，75% 以上收入来自企业 | 官网已不公示消费者价格；App Store 内购：个人月付 4.99、年付 47.99（约 4/月），家庭年付 71.99；[Teams Starter Pack](https://1password.com/business-pricing) 24.95/月含 10 席；Business 年付 8.99/用户/月；Unified Access 定制 | ARR 4 亿+；2026-06 收购 Apono | 高，最大威胁 |
| [SynAuth](https://thesynthesisai.substack.com/p/the-vault) | iPhone Face ID 逐次审批 + 托管后端代发请求 | 开发者 | 未公开 | 一人项目，2026-02 发布；MCP 仓库 0 star，2026-02-24 后无提交；美区 App Store 搜不到；后端未开源 | 想法非常高，项目已基本停滞 |
| [Infisical Agent Vault](https://github.com/Infisical/agent-vault) | 开源本地 HTTPS 代理，MITM 注入凭据，agent 看不到 key | 开发者到企业 | OSS 免费；Pro 年付 20、月付 23/身份/月，Advanced 40 | A 轮 1,600 万（2025-06）；2,316 star，最新 v0.40.0（2026-10） | 高（注入），无审批（PR #434 自 2026-09-27 起仍 open） |
| [GitGuardian ggshield](https://docs.gitguardian.com/releases/saas/2026/09/07/changelog) | `ggshield machine setup` 一键为本机所有 agent 装钩子，扫描与阻断 | 开发者到企业 | 25 人以下免费（Starter，10K API 调用/月）；Growth/Enterprise 定制，不公示单价 | — | 中高，最接近的在位者动作；不注入、不签发 |
| [Doppler](https://www.doppler.com/agents) | 运行时注入密钥，MCP 只读 | 开发团队 | Developer 3 人免费，加人 8/用户/月；Team 21/用户/月，附加件各 9/席 | 2026 年无新融资 | 中 |
| Bitwarden | MCP 管理密码库；Secrets Manager；2026-04 发生 CLI 包投毒事件 | 个人到企业 | Premium 1.65/月（年付 19.80）；Teams 4、Enterprise 6/用户/月；Secrets Manager Teams 6（含 20 机器账户）、Enterprise 12（含 50），加机器账户 1/个 | — | 中低 |
| HashiCorp Vault / OpenBao | 动态密钥 | 企业 | 官网现只显示 IBM 版四档，不公示价格；第三方称集群 1,152–6,870/月 [未核实] | IBM 旗下 | 低 |
| [Auth0 for AI Agents](https://auth0.com/blog/auth0-for-ai-agents-generally-available/) | Token Vault 托管 OAuth token；只做 OAuth 不存 API key [未核实] | 做 SaaS 的开发者 | 免费到 25k MAU 含 Token Vault 2 个连接；AI Agents 附加件为基础价 +50%，之后 Token Vault 不限量 | Okta 旗下 | 中，偏 B2B2C |
| [Okta XAA / Agent SSO](https://www.okta.com/newsroom/press-releases/okta-brings-first-class-identity-to-ai-agents-with-agent-sso/) | Cross-App Access 成为 MCP 官方授权扩展；Agent SSO 2026-08 GA | 企业 | 含在套餐 | — | 低到中，企业侧 |
| [Arcade.dev](https://www.arcade.dev/pricing/) | 执行时授权 + MCP 运行时 | 开发者与企业 | Growth 25/月 + 0.10/授权事件 + 0.01/调用 | A 轮 6,000 万（2026-06） | 中 |
| Composio | 500+ 工具集成 + 托管认证 | 开发者 | 免费层 + 按量 | 2,900 万 | 中低 |
| [Keycard](https://www.keycard.ai/pricing/) | agent 身份、短期 token，「secretless」 | 企业与开发者 | Team 500/月含 10 万事务，超出 1/千 | 3,800 万（2025-10） | 中 |
| [Aembit](https://aembit.io/pricing/) | 无密钥工作负载与 agent 访问 | 企业 | Teams 20/agent/月 | 约 4,500 万 | 低 |
| [AWS AgentCore Identity](https://aws.amazon.com/bedrock/agentcore/pricing/) | token vault（KMS 加密），agent 凭工作负载身份取 token | AWS 内的 agent | 0.010/千次；经 Runtime/Gateway 免费 | — | 低，仅 AWS |
| Microsoft Entra Agent ID | agent 身份，2026-04 GA | 企业 | 随 Agent 365 15/用户/月 [未核实] | — | 低 |
| [Docker MCP Gateway](https://www.docker.com/blog/docker-mcp-gateway-secure-infrastructure-for-agentic-ai/) | Docker Desktop 存 secret，可拦截流量里的疑似密钥 | 开发者 | 免费 | — | 中 |
| Descope / WorkOS / Clerk / Stytch | agent 身份与 MCP OAuth，面向做 SaaS 的开发者 | SaaS 开发者 | Descope Pro 249；AuthKit 免费到 100 万用户 | Descope 8,800 万；Stytch 被 Twilio 收购 | 低 |
| Astrix / Oasis / Natoma / Entro / SGNL | NHI 安全 | 企业 | — | 均已被收购（见 §2.4） | 低 |
| 小项目：claude-vault、BotVault、Vultrino、Aegis、Pushary、YC 的 Alter | 本地 Keychain、MCP 凭据代理、手机审批推送、agent 身份与审批流 | 个人开发者 | 多数免费 | 无 | 中高，说明方向已开始同质化 |

### 3.2 1Password 对 agent 的支持：做到哪一步

1Password 的 agent 能力几乎全部围绕「人登录网页」，开发者用 agent 调 API、跑 CLI 这一块基本没有覆盖。以下按 1Password 官方文档和公告核实，截至 2026-10。

| 功能 | 状态 | 实际能力 |
| --- | --- | --- |
| [1Password for Claude](https://1password.com/press/2026/july/1password-for-claude) | 2026-07-16 beta | 只覆盖网页登录：Claude 在 Chrome 里需要登录时弹窗显示「用哪个凭据、用来做什么」，生物识别批准后直接填表，模型看不到密码；提交失败时清空已填值。需要 Mac + Claude Desktop + Chrome。新闻稿措辞为「now available」；截至 2026-10 的 1Password 博客和开发者文档均未提 Claude Code 或 Cowork 版本（开发者文档里的 Claude Code 只涉及 Environments MCP 和 shell 插件） |
| [Agentic Autofill](https://www.1password.dev/agentic-autofill)（Browserbase） | 2025-10 Early Access | 浏览器 agent 与桌面 App 间 Noise 协议 E2E 通道，每次填充人工批准；只支持浏览器登录；审计日志标为「未来」功能 |
| [Environments MCP](https://1password.com/blog/the-1password-environments-mcp-server-is-now-on-cursor-marketplace)（Codex 2026-05，Cursor 2026-07） | 已发布 | MCP 只返回变量名，程序通过本地 .env 读到的仍是明文；仅 macOS/Linux，需 Developer Tools |
| [op CLI](https://www.1password.dev/cli/app-integration-security/) | 已发布 | 生物识别解锁后授权范围是整个账号，绑终端会话，空闲 10 分钟过期，最长 12 小时；agent 在该终端可读任意条目明文 |
| [SSH agent](https://www.1password.dev/ssh/agent/security/) | 已发布 | 最接近 KeyValet：按密钥×应用（默认）、按终端、每次请求批准；显示哪个进程，无用途字段 |
| [Service Accounts / Connect](https://www.1password.dev/service-accounts/) | 已发布 | 按 vault 授权，长期静态 token |
| [Credential Broker](https://1password.com/blog/1password-credential-broker-public-preview) / Unified Access | 企业版公开预览 | 用 GitHub Actions 或 OIDC 工作负载身份换静态 vault 条目；「短期凭据」在路线图上 |
| [Privileged Access](https://1password.com/product/privileged-access)（基于 Apono） | 2026-07-28 推出，企业版，需联系销售 | JIT 访问云、K8s、数据库、SaaS；可从 Slack、CLI、MCP、ITSM 发起申请；低风险自动批准；「AI Agent Control」（任务级身份、零常设权限）；「Intent-Based Access Control」；未见必填理由字段 |
| 短期令牌签发 | 无 | 不签发 OAuth、JWT、AWS STS、GitHub App 令牌，只分发静态密钥和 TOTP |
| API 调用的代理注入 | 无 | 除浏览器表单外没有 |
| 运行时防泄漏 | 无 | Discover 扫描明文（企业），无 hook 拦截 |

**逐项对比**

| 能力 | 1Password | KeyValet |
| --- | --- | --- |
| 每次使用的批准粒度 | 浏览器每次填充；SSH 可逐次；op CLI 一次解锁整账号 12 小时 | 逐次 Touch ID / Face ID，或按凭据、会话、N 小时 |
| 显示并记录用途 | 仅 Claude 浏览器弹窗显示；Activity Log 字段只有日期、操作者、动作、对象、附加信息、IP，没有用途字段 | 显示并写入审计 |
| agent 能否看到明文 | 浏览器和 Environments MCP 看不到；op CLI 和 .env 注入的进程能读到 | proxy_only 读不到；export_file 只返回路径 |
| API 调用代理注入 | 无 | 有 |
| 令牌签发 | 静态密钥和 TOTP | OAuth2、JWT、GitHub App、AWS STS、Google SA、TOTP |
| 防 CLI/shell 泄漏 | 无运行时拦截 | hooks 拦截 |
| 远程或云端 agent + 手机审批 | 仅 Browserbase 早期试用 | 计划：relay + iPhone |
| 本地 MCP | Environments MCP 只返回变量名 | 完整凭据工具集 |
| 审计 | 条目使用报告，无用途字段 | 逐次，带用途 |
| 平台 | 需 Mac 桌面 App | macOS 现有，Linux 计划 |
| 生态 | Anthropic、OpenAI、Cursor、GitHub、Vercel 官方合作方 | 无 |

1Password 明显领先的地方：生态和分发；浏览器登录场景已完整；企业治理（Credential Broker 的 OIDC 身份、Apono 的即时访问、设备信任）；SSH agent 成熟且支持 Windows/Linux。它的路线图上已有「短期凭据」，Privileged Access 已把 Apono 的 JIT 和「AI Agent Control」做进企业版，所以窗口期约 12–18 个月，企业侧可能更短。

### 3.3 SynAuth 与 Infisical Agent Vault

**SynAuth**：作者是 The Synthesis（GitHub `dennischoubot-glitch`），2026-02-27 发布介绍文章，`synauth-mcp` MIT 许可、0 star、5 个提交。默认用作者托管的 `synauth.fly.dev` 后端，凭据在服务器上用 Fernet 对称加密，密钥是服务端 secret，不是端到端加密。iPhone 审批显示动作意图、目标服务和请求参数，对规范化参数算 SHA-256 并在执行时复核，每次审批只能执行一次。支持 bearer、API key、basic auth、自定义 header，每个凭据有 host 白名单；有防 SSRF（只 HTTPS、禁私有 IP）；规则可按风险、金额（如低于 25 美元自动放行）、agent ID 自动判定。不签发任何 token，无防泄露 hook，只有 iOS。作者自述「v1，单实例，281 个测试，还没有规模和使用记录」；价格、融资、用户量均未公开。2026-10-07 复核：仓库 0 star、2026-02-24 后无提交，作者账号下没有后端仓库，美区 App Store 搜不到名为 SynAuth 的应用。来源：[The Vault](https://thesynthesisai.substack.com/p/the-vault)、[GitHub](https://github.com/dennischoubot-glitch/synauth-mcp)。

**Infisical Agent Vault**：2026-04-22 以 research preview 发布，Go 写的，MIT 许可加 `ee` 商业目录，约 2.3k star。agent 设置 `HTTPS_PROXY`，代理用本地信任的 CA 终止 TLS，注入凭据后转发；支持占位符替换（如 `__anthropic_api_key__`）；策略分 vault、credential、service（按目标 host）、agent 四层；默认 SQLite，生产可用 PostgreSQL，也可接 Infisical。开源版没有人工审批（社区 PR #434「per-request human approval」2026-09-27 提交，至今 open），本身不签发上游 token（商业平台的 dynamic secrets 可以），本身不是 MCP server，而是让 MCP、CLI、SDK 的出站请求经过它（README 原话），IMAP、SSH 等非 HTTP 协议覆盖不到，需信任中间人 CA。最新版本 v0.40.0，2,316 star（2026-10-07）。商业版内置在 Infisical 平台，价格不公开。来源：[博客](https://infisical.com/blog/agent-vault-the-open-source-credential-proxy-and-vault-for-agents)、[GitHub](https://github.com/Infisical/agent-vault)。

| 维度 | KeyValet | SynAuth | Infisical Agent Vault |
| --- | --- | --- | --- |
| 密钥在哪 | 本机 | 作者服务器，服务器能解密 | 自建 SQLite/PG 或 Infisical |
| 人工审批 | Mac Touch ID，四种粒度，显示 agent 写的用途 | iPhone Face ID，按请求，显示真实参数并哈希绑定 | 无 |
| 规则自动放行 | 按时间或会话记住 | 按风险、金额、agent | 出站过滤 |
| 接入方式 | MCP 工具 | MCP 或 REST | 透明代理，零改动 |
| token 签发 | OAuth、JWT、GitHub App、AWS STS、Google SA、TOTP | 无 | 无 |
| 防泄露 hook | 有 | 无 | 无 |
| 云端 agent | 计划中 | 有，服务端代发 | 有，sidecar |
| 平台 | macOS | iOS + 任意 MCP 客户端 | macOS、Linux、Docker |
| 成熟度 | v0.1 | v1，0 star，已停滞 | preview，v0.40.0，2,316 star |

**值得借鉴的设计**（按优先级）：

1. 审批弹窗显示真实请求（method、host、path、body 摘要），并对规范化参数算哈希、一次性执行。这是对 SECURITY.md 里「用途未经校验」的直接补强。
2. 规则引擎：只读 GET 自动放行，写操作才要求 Touch ID，可加金额或风险阈值。
3. 本地 HTTPS_PROXY 模式加占位符替换，让没接入 MCP 的程序也受保护，也是给云端 agent 做 sidecar 的基础。
4. 防 SSRF 和 host 白名单：只走 HTTPS、拒绝私有 IP、只允许绑定的域名。
5. iPhone 远程审批做成端到端加密，正好是 SynAuth 的弱点。
6. 审计里记下游响应状态和审批人设备。
7. 存储插件支持 Infisical 作后端，顺带用上它的 dynamic secrets。

### 3.4 近期主要对手：Infisical Agent Vault 的应对

为什么是它而不是 1Password：Team 自助付费的买家是开发团队负责人，他们已经在看 Infisical（开源、2,316 star、A 轮 1,600 万、Pro 20 美元/身份/月）；它的人工审批 PR #434 已经提交，一旦合并再补一个 MCP server，就覆盖了 KeyValet 面向团队价值的一大半。1Password 的 Privileged Access 卖给 CISO，短期内不会和一个 15 美元/席位的自助产品正面碰。

| Infisical 没有的 | KeyValet 的动作 |
| --- | --- |
| 生物识别逐次审批、审批绑定真实请求 | 阶段 0–1 做深，作为所有宣传的第一句 |
| 短期 token 签发（OAuth 刷新、JWT、GitHub App、STS、TOTP） | 保持并扩模板 |
| hooks 级防泄漏 | 覆盖 Claude Code、Codex、Cursor |
| 手机作为信任根（Linux/CI 也能生物识别审批） | 阶段 3 |
| 非 HTTP 协议（IMAP XOAUTH2、SSH 私钥、文件型 secret） | 现有 `export_file` 继续领先 |

两手策略：一是把 Infisical 做成存储后端（阶段 2），用户不用迁移就能在 Infisical 之上获得审批和签发；二是在它的社区以集成方身份出现，而不是竖对手。监控信号：PR #434 合并、Infisical 发布 MCP server、Pro 档加入审批功能，任何一条触发就把阶段 3 的手机审批提前。

---

## 4. 平台与分发

八个主流运行时全部支持 MCP，也全部具备「执行前可拦截」的 hook，但没有一个在本机提供按次生物识别授权加协议级注入的 vault。2026 年行业已收敛到 Claude Code 式的 `PreToolUse` 契约：Codex、Copilot 直接沿用同名事件和 JSON 结构，Copilot 甚至会读取 `.claude/settings.json` 里的 hooks。KeyValet 现有的 `claude-plugin/hooks/secrets.mjs` 只需少量适配就能覆盖 Codex 和 Copilot。

### 4.1 运行时对比

| 运行时 | MCP | 可拦截的 hooks（执行前） | secret 处理 | 插件市场 | 规模数据 |
| --- | --- | --- | --- | --- | --- |
| [Claude Code](https://code.claude.com/docs/en/hooks) | stdio / 流式 HTTP，远程 OAuth | `PreToolUse` 可 allow/deny/ask 并 `updatedInput` 改写；`PermissionRequest`、Elicitation hooks | 无 vault；`/sandbox` 文件和网络隔离；MDM 托管设置；MCP 配置 `${VAR}`；#70716 被拒；云端 Managed Agents vault | 任意 git 仓库可作 marketplace；官方 `anthropics/claude-plugins-official`；无公开安装量 | 年化 25 亿美元（2026-02）[未核实，Anthropic 新闻室无原始帖]；Anthropic 整体年化 650 亿+（2026-07）[未核实] |
| [Cursor](https://cursor.com/docs/agent/hooks) | IDE stdio/HTTP；Cloud Agents 由后端代理，VM 看不到凭证 | GA；`preToolUse`、`beforeShellExecution`、`beforeMCPExecution`、`beforeReadFile` 可 deny（exit 2） | Cloud Agents Secrets（团队级）；MCP 配置加密；本地无 vault；1Password 合作 | Cursor Marketplace（2026-02-17，人工审核）；cursor.directory | ARR 30 亿（Bloomberg 2026-05-21），「40 亿+」未核到；SpaceX 600 亿收购 2026-06-16 达成协议、2026-08-14 完成 |
| [OpenAI Codex](https://developers.openai.com/codex/hooks) | stdio + 流式 HTTP，OAuth | `PreToolUse` allow/deny/ask + `updatedInput`；不覆盖所有 shell 路径 | 1Password Environments MCP（2026-05，仅 macOS）；本地无 vault | Codex plugins（2026-03），与 ChatGPT 共用目录 | 周活 200 万+（Reuters 2026-03-19）；「500 万周活」（2026-06）和「2,000 万活跃」（2026-08）未找到一手出处 [未核实] |
| [GitHub Copilot](https://docs.github.com/en/copilot/reference/hooks-reference) | CLI 本地 + 远程；coding agent 仓库配置 | `preToolUse` allow/deny/ask + `modifiedArgs`；兼容读取 `.claude/settings.json`；超时 fail-open | Actions `copilot` 环境 secrets；CLI 用环境变量；无 vault | GitHub MCP Registry；VS Code Marketplace | 付费 470 万（2026-01）；5,000 万用户（2026-07）；CLI GA 2026-02-25 |
| [Gemini CLI → Antigravity CLI](https://developers.googleblog.com/an-important-update-transitioning-gemini-cli-to-antigravity-cli/) | stdio/SSE/HTTP | `BeforeTool` 可 block/rewrite | 环境变量替换；无 vault | Extensions Gallery（70+） | 3 个月 100 万开发者（2025-10）；2026-06-18 起对个人用户停服 |
| [OpenCode](https://opencode.ai/docs/plugins/) | 本地 + 远程，OAuth | JS/TS 插件 `tool.execute.before`，可改写 args | `{env:}`/`{file:}` 替换；无 vault | npm 分发 | 212,118 star（GitHub API，2026-10-07） |
| [Goose](https://goose-docs.ai/docs/guides/context-engineering/hooks/) | MCP 原生 | `PreToolUse` 可 block，不能改写；Code Mode 嵌套调用可能绕过 | keyring 存 provider key [未核实] | extensions 目录 | 55,028 star（GitHub API，2026-10-07） |
| [Cline](https://cline.bot/blog/cline-v3-36-hooks) | stdio/SSE/HTTP，内置 Marketplace | 脚本 `PreToolUse` `{"cancel":true}`，无 ask、不能改写；不支持 Windows | VS Code secret storage | 内置 MCP Marketplace | 69,971 star；VS Code Marketplace 5,550,862 次安装（2026-10-07） |

### 4.2 Anthropic 的态度

- [Managed Agents vault](https://claude.com/blog/claude-managed-agents)：2026-04 发布，按消费计费（0.08 美元/会话小时 + token），vault 不单独收费；2026-06-09 beta 增加「API key + 环境变量名 + 允许域名」，沙箱内只有占位符，真密钥在网络边界附加。与 KeyValet 的代理注入同构，但只在 Anthropic 云沙箱内。
- [issue #70716](https://github.com/anthropics/claude-code/issues/70716)：「Account-level Secrets/Credentials Vault」被以 not planned 关闭，标签 `area:security`。
- 1Password 合作：2026-03 宣布浏览器扩展、Cowork、Claude Code 三处集成；2026-07-16 beta 仅覆盖 Claude Desktop/Cowork 和浏览器，Claude Code 路径未给出。
- [Remote Control](https://code.claude.com/docs/en/remote-control)：手机 Claude App 可连接本机 CLI 会话并审批权限提示，但推送无 Approve/Deny 按钮（#62458 not planned）。它批的是工具权限，不持有凭据。
- 「Claude Code 弹窗 93% 被批准」这一说法在 Anthropic 官方页面未找到原文 [来源待补]。

### 4.3 KeyValet 对各运行时的支持程度

- 完整支持（hooks 拦截 + MCP + 可改写参数）：Claude Code、Codex、Copilot、Cursor、Antigravity CLI、OpenCode。前三者一份脚本三处复用；Cursor 需单独 `hooks.json`；Gemini 改事件名；OpenCode 写 JS 插件。
- 部分支持（只能 deny）：Goose、Cline。能阻止明文进 shell，做不到替换为占位符。
- 降级保护需在文档标注：Codex PreToolUse 不覆盖全部 shell 路径，Copilot 超时 fail-open，Goose 嵌套调用可绕过。真正的保证来自「agent 从未持有密钥」。
- 远程或云端会话（Claude Code on web、Cursor Cloud Agents、Copilot coding agent）没有本机 Touch ID，是真正的边界，靠 relay + 手机解决。

### 4.4 分发渠道（按触达/投入比）

1. Claude Code plugin marketplace（自建仓库 + 提交官方目录）：已具备，投入最低，用户付费意愿最强。
2. Copilot CLI + coding agent（第二批运行时）：`.github/hooks` 和 `~/.copilot/hooks`，格式近似 Claude Code；5,000 万用户基数。
3. Codex plugins：hooks 同构，但需正面对比 1Password 官方集成，强调「协议级 token 签发 + 免费开源」。
4. Cursor Marketplace：人工审核排队，先走 cursor.directory。
5. MCP 目录全部挂牌：官方 Registry 约 9.6k 条、[PulseMCP](https://www.pulsemcp.com/servers) 约 21.7k、Glama 37k–48k、Smithery 7k–11k。
6. Antigravity CLI plugins：平台切换期，待稳定。
7. OpenCode（npm）、Cline MCP Marketplace、Goose extensions：长尾。

### 4.5 平台风险（18 个月内自建本地 vault 的可能性，主观估计）

| 平台 | 概率 | 更可能做的 | 不太可能做的 |
| --- | --- | --- | --- |
| Cursor | 中，约 40% | Cloud Secrets 下沉到 IDE/CLI；团队策略 | 跨其他运行时 |
| Anthropic | 低到中，约 30% | 把 Managed Agents 的网络边界注入扩展到 Claude Code on web；深化 1Password | 本机 Touch ID 按次授权、协议级签发、跨运行时 |
| OpenAI | 低，约 25% | 1Password 作为受信访问层；企业 secret manager 对接 | 本地生物识别代理 |
| GitHub | 低，约 20% | Actions 环境 + 企业策略 | 本机 CLI vault |
| Google | 低，约 20% | Secret Manager 云侧对接 | 本地 |
| OpenCode / Goose / Cline | 很低，10–15% | keyring 存 provider key | 按次授权与审计 |

结构性判断：运行时厂商一致把 secret 管理做成云侧、团队级、锁定自家沙箱的能力。KeyValet 的防御位是本机、开源、协议感知、跨八个运行时共享一个 vault、hooks 级泄漏阻断、带用途的审计。最大风险来自 1Password 的平台级签约，而非运行时自建。

---

## 5. 标准与协议

MCP 授权规范已在 OAuth 2.1 上稳定，Okta 的 Cross-App Access 已被 Claude、Cursor、VS Code 采用；但 IETF 还没有采纳任何 agent 专属的授权草案，「批不批这一次调用」在各运行时之间没有统一标准。OS 级生物识别审批是目前唯一真正跨运行时的人工确认层，这正是 KeyValet 的壁垒所在。

| 标准 | 状态（2026-10） | 推动者 | 已采用方 | 对 KeyValet |
| --- | --- | --- | --- | --- |
| [MCP Authorization 2026-07-28](https://modelcontextprotocol.io/specification/latest/basic/authorization) | 正式版：AS 必须 OAuth 2.1；RFC 9728 受保护资源元数据必须；RFC 8707 `resource` 必须；RFC 9207 `iss` 校验；增量授权走 `insufficient_scope` | MCP 项目 | 全部 MCP 客户端和 SDK | 采用（远程 MCP 端点作 AS）。规范原文说 stdio 服务器「SHOULD NOT follow this specification, retrieve credentials from the environment」，KeyValet 就是这个 environment |
| Client ID Metadata Documents | IETF 草案 -00；MCP 标 SHOULD；DCR（RFC 7591）本版正式 Deprecated | Parecki / Okta | MCP、Okta、Auth0 | 采用，在 keyvalet 域名托管 CIMD；DCR 仅兜底 |
| [Enterprise-Managed Authorization / XAA / ID-JAG](https://github.com/modelcontextprotocol/ext-auth) | ext-auth 仓库 Stable；IETF OAuth WG Standards Track（RFC 7523 + RFC 8693 组合） | Okta、WorkOS、Auth0 | [Okta 2026-06 公布 25+ 集成](https://www.okta.com/newsroom/press-releases/okta-announces-cross-app-access-partners/)，含 Claude、Cursor、Docker、VS Code、Zoom；SDK TS/Java 已内建；新闻稿全文无 OpenAI/ChatGPT，25+ 早期采用者含 Anthropic、Cloudflare、Keycard、Stytch by Twilio、Supabase、WorkOS、Zuplo | 兼容，由 SDK 带，作为企业身份来源 |
| MRTR / elicitation | 2026-07-28 正式：工具返回 `input_required` + `inputRequests`，客户端带 `inputResponses` 重试；同版删除 `Mcp-Session-Id`，弃用 Sampling/Roots/Logging，`_meta` 规范 OTel `traceparent` | MCP 项目 | Claude Code 已有 Elicitation hook | 兼容，Touch ID 不可用时回退；per-session 模式继续绑 stdio 进程 |
| Tool annotations | 正式但是 untrusted hint；规范要求「human in the loop」和「log tool usage for audit」；警告勿把密钥标为 `x-mcp-header` | MCP 项目 | 各客户端 | 采用，零成本：list/status/audit_log/templates 标 readOnly，delete 标 destructive，http_request/gateway 标 openWorld |
| [Transaction Tokens](https://datatracker.ietf.org/doc/draft-ietf-oauth-transaction-tokens/) | WG -11（2026-07-30，Standards Track）；for-agents 个人草案 -02（`act`=agent，`sub`=用户） | SGNL、Amazon | 企业内网 | 兼容，代发 token 的 claims 形状 |
| RFC 8693 token exchange / RFC 9396 RAR | RFC | IETF | IdP 普遍 | 采用语义，不自造 token 格式 |
| OAuth WG 的 agent 草案 | 未采纳；主席 2026-08-27 称「premature」。活跃个人草案：aauth-protocol、agent-delegation、agent-grants、[user-mediated-delivery-00](https://www.ietf.org/archive/id/draft-emerson-oauth-user-mediated-delivery-00.txt)（2026-07-01，Informational，作者 C. Emerson / AgentAdmit，**声明专利申请中**）。后者的模型：资源方 SaaS 提供连接管理界面，用户选范围和期限后得到一次性连接凭据，粘贴给 agent 换取限定范围的 token，每次调用强制 introspection，step-up 走新的用户中介流程而非 CIBA 推送 | 个人 | 无 | 只作参考，不采用其术语：它在资源方实现，KeyValet 在代理端对任何 API 生效；因专利声明需做 FTO 排查 |
| WIMSE AIMS / SPIFFE | WG -00（2026-09-15 采纳），「agents are workloads」 | Microsoft、Okta、Ping | 企业工作负载 | 忽略，跟踪 |
| [Web Bot Auth](https://datatracker.ietf.org/doc/draft-ietf-webbotauth-httpsig-protocol/)（RFC 9421 画像） | WG -00（2026-09-01）；Cloudflare signed agents 2025-08 生产可用 | Cloudflare、Google | Cloudflare、Akamai、AWS 验签 [部分未核实] | 兼容，proxy 出站签名，后置 |
| [Microsoft Entra Agent ID](https://learn.microsoft.com/en-us/entra/agent-id/whats-new-agent-id) / [AWS AgentCore Identity](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/key-features-and-benefits.html) | GA（Entra 2026-04）；AgentCore 是 KMS 加密的 token vault，0.010 美元/千次，经 Runtime/Gateway 使用免费（官方价格页） | Microsoft / AWS | 各自云 | 忽略模型，只当上游凭据源 |
| OTel GenAI 语义约定 | 全部 Development；2026-06 移至独立仓库，至今无 release | OTel SIG | Datadog、Grafana；Claude Code 的 beta traces 的 span 带 `gen_ai.system`、`gen_ai.request.model`、`gen_ai.tool.call.id` 等（metrics 和日志用 `claude_code.*`） | 兼容，审计字段映射层 |
| OWASP Top 10 for Agentic Applications 2026 | 2025-12-09 发布：ASI02 Tool Misuse、ASI03 Identity & Privilege Abuse、ASI09 Human-Agent Trust Exploitation | OWASP | 厂商映射文档 | 采用，文档映射 |
| [NIST CAISI / NCCoE / COSAiS](https://csrc.nist.gov/projects/cosais) | AI Agent Standards Initiative（2026-02-17）；NCCoE 概念稿「Software and AI Agent Identity and Authorization」（2026-02-05）；SP 800-53 overlays 尚无草案 | NIST | — | 采用，合规映射 |
| Claude Code hooks / OpenAI approvals / Managed Agents policy | 各家私有：Claude Code `permissionDecision` allow/deny/ask/defer；OpenAI `mcp_approval_request`；Managed Agents `always_allow / always_ask / auto` | Anthropic / OpenAI | 各自运行时 | 兼容，逐运行时适配器 |
| secret reference 约定 | 无跨厂商标准，仅厂商 URI（`op://`） | — | — | 自定 `keyvalet://` 并支持 `op://` 引用 |

**原生实现**

1. `credential_oauth_login` 和远程 MCP 登录走 OAuth 2.1 + PKCE、RFC 9728 发现、RFC 8707、RFC 9207；在 keyvalet.dev 托管 CIMD 文档。
2. 所有工具加 annotations。
3. 审计日志字段映射 OTel GenAI（gen_ai.tool.name、gen_ai.agent.name）并保存 `_meta.traceparent`；保留自有 schema 加映射层。
4. 代发短期 token 用 JWT：`sub`=用户、`act`=agent、`purpose` 自定义 claim，与 Transaction Tokens for Agents 对齐。
5. 文档映射 OWASP ASI02/03/09 与 NCCoE 四要素。
6. SDK 升级到 2026-07-28 规范，per-session 模式继续绑 stdio 进程，不依赖已删除的 `Mcp-Session-Id`。

**可以自创的**：purpose 语义、四档授权模式、生物识别门控、代理注入格式、`credential_export_file`、模板库、`keyvalet://` 引用。这些没有任何标准覆盖。

---

## 6. 技术可行性核实

架构的两个假设被 Apple 文档推翻：iPhone 不能在后台执行 30–60 秒的 API 调用，锁屏快速批准也不是 Face ID 绑定的。其余假设（Nitro c7g.large、KMS 绑定证明、Linux TPM、透明代理）全部成立。以下均对照一手文档。

### 6.1 iOS

| 问题 | 结论 | 依据 |
| --- | --- | --- |
| `authenticationRequired` 是否强制解锁 | 是。系统弹解锁，解锁后才通知 app | [Apple](https://developer.apple.com/documentation/usernotifications/unnotificationactionoptions/authenticationrequired) |
| 通知动作的后台 handler 能否联网 | 是。系统在后台启动 app 调用 `didReceive`；Apple 对后台推送唤醒给出的上限是「up to 30 seconds of wall-clock time」，`applicationDidEnterBackground` 只有 5 秒 | [Apple](https://developer.apple.com/documentation/usernotifications/handling-notifications-and-notification-related-actions) · [Apple](https://developer.apple.com/documentation/usernotifications/pushing-background-updates-to-your-app) |
| 后台能否用 `.biometryCurrentSet` 的 SE 密钥签名 | 否。生物识别弹窗需前台，后台返回 LAErrorNotInteractive（Apple DTS 回复）。锁屏快速批准只是「设备解锁门禁」，强审批必须打开 app | [Apple 论坛](https://developer.apple.com/forums/thread/765094) |
| 业界模式 | Duo 锁屏长按 Approve 再输密码或生物识别；Okta Verify 开启数字挑战时必须进 app | [Duo](https://guide.duo.com/iphone) · [Okta](https://help.okta.com/oie/en-us/content/topics/identity-engine/authenticators/ov-user-verification-exp.htm) |
| Notification Service Extension | 时限 ≤ 30 秒；官方用例含「decrypt an encrypted data block」，所以能联网和 E2E 解密；需 `mutable-content:1`；内存上限 Apple 未文档化，开发者论坛的崩溃日志显示 24 MB（ActiveHard），仅论坛来源；解密密钥不能用生物识别保护 | [Apple](https://developer.apple.com/documentation/usernotifications/unnotificationserviceextension/didreceive(_:withcontenthandler:)) |
| 手机执行 30–60 秒流式调用 | 否。`beginBackgroundTask` 只有「finite amount of time」（后台唤醒的上限同样是 30 秒）；`BGProcessingTask` 只在设备空闲时跑。前台时手机可直连短请求；否则手机只签批准或释放密钥，由 helper 或 enclave 执行 | [Apple](https://developer.apple.com/documentation/backgroundtasks/bgprocessingtask) |
| Secure Enclave 算法 | Security 框架仅 P-256（签名 + ECDH），不能导入密钥；CryptoKit 26.0 起（iOS/iPadOS/macOS/tvOS/watchOS/visionOS）新增 `SecureEnclave.MLDSA65/87`、`MLKEM768/1024`，Apple 文档和 WWDC25 Session 314 只要求设备具备 Secure Enclave，未列芯片限制；`SecureEnclave.P256.KeyAgreement` 可用 | [Apple](https://developer.apple.com/documentation/cryptokit/secureenclave) |
| `.biometryCurrentSet` | Face ID 重录或指纹增删即作废 | [Apple](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/biometrycurrentset) |
| iCloud 钥匙串 | 端到端加密，Apple 不能读；但 SE 密钥绑定设备，`kSecAttrSynchronizable` 条目不能带 SecAccessControl，SE 密钥不可同步 | [Apple](https://support.apple.com/guide/security/icloud-keychain-security-overview-sec1c89c6f3b/web) · [Apple](https://developer.apple.com/documentation/security/ksecattrsynchronizable) |
| App Attest | 可用，私钥在 SE，Apple 证明密钥属于合法 app 实例；大多数扩展不支持 | [Apple](https://developer.apple.com/documentation/devicecheck/establishing-your-app-s-integrity) |
| Swift 验证 Nitro 证明 | 无现成库，可拼：CBOR/COSE_Sign1 用 [SwiftCOSE](https://github.com/Kingpin-Apps/swift-cose)，证书链到 AWS Root-G1 用 [swift-certificates](https://github.com/apple/swift-certificates)，ES384 用 CryptoKit `P384.Signing`；可移植参考 hf/nitrite（Go）、EternisAI/remote-attestation-verifier（Rust） | [AWS](https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html) |

### 6.2 AWS Nitro Enclaves

| 问题 | 结论 | 依据 |
| --- | --- | --- |
| 机型 | c7g.large 支持（C7g 仅排除 medium 和 metal）。规则：x86 排除 *.large，最少 4 vCPU；Graviton 排除 *.medium，最少 2 vCPU；T/T4g 系列不支持。原因：SMT 父机需分配偶数 vCPU 并保留 ≥ 2 | [AWS](https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave.html) |
| 出站 HTTPS | 是。vsock-proxy 纯 L4 转发，TLS 在 enclave 内协商，宿主只见密文；白名单在 `/etc/nitro_enclaves/vsock-proxy.yaml` | [AWS](https://github.com/aws/aws-nitro-enclaves-cli/blob/main/vsock_proxy/README.md) |
| KMS 绑定证明 | 是。条件键 `kms:RecipientAttestation:ImageSha384`（= PCR0）和 `kms:RecipientAttestation:PCR<n>`，适用 Decrypt/GenerateDataKey 等；`Recipient{AttestationDocument}` 参数返回 `CiphertextForRecipient`，`Plaintext` 为空 | [AWS](https://docs.aws.amazon.com/kms/latest/developerguide/conditions-nitro-enclave.html) |
| 可复现 EIF | 有条件。nitro-cli 不承诺确定性，EIF 带时间戳，但同一 Docker 镜像的 PCR 一致；AWS 官方路线 kaniko `--reproducible` + 固定基础镜像；Nix 路线 [monzo/aws-nitro-util](https://github.com/monzo/aws-nitro-util)；debug 模式 PCR 全零，签名 EIF 增加 PCR8 | [AWS 博客](https://aws.amazon.com/blogs/web3/verify-enclave-counterparties-with-reproducible-builds-and-cryptographic-attestation-using-aws-nitro-enclaves) |
| c7g.large 价格（us-east-1 Linux，2026-10-06 价目表） | 按需 0.0725 美元/小时（约 53/月）；1 年 Compute Savings Plan 无预付 0.052（约 38/月）；1 年 EC2 Instance SP 0.0478（约 35/月）；3 年 Compute SP 0.0351（约 26/月）；Spot 约 0.023–0.028（17–20/月） | [AWS 价目表](https://pricing.us-east-1.amazonaws.com/savingsPlan/v1.0/aws/AWSComputeSavingsPlan/current/region_index.json) |
| 替代 | Lambda、Fargate 不支持 enclave；AWS 内只有 EC2 Nitro Enclaves 这一条路 | — |

### 6.3 非 Secure Enclave 主机

- Linux：TPM 2.0 可用。tpm2-tss（TCG 参考实现）或 `systemd-creds encrypt --with-key=tpm2 --tpm2-pcrs=`。TPM 无生物识别，审批仍在手机。[systemd](https://www.freedesktop.org/software/systemd/man/latest/systemd-creds.html)
- Windows：CNG Platform Crypto Provider 在 TPM 内建不可导出密钥；Windows Hello `KeyCredentialManager.RequestSignAsync` + 密钥证明，需交互桌面会话。[Microsoft](https://learn.microsoft.com/en-us/windows/security/hardware-security/tpm/how-windows-uses-the-tpm)
- 云身份：AWS IMDS `iam/security-credentials/`；GCP `service-accounts/default/identity?audience=`；GitHub Actions OIDC（注意 2026-07-15 后新仓库 `sub` 格式变化）。[GitHub](https://docs.github.com/en/actions/security-for-github-actions/security-hardening-your-deployments/about-security-hardening-with-openid-connect)
- Android：StrongBox（API 28+，P-256 ECDSA/ECDH），`setUserAuthenticationParameters(0, AUTH_BIOMETRIC_STRONG)` 配合 `BiometricPrompt.CryptoObject` 每次操作验证，支持 Key Attestation，默认录入新生物特征即作废。可行。[Android](https://developer.android.com/privacy-and-security/keystore)

### 6.4 本地 CA 透明代理的坑

- 参照物 Infisical Agent Vault：`HTTPS_PROXY` 指向本地 TLS 终止代理，同时注入 `SSL_CERT_FILE`、`NODE_EXTRA_CA_CERTS`、`REQUESTS_CA_BUNDLE`、`CURL_CA_BUNDLE`。
- Node：全局 fetch（undici）默认忽略 `HTTPS_PROXY`，需 `NODE_USE_ENV_PROXY=1`（Node ≥ 22.21 / 24.5）或 `--use-env-proxy`；旧版用 undici `EnvHttpProxyAgent`。[Node](https://nodejs.org/learn/http/enterprise-network-configuration)
- Python：requests 读 `REQUESTS_CA_BUNDLE`；httpx 默认 trust_env；Anthropic Python SDK 显式挂载环境代理；OpenAI Python 3.26 依赖 httpx2 ≥ 2.12，httpx2 默认 trust_env=True 读取 HTTP(S)_PROXY，SDK 源码未覆盖该设置，默认走代理（源码推断，未实测）；boto3 读 `HTTP(S)_PROXY` + `AWS_CA_BUNDLE`。
- Go：`SSL_CERT_FILE`/`SSL_CERT_DIR`；Go 1.27 起设置后会关闭 macOS/Windows 系统验证器。[Go](https://pkg.go.dev/crypto/x509)
- SDK：OpenAI Node 用 `fetchOptions` + undici `ProxyAgent`；Anthropic TS `fetchOptions` 可传 `dispatcher`；Octokit 默认不读代理变量，需 `request.fetch` 注入。
- 其他：gRPC 走 `grpc_proxy/https_proxy`，根证书用 `GRPC_DEFAULT_SSL_ROOTS_FILE_PATH`；HTTP/2 需代理支持 h2；Java 需导入 cacerts。忽略代理变量的工具不会被代理，必须配合网络层出站封锁，Claude Code 的 `/sandbox` 网络隔离是天然搭配。

### 6.5 TEE 成本对比（2026-10 查询）

每月按 730 小时，美元，Linux，美国东部或 us-central1 区域，不含磁盘和出网流量（各家约另加 1–3 美元/月）。除 Oasis/Marlin 外，价格均为 2026-10-07 官方价格页或官方价格 API 的原值。

| 方案 | 最小配置 | 常驻月费（美元） | 证明类型 | iOS 端验证难度 | 备注 |
| --- | --- | --- | --- | --- | --- |
| Azure DC2as_v5 Spot | 2 vCPU / 8 GB | 13（Spot 0.018155/小时） | AMD SEV-SNP | 中 | 按需 0.086/小时约 63；Low Priority 0.0172；Spot 可被回收 |
| AWS Nitro Enclaves c7g.large Spot | 2 vCPU / 4 GB，1 vCPU 给 enclave | 17–20 | Nitro attestation（COSE_Sign1，PCR） | 简单 | 按需 0.0725/小时约 53；1 年 SP 35–38；3 年 26 |
| GCP n2d-standard-2 Spot + SEV-SNP | 2 vCPU / 8 GB | 32（Spot 0.043028/小时 + SNP 加价 0.0013） | SEV-SNP；Confidential Space 签发 Google OIDC 令牌 | 最简单，验一个 JWT | 按需 0.084492/小时约 62；SNP 加价约 10%，SEV 加价约 20%（us-central1） |
| Azure ACI 机密容器 | 1 vCPU / 1 GB | 常驻约 36（vCPU 0.04455/小时 + 内存 0.004895/GB·小时）；按秒 0.000012375/vCPU·秒，只在请求时运行可至几美元 | SEV-SNP（MAA / SKR） | 中 | 冷启动数十秒，不适合同步调用；比标准 ACI 贵约 10% |
| Phala Cloud dstack tdx.small | 1 vCPU / 2 GB / 20 GB | 约 44（0.06/小时） | Intel TDX（DCAP） | 较难 | tdx.medium 0.12/小时；Web3 生态 |
| Tinfoil Containers | 按用量 | 约 78（20/月基础费 + 0.06/vCPU·小时 + 0.01/GB·小时，按 1 vCPU + 2 GB） | 自有体系（SEV-SNP/TDX + 透明日志） | 简单，但需信任其工具链 | 2026-03 才 GA；官网的 20/月是 Private Chat 产品 |
| Oasis ROFL / Marlin Oyster | 节点市场定价 | 未查到 [未核实] | TDX / SGX / Nitro | 较难 | 代币计价 |
| OVH Scale-a1 2026 独服 | 整机，EPYC 9135 16 核 | 708 起（未税） | AMD SEV-SNP，需自行启用；价目表带「Confidential computing」标签 | 中 | 严重过剩；High Grade 2026 不带该标签 |
| Evervault Enclaves | — | 995/月起；AWS Marketplace 3,540/年 | Nitro | 简单，有 SDK | 太贵 |
| Cloudflare Workers | — | — | 无硬件 TEE | — | 不符合需求 |

选 Nitro 的理由：生态最成熟、KMS 绑定证明开箱即用、iOS 端验证难度可控。价格来源：[Azure Retail Prices API](https://prices.azure.com/api/retail/prices)、[Azure ACI](https://azure.microsoft.com/en-us/pricing/details/container-instances/)、[GCP 通用机型](https://cloud.google.com/products/compute/pricing/general-purpose)、[GCP Spot](https://cloud.google.com/spot-vms/pricing)、[GCP 机密计算](https://cloud.google.com/confidential-computing/confidential-vm/pricing)、[Phala](https://phala.com/pricing)、[Tinfoil](https://tinfoil.sh/pricing)、[OVH](https://www.ovhcloud.com/en/bare-metal/prices/)、[Evervault](https://evervault.com/pricing)。

---

## 7. 最终架构

### 7.1 分层总图

```
┌─────────────────────────── 接入层（任意 agent，任意机器）───────────────────────────┐
│ 本地 MCP (stdio)  │  远程 MCP (HTTP, OAuth 2.1)  │  CLI · 透明 HTTPS 代理 + 占位符  │
│ SDK 网关 (OPENAI_BASE_URL 等)  │  hooks 适配器 × 8 运行时（执行前拦截）           │
└──────────────────────────────────────┬────────────────────────────────────────────┘
                                       ▼
┌──────────────── 核心引擎（Rust，Mac/Linux helper、iPhone、enclave 三端共用）────────────────┐
│  ①身份 → ②策略 → ③审批 → ④签发 → ⑤交付 → ⑥脱敏 → ⑦审计                                 │
└────────┬───────────────────────────┬──────────────────────────────┬─────────────────────┘
         ▼                           ▼                              ▼
  审批端 Approvers            执行端 Executors                 存储后端 Storage
  · Mac Touch ID              · Mac helper (Secure Enclave)    · 本地 vault (Keychain 包裹)
  · iPhone 两级审批           · Linux helper (TPM2)            · iCloud Keychain 同步
  · Android StrongBox         · iPhone 前台，仅短请求          · 1Password (op:// 引用)
  · Windows Hello             · Nitro enclave (阶段 4)          · Bitwarden / Infisical
  · 策略自动放行 (T0)         · 客户 AWS 内 enclave (Ent.)    · Vault / OpenBao / Secrets Manager
  · 团队审批人 N-of-M         · CI 身份: GitHub OIDC / IMDS    · AWS KMS (主密钥托管)
         ▲                           ▲
         └──────────── E2E 加密消息 ─┴──────────────┐
                                                    ▼
┌──────── 服务端：自建 Docker 或 AWS EC2 + Nitro；端到端加密，只见密文 ────────────────┐
│ relay 路由 · 待审批队列 · 设备在线表 │ 远程 MCP 端点 (OAuth 2.1 AS, CIMD, PRM)          │
│ 密文存储 · 设备注册 · 团队策略与审计同步 │ 推送网关（只发唤醒信号，不含内容）          │
└───────────────────────────────────────────────────────────────────────────────────────┘
```

### 7.2 核心引擎流水线

| 步骤 | 做什么 | 关键设计 |
| --- | --- | --- |
| ① 身份 | 每个 agent 实例有一对密钥，签名所有请求 | 本机 Secure Enclave / Linux TPM2 / Windows CNG；CI 用 GitHub OIDC、AWS IMDS 等云身份 |
| ② 策略 | 规则引擎决定自动放行 / 需审批 / 拒绝 | 风险分级：T0 只读（GET、`readOnlyHint` 工具）自动放行并审计；T1 写操作按凭据授权；T2 敏感（支付、IAM、删除、超预算）逐次强审批；T3 禁止（非白名单 host、内网 IP）直接拒绝。支持仓库内 `.keyvalet/policy.yaml` 加组织级覆盖；从历史推荐规则 |
| ③ 审批 | 可插拔 Approver | 审批绑定规范化请求摘要（method、host、path、body 哈希），弹窗同时显示 agent 声明的用途和真实请求，审批结果一次性有效 |
| ④ 签发 | 长期凭据换短期、限权 token | 现有 protocols 全部保留；签发的 JWT 用 `sub`=用户、`act`=agent、`purpose` 自定义 claim |
| ⑤ 交付 | 优先级：代理执行 > 文件路径 > 明文 | 明文需显式允许；`proxy_only` 为默认推荐 |
| ⑥ 脱敏 | 响应中的密钥及编码变体过滤 | 已有 `kv-proxy/redact.rs`，加防 SSRF（只 HTTPS、拒内网、只放行绑定域名） |
| ⑦ 审计 | 哈希链串联、不可篡改 | 字段映射 OTel GenAI，保留 `_meta.traceparent`；记录策略决策、审批人设备、上游状态码 |

### 7.3 审批协议（KeyValet Delegation Protocol v0）

```
请求  = { agent_id, credential_id, request_digest, purpose, runtime, repo/cwd, nonce, exp }
        由 agent 设备密钥签名
审批  = Sign_approver( request_digest || nonce || decision || grant_scope )
        一次性；执行端验证 agent 签名 + 审批签名 + nonce 未用过 + 未过期
预授权 = 能力令牌 JWT { sub, act, authorization_details(RFC 9396 风格), budget, exp }
        手机或 Mac 签发，适用于人不在场的 CI / 夜间任务；可随时吊销
```

两级手机审批：

- 快速批准（锁屏）：`authenticationRequired` 强制设备解锁；用不带生物识别 ACL 的 SE 密钥签名；只允许 T0/T1。
- 强批准（打开 App）：Face ID 绑定的 `.biometryCurrentSet` 密钥签名；T2 必须走这一级；弹窗显示完整请求。

### 7.4 密钥体系

```
设备身份密钥（每台设备一把，不可导出，不可同步）
  iPhone SE P-256 × 2：快速批准密钥（解锁即可用）+ 强批准密钥（.biometryCurrentSet）
  Mac SE / Linux TPM2 / Windows CNG / Android StrongBox
  enclave：每次启动生成，通过远程证明绑定

用户主密钥 UMK（随机 256 位）
  ├ 用每台已注册设备的密钥各包裹一份（SE 密钥不能 iCloud 同步，所以每台设备单独注册）
  └ 用恢复码派生密钥包裹一份（纸质备份，必须有）

每条凭据的 CEK ── 由 UMK 包裹
凭据密文 ── 存在用户选择的存储后端

阶段 4 的 enclave：每次只拿单条凭据的 CEK（HPKE 加密给经证明的 enclave 公钥），用完即弃；
         预授权场景下 CEK 由 KMS 包裹，key policy 用 kms:RecipientAttestation:ImageSha384 绑定 PCR0
         （这条路径信任的是 KMS 密钥所属 AWS 账号的治理：默认 BYO-KMS 由客户控制；托管 KMS 需明示运营方信任，见架构文档 §11.4）
```

关键约束：enclave 永远拿不到 UMK，即使被攻破也只能影响单次请求的单条凭据。加设备：用已有设备解开 UMK 后用新设备密钥重新包裹。吊销设备：删掉它那份包裹并轮换 UMK。

### 7.5 执行端路由

1. 请求来自已配对的 Mac 本机：本机执行，走 Touch ID，不经 relay。
2. Mac 或 Linux helper 在线：转给它执行；审批走本机 Touch ID 或推送到手机。
3. 都不在线但手机在前台且是短请求：手机执行。
4. 团队开通了 CI 离线执行附加项（阶段 4）：Nitro enclave 执行，审批走手机或预授权策略。
5. 以上都不满足：拒绝并告知原因。「设备离线」是 CI 离线执行附加项的转化点。

### 7.6 服务端两种模式

| | A 自建（Docker） | B AWS |
| --- | --- | --- |
| 组件 | relay + 密文存储 + 远程 MCP 端点 + 团队同步 | 同左，宿主 EC2 + Nitro enclave 执行端 |
| 看得到明文吗 | 不能，只转发和存密文 | 不能，明文只在 enclave 内 |
| 设备全离线 | 不能执行 | 能执行 |
| 成本 | 一台小 VPS（simvito 即可） | c7g.large 按需约 53 美元/月，1 年 SP 约 35–38，Spot 约 17–20 |
| 用途 | Free 用户自建；Simvito Limited 运营的官方 relay（美国托管） | 阶段 4：Team 的 CI 离线执行附加项；Enterprise 部署在客户自己的 AWS（BYO-KMS） |

推送网关：APNs 必须用 Simvito Limited 的推送密钥，用户自建的服务器拿不到。Simvito Limited 运营一个只发「有新审批」唤醒信号的网关，不含任何内容；手机被唤醒后直接连回用户自己的服务器拉取加密请求。Bitwarden、Mattermost 都是这个做法。不想依赖网关的用户可以自己编译 iOS App 用自己的推送证书，或者只用「打开 App 时拉取」模式。

### 7.7 透明代理模式

`keyvalet run -- <cmd>` 为本次运行生成会话 token，只对子进程设置 `HTTPS_PROXY=http://<token>@127.0.0.1:8788` 和 CA 相关环境变量（含 `NODE_USE_ENV_PROXY=1`、`NODE_EXTRA_CA_CERTS`、`SSL_CERT_FILE`、`REQUESTS_CA_BUNDLE`、`AWS_CA_BUNDLE`）；请求里写占位符 `${KEYVALET:openai/default}`，代理替换成真值。代理拒绝无 token 的连接；CA 私钥在 helper，代理只拿短期叶证书；不做按 host 自动注入。配合 Claude Code `/sandbox`：沙箱只允许访问 KeyValet 代理，忽略代理变量的工具也出不去。

### 7.8 存储后端接口

```
trait SecretSource {
  fn list(&self) -> Vec<CredentialMeta>;        // 只有元数据，不读明文
  fn get(&self, id) -> Secret;                   // 仅在 vault 内部调用，受审批约束
  fn put(&self, id, Secret) -> Result<()>;       // 可选
}
```

后端：本地 vault（现有）、iCloud Keychain（非 SE 条目，Apple 负责 E2E）、1Password（`op` CLI 或 Connect，存 `op://vault/item/field` 引用，不复制明文，用户在 1Password 里轮换后自动生效）、Bitwarden（`bw`）、Infisical（顺带 dynamic secrets）、Vault/OpenBao、AWS Secrets Manager + KMS、GitHub OIDC 换短期凭据（CI）。

### 7.9 一键导入

- 1Password：`op item list` + `op item get --format json`，或解析 `.1pux`。
- Bitwarden：`bw list items` 或 `bw export --format json`。
- macOS Keychain：每个条目系统都会单独弹「允许访问」，只能做选择性导入，不承诺一键。
- `.env` 和 agent 配置文件（`~/.claude.json`、`.cursor/mcp.json`、`~/.codex/config.toml`）：`keyvalet scan` 扫描、导入、替换为占位符，导入成功后复用 `delete_source_file` 的确认流程。
- 流程：先列元数据，自动识别适合 agent 的条目（API Credential 类型、字段名含 api_key/token/secret、SSH Key、TOTP、URL 匹配模板），用户在原生窗口勾选后才读明文；导入逻辑放在 helper 侧，明文不经过 MCP 和模型上下文。

### 7.10 现有 Rust 工作区到组件的映射

| crate（现有） | 对应组件 | 需要新增 |
| --- | --- | --- |
| `kv-core`（auth_gate、dispatch、settings） | ② 策略、③ 审批、路由 | `kv-policy`（规则引擎）、`kv-approval`（哈希绑定、一次性 nonce） |
| `kv-vault`（crypto、validate、vault） | 存储加密、UMK/CEK | `kv-storage-*` 后端插件（1password、bitwarden、infisical、aws） |
| `kv-protocols`（oauth2、jwt、github_app、google_sa、aws、totp、http） | ④ 签发 | `act`/`purpose` claims |
| `kv-proxy`（proxy、gateway、redact、manage） | ⑤ 交付、⑥ 脱敏、透明代理 | 防 SSRF、占位符替换、CA 管理 |
| `kv-touchid` | Mac Approver | `kv-relay-client`（用户态 relay 客户端，helper 不出网） |
| `kv-platform`（macos、trust、paths） | 平台层 | Linux（TPM2）、Windows（CNG） |
| `kv-ipc`、`kv-i18n`、`kv-helper` | 进程与本地化 | — |
| 新 | `kv-audit`（哈希链、OTel 映射）、`kv-server`（axum：relay、远程 MCP 端点、密文存储）、`kv-enclave`（Nitro 执行端，复用 core + protocols + proxy） | iOS 通过 UniFFI 调用 `kv-core` 的审批与加密逻辑 |

### 7.11 威胁模型（对外公开版本）

| 威胁 | 防得住吗 |
| --- | --- |
| prompt injection 让 agent 外泄密钥 | 是。agent 没有密钥；审批绑定真实请求 |
| 恶意依赖在本机搜刮 .env、配置文件 | 是。密钥不在文件里；`keyvalet scan` 帮用户清理 |
| 不可信 CI 输入劫持 agent | 是。CI 只有短期限权 token，且受策略约束 |
| 恶意 MCP 服务器 | 是。同上，加 host 白名单 |
| 本机其他进程借透明代理拿到注入 | 是。会话 token 认证；CA 私钥在 helper；只有占位符或显式 `--inject` 才注入 |
| relay 或云运营方被攻破 | 是。只有密文；enclave 可证明 |
| 手机丢失 | 是。恢复码加其他已注册设备；远程吊销 |
| agent 宿主被攻破 | 部分。`proxy_only` 加绑定审批限制爆炸半径，但在已授权窗口内可滥用 |
| 以用户身份运行的恶意软件触发审批 | 不防（SECURITY.md 已写明）。靠绑定请求展示降低误批 |
| hook 被绕过（Codex 不覆盖全部 shell 路径、Copilot 超时放行、Goose 嵌套调用） | 部分。hook 是纵深防御，真正的保证来自「agent 从未持有密钥」 |
| 供应链投毒（Bitwarden 2026-04 npm 事件） | 部分。Rust 减少依赖、签名发布、可复现构建、安装脚本拒绝不受信任的运行时 |

---

## 8. 产品分层与定价

独立开发者版本：两档先行，收入靠 Team 自助付费；个人为「安全」几乎不付费（Bitwarden Premium 1.65 美元/月，1Password 消费者收入不到 25%），所以不设个人付费 SKU。

| 档位 | 阶段 | 价格 | 包含 | 对标 |
| --- | --- | --- | --- | --- |
| Free（开源，Apache-2.0） | 0 起 | 0 | 本地 vault、全部协议和约 50 个模板、Claude Code / Codex / Cursor / Grok 的 hooks、策略引擎、Linux helper、自建 relay、官方 relay 合理使用（3 台设备、每月 2,000 次远程审批、待审批保留 7 天）、iCloud 同步、1Password / Infisical 后端、本地审计；阶段 3 起含 iPhone 审批 App | Tailscale 个人免费 |
| Team v1 | 2（第 6 个月起收费） | 15 美元/席位/月，年付 12；机器身份不限量（合理使用） | 共享凭据（成员设备间包裹 CEK，各自用本机 Touch ID 审批）、组织策略即代码、审计导出（JSONL / OTLP）、CI 身份（GitHub OIDC 换能力令牌）、托管 relay 不限额度、密文跨设备同步、邮箱账号与成员管理 | GitGuardian 约 18、Infisical 20、Doppler 21 |
| Team 完整版 | 3 | 18 美元/席位/月，年付 15 | Team v1 + 审批路由到负责人手机、敏感凭据 N-of-M、Linux / CI 的手机强审批、OIDC SSO、90 天加密审计留存 | 同上 |
| Team 附加项：CI 离线执行 | 4 | 0.5 美元/千次 enclave 执行，每席位每月含 2,000 次 | 设备全离线时在 Nitro enclave 内执行；默认 BYO-KMS（客户自己的 AWS 账号）；托管 KMS 需接受运营方账号治理的信任声明 | Keycard 按事务、Arcade 按授权事件计费 |
| Enterprise | 4 以后 | 年合同 5 万美元起 | 自建服务端加客户 AWS 内 enclave、SCIM、Okta Cross-App Access、Vault / OpenBao 后端、SOC 2、SLA | Teleport 5 万起 |

定价依据：

- Team v1 定 15 美元是为了低于 Infisical / GitGuardian / Doppler 的 18–21 锚点；它比完整版少了手机路由和 SSO，补齐后升到 18。
- 机器身份不限量：CI 重度团队是最想付费的群体，不能被按个计费卡住；滥用靠合理使用条款和 enclave 计量兜底。
- 不设个人 Cloud SKU：第一年的个人付费按模型只有约 1 万美元 ARR，却要承担最重的工程。个人用户的「设备离线也要用」需求，用自建 relay 或加入一个 Team 解决。
- 不做纯按次计费：agent 调用次数难预测；enclave 执行按用量只作为附加项。
- Team 14 天免费试用，不需要信用卡，到期不自动扣款；不做限时折扣。

开源许可：核心和 relay 保持 Apache-2.0；Team 功能放 `ee/` 目录，源码可见的商业许可（参照 Infisical）；阶段 0 做一次商标检索。

---

## 9. 商业模型与财务假设

两套数字：独立开发者基准线按一个人加 30–40% 自由职业时间估算，默认按它规划；乐观情形按第 9 个月融资后 3–4 人团队估算。转化率基准：开发者工具 freemium 中位 3–5%，安全类处于低峰 1–3%；OSS 组织转 Team 假设 6 个月内 3–5%。全部是假设。

### 9.1 独立开发者基准线

| 指标 | 第 1 年 | 第 2 年 | 第 3 年 |
| --- | --- | --- | --- |
| 累计安装 | 2 万 | 8 万 | 20 万 |
| 周活 | 4,000 | 15,000 | 40,000 |
| 付费团队 / 席位 | 10 / 80 | 60 / 600 | 180 / 2,000 |
| Team ARR（年付 12–15 美元/席位/月） | 1.2 万 | 10 万 | 33 万 |
| CI 离线执行附加项 | 0 | 2 万 | 8 万 |
| Enterprise | 0 | 0–1 个试点 | 2 × 5 万 |
| 合计 ARR（美元） | 约 1–2 万 | 约 12–17 万 | 约 50 万 |

这条线的意义：第 2 年覆盖一个人的生活成本，第 3 年成为「有收入的开源项目」，可被收购。

### 9.2 乐观情形（第 9 个月融资，3–4 人）

| 指标 | 第 1 年 | 第 2 年 | 第 3 年 |
| --- | --- | --- | --- |
| 累计安装 | 3 万 | 15 万 | 40 万 |
| 周活 | 6,000 | 30,000 | 80,000 |
| 付费团队 / 席位 | 20 / 200 | 150 / 1,800 | 500 / 6,000 |
| Team ARR | 3.6 万 | 32 万 | 108 万 |
| CI 离线执行附加项 | 0 | 5 万 | 20 万 |
| Enterprise | 0 | 2 × 5 万 | 8 × 10 万 |
| 合计 ARR（美元） | 约 4 万 | 约 47 万 | 约 210 万 |

个人层对收入贡献为零，但它是品牌、信任和自下而上渗透团队的通道，不能省。

### 9.3 成本结构

| 项目 | 金额 | 说明 |
| --- | --- | --- |
| relay + 推送网关 | 约 20–40 美元/月 | 一台美国 VPS |
| Ory Hydra | 0 | 自托管，随 relay 部署 |
| Nitro 执行端（阶段 4） | 约 70–110 美元/月 | 2 台 c7g.large，1 年 Savings Plan |
| 海外主体 | 约 1,000–3,000 美元/年 | 注册与年审 |
| 第三方安全审计 | 3–6 万美元，第 2 年 | 有付费团队后 |
| SOC 2 Type I | 3–6 万美元，第 3 年 | Enterprise 需要时 |
| Apple 开发者、域名、CI | 不到 1,000 美元/年 | — |
| 人力 | 1 人（基准线）或 3–4 人（乐观） | 主要成本 |

单位经济：relay 流量可忽略；一台 c7g.large 可服务数千用户，每次 enclave 执行成本远低于 0.5 美元/千次的售价，毛利率 90% 以上。

---

## 10. 路线图

顺序原则：先做能收费的，再做手机，最后做 enclave。每阶段有门槛，不达标不进下一阶段。

2026-10-09 补充决策：macOS Secure Enclave 本地保护现在推进，不等待 Team 或云端执行；本地硬件保护属于基础安全能力，不以 Free / Team 区分。Linux / CI 优先做调用与身份接入，TPM 可选，远程执行依赖配对与 relay。Windows 原生 TPM + Hello 支持按明确用户需求排期，不承诺原阶段 4 的固定月份。云端隔离执行随设备离线 / 无人值守需求推进，首个方案为 AWS Nitro Enclaves + KMS，BYO-KMS 默认；可作为承担部署与运维成本的付费能力。VBS Enclaves、Linux SGX、Azure / GCP 当前只预留接口。技术保证及兼容、恢复要求见产品 §1.4 与架构 §8.0。

```
月  0   1        4             8               14                      24
    │───│────────│─────────────│───────────────│───────────────────────│
    阶段0 阶段1   阶段2          阶段3            阶段4
    发布  策略与   relay + Team   iPhone 与 Team   CI 离线执行、远程 MCP、
         Linux    v1 收费        完整版           Enterprise
    ◇     ◇        ◇             ◇                ◇
  发布完成 1万安装  第6月3家付费   20家付费团队     5家企业合同或
          ≥3凭据   团队；D30留存  周活8000；第9月  附加项收入≥5万/年
          周活20%  ≥25%           融资复盘
```

| 阶段 | 月份 | 交付物 | 门槛 |
| --- | --- | --- | --- |
| 0 发布 | 0–1 | macOS Secure Enclave 本地主密钥保护验证与显式迁移（P §1.4）；按 `marketing/launch-plan.md` 发 v0.1；审批弹窗显示 method/host/path 并绑定请求摘要；工具 annotations；hooks 复用到 Codex，Cursor 适配，Grok 核实后 MCP 接入；SDK 升级到 2026-07-28 规范；`keyvalet scan`；商标检索；启动海外主体注册；官网改版（定价页、对比页、安全页） | 发布完成，首批反馈 |
| 1 策略与 Linux | 1–4 | 策略引擎 v1（风险分级、host/method 规则、预算、`.keyvalet/policy.yaml`）；grant 范围明确化；模板 `summarize`；Linux / CI 调用与身份接入、本地 helper 兼容路径（系统用户 + Unix socket，TPM2 可选，TTY 仅 Quick；P §1.4）；`keyvalet hooks install --all`；审计哈希链；能力令牌（Mac 签发，CI 使用） | 1 万安装；有 ≥3 条凭据的周活占比 ≥ 20%；每周活审批次数与拒绝率有数据 |
| 2 relay + Team v1 收费 | 4–8 | 自建 relay（Docker，官方实例美国托管，无推送）；`kv-relay-client` 用户态进程；密文同步与 vault v2；Team v1（邮箱账号、成员、共享凭据 Mac 对 Mac 包裹、org 策略、审计导出、GitHub OIDC CI 身份）；Team Web 控制台 v1；Stripe；透明代理 opt-in（会话 token、CA 在 helper）；1Password 与 Infisical 后端；10 家设计合作伙伴 | 第 6 个月 3 家付费团队；D30 留存 ≥ 25%；`proxy_only` 占比 ≥ 60% |
| 3 iPhone 与 Team 完整版 | 8–14 | iPhone App 上架（两级审批、配对、NSE、App Attest）；推送网关；控制台「浏览器作为设备」；`remote-phone` Approver；审批路由到 owner、N-of-M；Linux / CI 手机强审批；OIDC SSO（Ory Hydra）；Team 完整版定价；第一次第三方安全审计 | 20 家付费团队；周活 8,000；第 9 个月融资复盘 |
| 4 CI 离线执行、远程 MCP、Enterprise | 14–24 | AWS Nitro 执行端（BYO-KMS 优先，托管 KMS 带信任声明）、可复现 EIF、客户端固定 PCR 允许列表；远程 MCP 端点（Hydra 作 AS）；Enterprise 自托管 Terraform；SCIM；Okta Cross-App Access；Vault / OpenBao 后端；SOC 2 Type I；Android App；Windows TPM + Hello 本地客户端按明确需求另行排期；凭据轮换；标准参与（MCP ext-auth 扩展；user-mediated delivery 草案只跟踪） | 5 家企业合同，或附加项收入 ≥ 5 万美元/年 |

---

## 11. GTM

**叙事**：「今年 agent 把开发者的密钥弄丢了五次」系列内容，每个事件对应一个控制点，核心一句话：「就算 agent 被注入，它也拿不到你的 key。」

**渠道**（按触达/投入比）：Claude Code 官方插件市场 → Codex plugins → cursor.directory 再到 Cursor Marketplace → 所有 MCP 目录 → Infisical、1Password 社区（以存储后端集成方身份出现）→ 安全社区（OWASP Agentic、BSides 演讲，把 KeyValet 映射到 OWASP ASI02/03/09）→ Copilot hooks（第二批运行时）。

**三类受众三套话术**：

| 受众 | 话术 | 买点 |
| --- | --- | --- |
| 开发者 | 你的 agent 永远看不到密钥 | 免费、一条命令、不改代码 |
| 平台或 DevEx 负责人 | 一个 vault，所有 agent，所有运行时；策略即代码；CI 身份 | SSO、共享凭据、审计导出 |
| CISO / AppSec | AI agent 在终端和 CI 上的运行时访问控制与审计 | 自托管、enclave 可证明、合规映射、SOC 2 |

**设计合作伙伴画像**：重度使用 Claude Code 且有安全团队的公司，优先金融科技和开发者工具公司；免费 6 个月 Team，换反馈、logo 和案例。

**核心指标**（按预测付费的能力排序）：有 ≥3 条凭据的周活占比、`proxy_only` 占比、D30 留存、每周活审批次数与拒绝率、团队转化率、首次价值时间。手机配对率只作阶段 3 的参考指标，不作门槛。

**内容计划**：发布周 Show HN 加 X 长帖；每月一篇事故复盘（s1ngularity、Comment and Control、GhostSplice、CVE-2026-21852、DuneSlide）；每季度一份「agent 配置里的密钥」统计（复现 GitGuardian 的 MCP 配置扫描方法）；SECURITY.md 保持诚实，所有安全质疑直接引用它回答。

---

## 12. 风险与对策

| 风险 | 严重度 | 对策 |
| --- | --- | --- |
| 1Password 的平台级签约（Anthropic、OpenAI、Cursor、GitHub 合作方；定价页已出现「Runtime credentials for AI agents」；Privileged Access 已于 2026-07-28 推出，含「AI Agent Control」和「Intent-Based Access Control」） | 最高（企业侧） | 做它上面的一层：支持 `op://` 后端，主攻它不做的 API / CLI / CI / Linux / 签发；独立开发者阶段不碰企业侧 |
| Infisical Agent Vault 补上人工审批和 MCP（PR #434 已存在） | 最高（团队侧） | 见 §3.4：抢它没有的，同时把它做成后端；监控三个触发信号 |
| 审批疲劳（业内引用「93% 的弹窗被批准」，来源待补） | 高 | 策略引擎让弹窗变少但每次有意义；绑定真实请求 + 模板 `summarize` 让弹窗值得看；任务级授权；用数据盯住每周活审批次数 |
| 个人付费意愿低 | 高 | 个人全免费，不设个人 SKU，收入放 Team |
| 一个人的时间与分发 | 高 | 两档产品、阶段门槛、保留 30–40% 自由职业收入；第 6 个月不达标降级为 side project |
| 主体与托管地的信任折扣 | 高 | 海外主体；官方 relay 与推送网关美国托管；开源 + 可复现构建 + 诚实的 SECURITY.md |
| 运行时自建本地 vault（Cursor 约 40%，Anthropic 约 30%） | 中 | 多运行时和跨平台策略是它们不会做的 |
| 供应链（Bitwarden 2026-04 npm 投毒） | 中 | Rust 减少依赖、签名发布、SLSA、安装脚本拒绝不受信任的运行时 |
| KMS 托管路径的运营方信任（阶段 4） | 中 | 默认 BYO-KMS；托管 KMS 用独立账号、变更告警、公开信任声明 |
| iOS 后台限制 | 已处理 | 手机只审批，执行交给 helper 或 enclave |
| hook 可绕过 | 低 | 文档标注为纵深防御；核心保证是 agent 不持有密钥 |
| 商标冲突 | 低 | 阶段 0 检索；发布前改名成本最低 |

---

## 13. 融资与退出

- 自举路径：OSS 核心 + Team 15–18 美元，独立开发者基准线（§9.1）第 2 年约 12–17 万、第 3 年约 50 万美元 ARR；按 Tailscale 式漏斗加团队后可到 100–300 万，但要接受安全类工具转化率低、收入靠 Team 的现实。
- 风投路径：投资人有明确论点（a16z 2026 Big Ideas 的 KYA 和 secrets-as-a-service，Sequoia 把身份视为 agent 经济的问责层，YC S2026 RFS 包含 agent 身份和权限层）。第 9 个月复盘，门槛见 §1.3，达标则融 200–400 万美元种子轮。
- 退出路径（最可能的结局）：

| 潜在买家 | 为什么 | 可比交易 |
| --- | --- | --- |
| GitGuardian、Doppler、Infisical、Bitwarden | 还没补「笔记本和 CI 运行时」这一块 | — |
| Teleport、Snyk、Cycode/Apiiro | 开发者安全平台补 agent 能力 | Entro→SailPoint 约 2 亿 |
| 1Password、Okta、Cisco、CrowdStrike、Palo Alto | 平台型买家补 agent 身份 | Stytch→Twilio 1.04 亿（2025-11）；Astrix→Cisco 3–4 亿；SGNL→CrowdStrike 7.4 亿；Apono→1Password 未披露 |
| Anthropic、Cursor/SpaceX、OpenAI、GitHub/JetBrains | 运行时厂商把本地凭据层收进来 | Natoma→Snowflake 1.28 亿（27 人、融资 700 万、成立 2 年） |

前提是在 Claude Code/Cursor/Codex 用户群里形成可观的安装基数和品牌。Stack Overflow 2026 的 Claude Code 66% 份额和 JetBrains 的 39% 渗透说明这个基数正在高速扩大。

---

## 14. 未来 90 天行动清单

- [ ] 第 1–2 周：按 `marketing/launch-plan.md` 发布 v0.1（gh 登录、仓库 Pages、tag、Show HN、X、Reddit、MCP 目录）
- [ ] 第 1–2 周：商标检索（KeyValet，美国与中国）
- [x] 域名 keyvalet.dev 已注册；D-U-N-S 已完成
- [ ] 以 Simvito Limited 开 Apple 开发者组织账号与 Stripe 账号；防御性注册 .ai/.io/.app（可选）；占住 npm / crates.io / PyPI 的 `keyvalet` 包名与 GitHub `keyvalet` 组织（组织已建，仓库待转移）
- [ ] 第 8–12 周：官方 relay 的美国托管选型（VPS 或 us-east-1），为阶段 2 准备
- [ ] 第 8–12 周：法律页初稿（隐私政策、服务条款、数据处理说明），收费前完成
- [ ] 第 1–2 周：把 `rust/` 工作区提交进 git，确定它作为 Mac、Linux、enclave 三端共用核心的边界
- [ ] 第 2–4 周：审批弹窗显示 method/host/path 并绑定请求摘要（`auth-gate.ts` / `kv-core/auth_gate.rs`、`protocols/http.ts`）
- [ ] 第 2–4 周：所有 MCP 工具加 annotations；SDK 升级到 2026-07-28 规范
- [ ] 第 3–5 周：hooks 复用到 Codex（`~/.codex/hooks.json`），Cursor manifest 原型；核实 Grok 的 MCP 与 hook 能力
- [ ] 第 4–7 周：`keyvalet scan`：扫描 `~/.claude.json`、`.cursor/mcp.json`、`~/.codex/config.toml`、`.env`，一键导入并替换占位符
- [ ] 第 6–10 周：策略引擎 v1（风险分级、host/method 规则、`.keyvalet/policy.yaml`），开始收集每任务审批次数和拒绝率
- [ ] 第 8–12 周：Linux helper 原型（TPM2 可选，TTY 确认 + 预授权令牌由 Mac 签发）
- [ ] 第 8–12 周：开始接触 10 家设计合作伙伴（重度 Claude Code 用户 + 有安全团队）
- [ ] 持续：每月一篇事故复盘内容；提交 CIMD 文档到 keyvalet 域名
- [ ] 第 4–8 周：对 draft-emerson-oauth-user-mediated-delivery 的专利声明做 FTO 排查（KeyValet 是代理端模型，但要确认权利要求范围）

---

## 15. 来源与未核实清单

### 15.1 主要来源

市场与事件：
- https://www.gitguardian.com/state-of-secrets-sprawl-report-2026
- https://blog.gitguardian.com/ai-coding-agents-credential-security/
- https://blog.gitguardian.com/the-nx-s1ngularity-attack-inside-the-credential-leak/
- https://www.securityweek.com/claude-code-gemini-cli-github-copilot-agents-vulnerable-to-prompt-injection-via-comments/
- https://asset-group.github.io/disclosures/ghostsplice/
- https://thehackernews.com/2026/02/claude-code-flaws-allow-remote-code.html
- https://www.catonetworks.com/blog/duneslide-two-critical-rce-vulnerabilities/
- https://www.globenewswire.com/news-release/2026/10/06/3375448/0/en/sailpoint-report-finds-79-of-enterprises-run-ai-agents-in-production-yet-only-2-have-deployed-purpose-built-security.html
- https://www.gartner.com/en/newsroom/press-releases/2026-04-28-gartner-identifies-six-steps-to-manage-artificial-intelligence-agent-sprawl
- https://survey.stackoverflow.co/2026/ai/data/ai-select
- https://blog.jetbrains.com/research/2026/08/ai-coding-agent-adoption-2026/
- https://news.crunchbase.com/cybersecurity/solid-startup-venture-funding-growth-h1-2026/
- https://techcrunch.com/2026/09/29/reco-raises-55m-as-ai-agent-security-startups-crowd-the-market/

竞品：
- https://1password.com/press/2026/july/1password-for-claude
- https://1password.com/press/2026/mar/1password-unified-access
- https://1password.com/blog/1password-credential-broker-public-preview
- https://www.1password.dev/cli/app-integration-security/
- https://www.1password.dev/ssh/agent/security/
- https://www.1password.dev/agentic-autofill
- https://thesynthesisai.substack.com/p/the-vault
- https://github.com/dennischoubot-glitch/synauth-mcp
- https://infisical.com/blog/agent-vault-the-open-source-credential-proxy-and-vault-for-agents
- https://github.com/Infisical/agent-vault
- https://docs.gitguardian.com/releases/saas/2026/09/07/changelog
- https://www.keycard.ai/pricing/ · https://aembit.io/pricing/ · https://www.arcade.dev/pricing/ · https://infisical.com/pricing · https://tailscale.com/pricing

平台：
- https://code.claude.com/docs/en/hooks · https://code.claude.com/docs/en/sandboxing · https://code.claude.com/docs/en/remote-control
- https://cursor.com/docs/agent/hooks · https://cursor.com/blog/marketplace
- https://developers.openai.com/codex/hooks
- https://docs.github.com/en/copilot/reference/hooks-reference
- https://geminicli.com/docs/hooks/ · https://developers.googleblog.com/an-important-update-transitioning-gemini-cli-to-antigravity-cli/
- https://opencode.ai/docs/plugins/ · https://goose-docs.ai/docs/guides/context-engineering/hooks/ · https://cline.bot/blog/cline-v3-36-hooks
- https://github.com/anthropics/claude-code/issues/70716 · https://claude.com/blog/claude-managed-agents

标准：
- https://modelcontextprotocol.io/specification/latest/basic/authorization
- https://github.com/modelcontextprotocol/ext-auth
- https://www.okta.com/newsroom/press-releases/okta-announces-cross-app-access-partners/
- https://datatracker.ietf.org/doc/draft-ietf-oauth-transaction-tokens/
- https://datatracker.ietf.org/doc/draft-ietf-webbotauth-httpsig-protocol/
- https://csrc.nist.gov/projects/cosais

技术：
- https://developer.apple.com/documentation/usernotifications/unnotificationactionoptions/authenticationrequired
- https://developer.apple.com/forums/thread/765094
- https://developer.apple.com/documentation/cryptokit/secureenclave
- https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave.html
- https://docs.aws.amazon.com/kms/latest/developerguide/conditions-nitro-enclave.html
- https://github.com/monzo/aws-nitro-util
- https://nodejs.org/learn/http/enterprise-network-configuration
- https://developer.android.com/privacy-and-security/keystore

核实用一手来源（第二版）：
- https://apps.apple.com/us/app/1password-password-manager/id1511601750 · https://1password.com/business-pricing · https://1password.com/product/privileged-access · https://1password.com/blog/introducing-1password-privileged-access · https://support.1password.com/activity-log/
- https://www.sec.gov/Archives/edgar/data/1447669/000144766926000021/R69.htm（Twilio 10-K，Stytch）
- https://www.ietf.org/archive/id/draft-emerson-oauth-user-mediated-delivery-00.txt
- https://github.com/Infisical/agent-vault/pull/434 · https://api.github.com/repos/Infisical/agent-vault
- https://prices.azure.com/api/retail/prices（Standard_DC2as_v5、Container Instances）· https://azure.microsoft.com/en-us/pricing/details/container-instances/
- https://cloud.google.com/products/compute/pricing/general-purpose · https://cloud.google.com/spot-vms/pricing · https://cloud.google.com/confidential-computing/confidential-vm/pricing
- https://tinfoil.sh/pricing · https://www.ovhcloud.com/en/bare-metal/prices/ · https://phala.com/pricing
- https://developer.apple.com/documentation/usernotifications/pushing-background-updates-to-your-app · https://developer.apple.com/documentation/cryptokit/secureenclave/mldsa65 · https://developer.apple.com/videos/play/wwdc2025/314/
- https://code.claude.com/docs/en/monitoring-usage · https://raw.githubusercontent.com/open-telemetry/semantic-conventions-genai/main/docs/gen-ai/gen-ai-spans.md
- https://httpx2.pydantic.dev/environment_variables/ · https://github.com/openai/openai-python/blob/main/pyproject.toml
- https://www.gitguardian.com/pricing · https://www.doppler.com/pricing · https://bitwarden.com/pricing/ · https://auth0.com/pricing · https://aws.amazon.com/bedrock/agentcore/pricing/

### 15.2 第二版核实结果（2026-10-07）

| 项目 | 第一版 | 核实结果 | 来源 |
| --- | --- | --- | --- |
| 1Password 个人/团队价格 | 3.99 / 7.99 [未核实] | 官网已不公示消费者价格；App Store 内购个人月付 4.99、年付 47.99，家庭年付 71.99；Teams Starter Pack 24.95/月含 10 席；Business 年付 8.99/用户/月 | App Store 条目、1password.com/business-pricing |
| 1Password for Claude 范围 | 是否覆盖 Claude Code 未知 | 仅 Claude Desktop + 浏览器扩展（macOS）；8–10 月无更新；未提 Claude Code / Cowork | 新闻稿、1password.dev |
| 用途是否入 1Password 审计 | 未知 | Activity Log 字段无用途；官方无记载，倾向否 | support.1password.com/activity-log |
| Apono 整合 | 未知 | 2026-07-28 推出 Privileged Access（JIT、AI Agent Control、Intent-Based Access Control）；收购金额未披露 | 1password.com/blog、product/privileged-access |
| Stytch→Twilio | 未披露 | 2025-10-30 签约、11-14 交割，1.041 亿美元 | Twilio 8-K、10-K |
| Wiz 关于 Amazon Q 的报告 | 待找 | Wiz 博客与 sitemap 均无此文，已从本文删除 | wiz.io |
| Octoverse 2026 | 待发布 | 截至 2026-10-07 未发布 | octoverse.github.com |
| Cursor ARR / SpaceX | 40 亿+；据报道 | 可核到 ARR 30 亿（Bloomberg 2026-05-21）；SpaceX 600 亿收购 2026-08-14 完成 | Wikipedia 引注 |
| Okta XAA 是否含 OpenAI | 未核实 | 新闻稿全文无 OpenAI/ChatGPT | okta.com |
| Claude Code 的 OTel GenAI 属性 | beta [未核实] | beta traces 的 span 带 gen_ai.*；metrics 与日志用 claude_code.*；semconv 仍 Development | code.claude.com/docs、semantic-conventions-genai |
| SynAuth | App 与后端未知 | 美区 App Store 搜不到；作者账号无后端仓库；仓库 0 star、2026-02-24 后无提交 | iTunes Search API、GitHub API |
| Infisical Agent Vault 与 MCP | 未核实 | 本身不是 MCP server，代理 MCP/CLI/SDK 的出站流量；v0.40.0；2,316 star；审批 PR #434 仍 open | GitHub API、README |
| IETF user-mediated delivery 草案 | 内容未核实 | Informational，资源方模型，声明专利申请中；与 KeyValet 代理端模型不同 | ietf.org 草案全文 |
| OpenCode / Goose / Cline 规模 | 估计 | 212,118 / 55,028 / 69,971 star；Cline VS Code 市场 5,550,862 安装 | GitHub API、VS Code Marketplace API |
| OpenAI Python SDK 代理 | 未核实 | 3.26 依赖 httpx2≥2.12，httpx2 默认读环境变量，SDK 未覆盖 | pyproject、httpx2 文档 |
| iOS 后台时限 | 约 30 秒 [未核实] | 后台推送唤醒上限 30 秒（Apple 文档原文），didEnterBackground 5 秒，NSE 30 秒 | developer.apple.com |
| Secure Enclave 后量子 | 硬件覆盖未知 | 26.0 起全平台可用；Apple 只要求设备有 Secure Enclave，未列芯片 | developer.apple.com、WWDC25 314 |
| Azure DC2as_v5 | 12–13 / 63 [未核实] | Spot 0.018155、按需 0.086、Low Priority 0.0172 美元/小时 | Azure Retail Prices API |
| Azure ACI 机密容器 | 36 [未核实] | vCPU 0.04455/小时、内存 0.004895/GB·小时（标准版约 +10%） | Azure 官方价格页与 API |
| GCP n2d-standard-2 | 14–31 / 74 [未核实] | 按需 0.084492、Spot 0.043028 美元/小时；SEV-SNP 加价约 10% | cloud.google.com 价格页 |
| Tinfoil | 20 起 [未核实] | Containers 20/月 + 0.06/vCPU·小时 + 0.01/GB·小时；20/月是 Private Chat | tinfoil.sh/pricing |
| OVH | 423 起 [未核实] | Scale-a1 2026（EPYC 9005）708 美元/月起，带机密计算标签；High Grade 2026 不带 | ovhcloud.com 价目表 |
| Phala | 46 | tdx.small 0.06/小时（约 44/月） | phala.com/pricing |
| GitGuardian 单价 | 约 18 [未核实] | 付费档不公示 | gitguardian.com/pricing |
| Doppler | 年付 12 | 无年付价，已删 | doppler.com/pricing |
| Bitwarden、Infisical、AgentCore、Auth0 | — | 全部与官网一致（Auth0 附加件为基础价 +50%） | 各官网 |

### 15.3 仍未核实

- Claude Code 年化 25 亿美元（2026-02）与 Anthropic 整体年化数字：Anthropic 新闻室无原始帖。
- Codex「500 万周活」（2026-06）和「2,000 万活跃」（2026-08）：无一手出处；可核到的是 Reuters 2026-03-19 的「周活 200 万+」。
- 「Claude Code 权限弹窗 93% 被批准」：调研中标注为 Anthropic 披露，但 Managed Agents 博客等官方页面未见原文，来源待补。
- HCP Vault Dedicated 价格：官网只显示 IBM 版四档，不公示。
- Teleport 公开价格与 AWS Marketplace 最低合同；Entra Agent ID / Agent 365 价格：Microsoft 页面抓取超时。
- NSE 内存上限 24 MB：只有 Apple 开发者论坛来源。
- Goose 是否把 provider key 存 OS keyring。
- Auth0 Token Vault 是否只做 OAuth 不存 API key。
- Oasis ROFL / Marlin Oyster 的价格。
- 本文所有转化率、ARR 和成本均为假设。
