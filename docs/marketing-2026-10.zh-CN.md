# KeyValet 营销规划（阶段 0 到阶段 3）

- 日期：2026-10-08
- 配套：`docs/strategy-2026-10.zh-CN.md`（定位、定价、路线图）、`docs/product-2026-10.zh-CN.md`（用户旅程、指标）、`marketing/`（发布日文案：Show HN、X、Reddit、Product Hunt、目录提交、演示脚本）
- 约束：一个人，每周约 20% 时间做营销，现金预算每月不超过 200 美元；海外英文市场为主，中文为辅；主体 Simvito Limited，品牌 KeyValet，域名 keyvalet.dev

## 目录

1. 目标
2. 信息架构：说什么、对谁说、怎么说
3. 品牌
4. 内容引擎
5. 渠道与节奏
6. 官网与 SEO
7. 社区与开发者关系
8. 设计合作伙伴获取
9. 转化：从安装到付费
10. 预算与时间
11. 指标与复盘
12. 前 90 天日历
13. 风险与预案
- 附录 A：外联邮件模板
- 附录 B：HN / Reddit 评论应对要点
- 附录 C：内容 brief 模板

---

## 1. 目标

| 时间 | 目标 | 说明 |
| --- | --- | --- |
| 发布周（阶段 0） | Show HN 进首页；GitHub star 500；安装 500 | 衡量「问题是否被认可」 |
| 第 4 个月（阶段 1 末） | 累计安装 1 万；周活 2,000；有 ≥3 条凭据的周活占比 20% | 衡量「产品是否被用起来」 |
| 第 6 个月 | 10 家设计合作伙伴在用；3 家付费团队 | 衡量「团队是否愿意付钱」 |
| 第 8 个月（阶段 2 末） | 周活 4,000；D30 留存 25%；Team 收入开始 | 复盘是否继续全力投入 |
| 第 14 个月（阶段 3 末） | 周活 8,000；20 家付费团队 | 融资或继续自举的判断点 |

营销只服务两件事：让更多 Dev 装上并每周用，让 Lead 在触发点看到 Team。不追求泛流量。

---

## 2. 信息架构

### 2.1 一句话与三条支撑

- 主张：**Give your AI agents a valet key, not your master key.**（给 AI agent 一把代客钥匙，而不是你的万能钥匙。）
- 支撑一：agent 永远看不到密钥。代理注入，agent 只拿到响应。
- 支撑二：每次使用你用指纹批准，弹窗显示真实请求，不是一句「允许吗」。
- 支撑三：一个 vault，所有 agent：Claude Code、Codex、Cursor、Grok 共用同一套凭据、策略和审计。

### 2.2 按受众的版本

| 受众 | 第一句 | 证据 | 行动 |
| --- | --- | --- | --- |
| Dev | 你的 agent 现在就能读到你的 API key | s1ngularity、Comment and Control、GhostSplice 三个事故，各一句话 | `curl … | sh`，5 分钟 |
| Lead | 团队的 key 不该在 Slack 里传，CI 里不该有静态 secret | 共享与撤销、OIDC 换令牌、带用途的审计导出 | 开一个 Team，15 美元/席位 |
| 安全圈（内容受众） | 所有事故的共同前提是「agent 持有明文」 | 事故复盘与威胁模型 | star、转发、提 issue |

### 2.3 用词规则

- 说「agent 拿不到密钥」，不说「更安全」；说「弹窗显示真实请求」，不说「智能审批」。
- 不用恐吓式标题；每篇内容都给出可执行的修复，而不只是风险。
- 与 1Password 的关系永远写成互补：「1Password 管你的登录，KeyValet 管你的 API」。
- 「93% 的弹窗被批准」在找到一手来源前不使用。
- 不说「企业级」「零信任」这类空词；说具体机制。
- 诚实列出做不到的事（SECURITY.md 的「不防什么」），这是信任来源，不是弱点。

---

## 3. 品牌

- 名字：key + valet，玩的是汽车的「valet key」（代客钥匙：能开车，打不开后备箱）。官网首屏用一句话解释这个比喻，一次就够。
- 口号：主张那一句；中文版「给 AI agent 一把代客钥匙」。
- 视觉：沿用现有落地页的深绿主题；终端录屏统一字号与配色；不用机器人、锁、盾牌这类套路图标，用「钥匙」和「钥匙圈」。
- 语气：具体、简短、工程师对工程师；中英文一致。
- 署名：产品 KeyValet，公司 Simvito Limited；GitHub 组织发布前改为 `keyvalet`，README 和官网不再出现第三个名字。

---

## 4. 内容引擎

一个人做内容要靠可重复的系列，不靠灵感。

| 系列 | 频率 | 形式 | 目的 |
| --- | --- | --- | --- |
| 事故复盘「agent 把密钥弄丢的 N 种方式」 | 每月 1 篇，首批 5 篇：Nx s1ngularity、Comment and Control、GhostSplice、Claude Code CVE-2026-21852、Cursor DuneSlide | 1,200 字博客 + X 长帖；每篇末尾一段「KeyValet 怎么切断这条路径」 | 建立「这个人懂问题」的认知；SEO |
| 对比页 | 一次写好，季度更新 | vs 1Password、vs Infisical Agent Vault、vs 直接用 .env | 截住比价流量；诚实写对方更强的地方 |
| 「agent 配置里的密钥」研究 | 每季度 1 篇 | 复现 GitGuardian 的 MCP 配置扫描方法，发布数字 | 可被引用的原创数据，媒体与安全圈转发 |
| 模板页 | 随模板增长自动生成 | 每个服务一页：怎么用 Claude Code 安全地调 Stripe / GitHub / OpenAI | 长尾 SEO，每页都是一个入口 |
| Release notes | 每个版本，中英文 | GitHub Release + 官网 changelog + X 一条 | 让用户知道在活跃维护 |
| 60 秒演示视频 | 每个大版本一个 | 按 `marketing/demo-script.md`；README 顶部 GIF | 转化 |
| 深度技术文 | 每季度 1 篇 | 审批绑定真实请求的设计、HPKE 与 Secure Enclave、enclave 可复现构建 | 招人、收购方、安全圈 |

写作顺序：先写事故复盘第一篇（s1ngularity）和 vs 1Password 对比页，这两篇在发布周就要有。

---

## 5. 渠道与节奏

### 5.1 发布周（按 `marketing/launch-plan.md` 执行，补充如下）

| 时间 | 动作 | 文案 |
| --- | --- | --- |
| D-7 | 官网改版上线；README 顶部 GIF；GitHub 组织改名 `keyvalet`；占住 npm / crates / PyPI | — |
| D-3 | 预热：X 发「agent 读到你 .env 的三种方式」短帖，不提产品 | 事故复盘摘要 |
| D0 周二或周三美西 8–10 点 | Show HN | `marketing/show-hn.md` |
| D0 +1 小时 | X 长帖 | `marketing/x-thread.md` |
| D0 | r/ClaudeAI、r/mcp | `marketing/reddit.md` |
| D1 | r/selfhosted、r/macapps、r/cursor、r/ChatGPTCoding | 强调本地、开源、不上云 |
| D2–D3 | dev.to / Medium 长文「Why your AI agent shouldn't hold your API keys」 | 由 Show HN 正文扩写 |
| D3 起 | MCP 目录与 awesome 列表 | `marketing/directories.md` |
| D5 | 提交 Claude Code 官方插件市场、Codex plugins、cursor.directory | 插件描述统一 |
| D7 | Product Hunt | `marketing/product-hunt.md` |
| D0–D2 | 前两小时守评论；安全质疑引用 SECURITY.md 具体条目回答；当天修 bug 并回帖 | 附录 B |

### 5.2 常态渠道（按触达/投入比）

| 渠道 | 投入 | 做什么 |
| --- | --- | --- |
| Claude Code 官方插件市场 | 低 | 插件描述、截图、每版本更新；这是付费意愿最强的用户 |
| Codex plugins、cursor.directory → Cursor Marketplace | 低 | 同一套描述；Cursor 人工审核先排队 |
| MCP 目录（官方 Registry、PulseMCP、Glama、Smithery、mcp.so） | 很低 | 一次提交，版本更新时刷新 |
| X | 中 | 每周 2–3 条：事故、changelog、一条有用的安全提示；不发鸡汤 |
| Reddit | 中 | 只在有实质内容时发；回复别人关于 key 泄露的帖子时给方案，不硬广 |
| Hacker News | 低 | 大版本 Show HN；平时回答相关帖子 |
| dev.to / Medium | 低 | 博客同步 |
| YouTube / 播客 | 中 | 阶段 1 后：录 5 分钟演示；争取上 2–3 个 AI 开发播客 |
| Infisical、1Password 社区 | 低 | 以「存储后端集成」身份出现，发集成教程，不竖对手 |
| 安全社区 | 中 | OWASP Agentic 项目的映射文档、BSides 投稿、GitGuardian 一类博客的客座文章 |
| 中文渠道 | 低 | V2EX、即刻、少数派、掘金各发一次中文介绍；中文文档同步；不单独做中文运营 |

### 5.3 不做的

- 不买广告、不刷票、不找人点赞；不做 Discord（一个人维护不动，用 GitHub Discussions）；不做新闻稿；不做每日发帖。

---

## 6. 官网与 SEO

- 结构见产品文档 §14；首页首屏：主张、60 秒 GIF、安装命令、三条支撑。
- 关键词簇：`claude code api key security`、`cursor .env secrets`、`mcp server secrets`、`ai agent credentials`、`openai api key leak agent`、`codex secrets management`、`touch id api key`。每簇对应一篇内容或一个页面。
- 模板页标题模板：「How to let Claude Code use your {Service} API key without exposing it」。
- 对比页标题：「KeyValet vs 1Password for AI agents」「KeyValet vs Infisical Agent Vault」。
- 技术 SEO：Zola 静态站、sitemap、OpenGraph 图、每页一个明确的安装或阅读 CTA；中英文 hreflang。
- 不做落地页 A/B 测试；早期用访谈和录屏观察代替。

---

## 7. 社区与开发者关系

- GitHub Discussions 分类：Show and tell、Q&A、Templates、Ideas、Security（引导走 SECURITY.md）。
- 响应承诺：issue 和 discussion 48 小时内回复；安全报告 24 小时内确认。
- 贡献者感谢：每个版本的 release notes 点名模板贡献者；官网模板页标注贡献者。
- 每月一次 30 分钟公开「办公时间」直播或录播（阶段 1 起），回答问题并演示新功能。
- 不建群、不做私域。

---

## 8. 设计合作伙伴获取

- 目标：第 6 个月前 10 家，重度 Claude Code / Codex 团队，优先金融科技、开发者工具公司、有安全负责人的 20–200 人公司。
- 名单来源：Show HN 和 Reddit 评论里说「我们团队也有这个问题」的人；GitHub 上公开使用 Claude Code hooks 或 MCP 配置的组织；在 X 上讨论 agent 安全的工程负责人；安装后在 GitHub 提 issue 的团队账号。
- 方案：免费 6 个月 Team，每月一次 30 分钟访谈（提纲见产品文档附录 D），换反馈、logo 使用权和一篇案例。
- 外联：附录 A 的邮件模板，每周发 5 封，跟进一次即止。

---

## 9. 转化：从安装到付费

| 阶段 | 用户在哪 | 触达方式 |
| --- | --- | --- |
| 安装后 | 终端 | 安装脚本末尾一句：下一步 `/keyvalet:add openai`；不要邮箱 |
| 第一次代理调用后 | agent 对话 | agent 用一句话说明发生了什么；不弹升级提示 |
| 第 2 个成员要用同一 key、CI 要用 key、超官方 relay 额度、想导出审计 | 触发点 | 一次性提示「这需要 Team」，附一行价格和链接 |
| 控制台 | Web | 定价页与账单页；Stripe Checkout |
| 付费后 | 邮件（Team 有邮箱） | 欢迎邮件一封：三件事清单（邀请成员、共享第一条凭据、配置 CI）；之后只发账单与安全公告 |

不做邮件营销序列、不做弹窗促销、不设限时折扣。

---

## 10. 预算与时间

| 项目 | 金额 / 时间 |
| --- | --- |
| 域名（keyvalet.dev + 防御） | 约 150 美元/年 |
| 录屏与剪辑工具 | 约 10 美元/月 |
| Product Hunt、目录提交 | 0 |
| 播客与演讲 | 0，时间成本 |
| 时间 | 每周约 8 小时：2 小时写作、2 小时社区回复、2 小时渠道维护、2 小时外联 |

---

## 11. 指标与复盘

| 指标 | 来源 | 频率 |
| --- | --- | --- |
| 安装、周活、≥3 凭据周活占比、D30 | opt-in 遥测（见产品文档 §10） | 每周 |
| 官网到安装转化 | 官网统计（无 cookie 的服务端统计） | 每周 |
| 各渠道带来的安装 | 安装脚本的 `?src=` 参数（只记渠道，不记个人） | 每周 |
| star、fork、issue、模板 PR | GitHub | 每周 |
| 设计合作伙伴数、付费团队数、席位 | 控制台 | 每月 |

每月复盘一页：哪条内容带来了安装，哪个渠道该停；每季度决定下季度的系列。

---

## 12. 前 90 天日历

| 周 | 营销动作 |
| --- | --- |
| 1 | 官网改版；GIF；组织改名；占名；写事故复盘第一篇和 vs 1Password |
| 2 | 发布周（§5.1） |
| 3 | 回收评论反馈写成 FAQ；提交插件市场与目录；发 dev.to 长文 |
| 4 | Product Hunt；事故复盘第二篇（Comment and Control）；开始外联设计合作伙伴 |
| 5–6 | v0.2 release notes；模板页上线；中文渠道各发一次 |
| 7–8 | 事故复盘第三篇（GhostSplice）；录 5 分钟演示视频；争取第一个播客 |
| 9–10 | v0.3 策略引擎发布：博客「让审批弹窗值得看」；X 长帖 |
| 11–12 | 季度研究「agent 配置里的密钥」第一期；vs Infisical 对比页；复盘并定下季度计划 |

---

## 13. 风险与预案

| 风险 | 预案 |
| --- | --- |
| 被当成「又一个密码管理器」 | 首屏和 Show HN 第一段就写清楚和 1Password 的分工 |
| HN 上的安全质疑（root helper、MITM 代理、信任一个独立开发者） | 附录 B；每条引用 SECURITY.md 的具体段落；承认不防什么 |
| 「为什么不用 1Password / Infisical」 | 对比页链接；一句话差异 |
| 发布日出 bug | 当天修，回帖附提交链接 |
| 内容产出断档 | 系列化 + 提前存两篇 |
| 中国背景的信任折扣 | 官网与法律页写明 Simvito Limited、美国托管、开源可验证；不回避问题 |
| 被大厂功能覆盖的舆论 | 预先写好「我们和 X 的关系」短文，发生时当天发 |

---

## 附录 A：外联邮件模板（设计合作伙伴）

主题：Your team's agents are holding API keys in plaintext — want to fix that together?

正文（≤ 120 词）：
Hi {name}, I saw {where you saw them} and figured your team runs Claude Code / Codex daily. KeyValet is an open-source credential broker: agents use your API keys and OAuth accounts without ever seeing them, every use needs Touch ID and shows the real request, and shared team keys are encrypted per device. I'm looking for 10 design-partner teams: free Team plan for 6 months, one 30-minute call a month, your feedback shapes the roadmap. Repo: github.com/keyvalet/keyvalet. Would a 20-minute call next week work?

## 附录 B：HN / Reddit 评论应对要点

| 质疑 | 回答要点 |
| --- | --- |
| 「root helper 是攻击面」 | 为什么需要特权隔离；`verify_root_environment`；helper 不出网；代码在哪 |
| 「MITM 代理很危险」 | 代理 opt-in；会话 token；CA 私钥在 helper；只对会话绑定的 host 终止 TLS |
| 「用途是 agent 自己写的，没意义」 | 同意，所以弹窗显示真实请求并绑定摘要；用途只做展示和审计 |
| 「为什么不用 1Password」 | 它管登录，不签发 token、不代理 API、CLI 一次解锁整账号 12 小时；可以把 1Password 当后端 |
| 「为什么不用 Infisical」 | 开源版没有审批；没有 token 签发；可以把 Infisical 当后端 |
| 「一个人维护的安全工具我不敢用」 | 开源、可复现构建、签名发布、SECURITY.md 写明不防什么；接受这是真实顾虑 |
| 「hooks 能绕过」 | 同意，hook 是纵深防御；核心保证是 proxy_only |
| 「macOS only」 | Linux 在阶段 1；手机审批阶段 3 |

## 附录 C：内容 brief 模板

- 标题（≤ 70 字符）与目标关键词
- 读者是谁、读完做什么
- 一句话结论
- 证据（事故、数字、链接，全部一手来源）
- KeyValet 的对应机制（一段，不超过 120 字）
- CTA（安装 / 看对比页 / 提 issue）
- 发布渠道与改写版本（X 长帖、Reddit 正文）
