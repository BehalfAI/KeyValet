+++
title = "KeyValet 对比 1Password（面向 AI agent）"
description = "1Password 管你的登录，KeyValet 管 agent 的 API 调用。一份详细、诚实的对比——包括 1Password 领先的地方。"
+++

**一句话：1Password 管你的登录，KeyValet 管 agent 的 API 调用。** 两者其实不算竞争——大多数 KeyValet 用户应该继续用 1Password 做它擅长的事，一个直接读取 `op://` 引用的 1Password 存储后端也在我们的路线图上。

这一页把这条界线讲具体，因为「互补」是每个厂商都会说、却几乎从不给出细节的话。以下是细节。

## 1Password 今天为 agent 提供了什么

截至 2026 年 10 月，1Password 面向 agent 的功能是真实的，但很窄：

- **1Password for Claude**（beta，2026 年 7 月）：当 Claude 需要在 Chrome 里登录网站时，1Password 弹出生物识别框，写明凭证和自述理由，然后替你填表单——Claude 看不到密码。需要 Mac、Claude Desktop 和 1Password 浏览器扩展，不覆盖 Claude Code。
- **Agentic Autofill**（early access，经由 Browserbase）：同样的思路用于浏览器自动化 agent——每次自动填充批准一次，agent 拿到填好的表单，而不是密码。
- **Environments MCP**（Codex、Cursor）：让 agent 看到 1Password Environment 里变量的*名字*，永远看不到值。程序自己在运行时仍从本地的 `.env` 式文件读真实值。
- **op CLI**：一次 Touch ID 解锁授权的是**整个账户**，绑定该终端会话，最长 12 小时。在这个窗口内，这个 shell 里运行的任何东西——包括某个被投毒依赖的 postinstall 脚本——都能用 `op read` 读出凭证库里的任何凭证。
- **SSH Agent**：1Password 最接近 KeyValet 模型的功能。可以要求按 key、按应用或按请求批准——但弹窗显示的是*哪个进程*在申请，而不是*它要用这把 key 做什么*，也没有 purpose 字段。
- **Credential Broker**（企业版，预览）：通过 OIDC 向 CI 工作负载签发静态凭证库秘密。仅企业版，而且签发的仍是同一枚长期凭证，不是短期的。

这些不是在贬低 1Password——浏览器登录是它解决得很好的硬问题，也不是 KeyValet 要解决的问题。

## 差距在哪里

| | 1Password | KeyValet |
|---|---|---|
| **为谁而建** | 人登录网站 | agent 调用 API |
| **批准粒度** | 浏览器：按次填充；CLI：按*账户*，最长 12 小时 | 按凭证、按调用或按会话——你选 |
| **agent 能看到 key 吗** | 浏览器流程里不能；已解锁 shell 里的 `op read`，或 Environments 注入的 `.env`，能 | 不能——`credential_http_request` 代为调用，只返回响应 |
| **弹窗里显示*为什么* / *什么*** | 只有 Claude 浏览器 beta；就我们能确认的而言，没有记入可查询的审计轨迹 | 弹窗显示的是*什么*——真实请求——而不是 agent 的自述理由；自述目的与每次使用一起记入审计日志 |
| **弹窗里显示*什么请求*** | 不显示 | 逐次模式下显示——方法、域名、路径，来自真实的出站调用 |
| **签发短期 token**（OAuth refresh、JWT、GitHub App installation token、AWS STS） | 不能——分发的是长期静态秘密和 TOTP 码 | 能——OAuth refresh、GitHub App installation token、Google service account token、签名 JWT、TOTP 码、AWS STS；agent 只持有短期结果 |
| **阻止秘密被写进 shell 命令或文件** | 不能 | 能——Claude Code、Codex、Cursor、Grok、Devin 的 hook 适配器在它落地前识别 |
| **运行在哪里** | 共享桌面会话或终端里的账户解锁 | 本地 macOS 凭证库；按 MCP 会话授权 |

规律是：1Password 的 agent 功能是它核心工作的延伸——一个人认证后打开某样东西。KeyValet 的工作从那之后才开
始：不是人，而是 *agent* 在反复、自动地调用，此时「批准一次、信任 12 小时」恰恰是错误的形态，因为下一次什么时候用这把 key 是 agent——不是你——在决定。

## 1Password 领先的地方，实话实说

- **生态和分发。** 1Password 是 Anthropic、OpenAI 和 Cursor 的官方集成伙伴。如果你只需要「Claude 能在浏览器里登录我的账户」，它已经在那，而且支持得很好。
- **浏览器登录，没有之一。** Agentic Autofill 和 1Password for Claude 解决的是一个真实的、不同的问题——替人填表单——比我们能做的任何东西都好，因为那不是 KeyValet 做的事。
- **多设备同步和团队凭证库。** 1Password 的跨设备同步和共享凭证库体验比 KeyValet 今天提供的任何东西都成熟得多（我们的团队功能还在开发中——见路线图）。
- **SSH agent 的批准粒度**确实做得好，精神上接近 KeyValet 对 API 调用做的事。

## 两个都用

如果你已经是 1Password 用户，这里没有要你离开的理由。1Password 存储后端在计划中：上线后你把一个凭证指向 `op://vault/item/field` 引用，KeyValet 实时读取——在 1Password 里轮换这个值，KeyValet 自动拿到新值，没有需要同步的副本。在那之前，1Password 继续处理它擅长的（你的登录、团队的共享凭证库）；KeyValet 处理 1Password 自己的文档说还在路线图上的部分——为「不是人往浏览器里敲密码」的场景做短期、按目的限定、逐次调用的授权。

---

**资料来源：**[1Password for Claude 新闻稿](https://1password.com/press/2026/july/1password-for-claude) · [1Password Agentic Autofill](https://www.1password.dev/agentic-autofill) · [1Password Environments MCP](https://1password.com/blog/the-1password-environments-mcp-server-is-now-on-cursor-marketplace) · [op CLI 安全模型](https://www.1password.dev/cli/app-integration-security/) · [1Password SSH Agent 安全](https://www.1password.dev/ssh/agent/security/) · [1Password Credential Broker](https://1password.com/blog/1password-credential-broker-public-preview) · [1Password Activity Log](https://support.1password.com/activity-log/)

*发现本页内容自我们核对后有变化？[开个 issue](https://github.com/KeyValet/KeyValet/issues/new)——1Password 的 agent 功能更新很快，我们宁愿被纠正也不想过时。*
