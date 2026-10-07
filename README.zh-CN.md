# KeyValet

**给 AI agent 一把代客钥匙，而不是你的万能钥匙。**

KeyValet 让 Claude Code、Cursor 等 AI agent 使用你的 API key 和 OAuth 账号，却看不到它们。每个凭证由你用 Touch ID 批准，由 KeyValet 代为调用，每次使用都有记录。

[官网](https://behalfai.github.io/KeyValet/) · [使用指南](docs/guide.zh-CN.md) · [安全模型](SECURITY.md) · [English](README.md)

## 安装

```sh
curl -fsSL https://behalfai.github.io/KeyValet/install.sh | sh
```

需要 macOS、Node.js 20+（来自 [nodejs.org](https://nodejs.org) 或 nvm）和 Xcode 命令行工具。安装时要输一次密码。会自动配置好 Claude Code；其他 MCP 客户端见[使用指南](docs/guide.zh-CN.md#安装)。

## 怎么用

直接对 agent 说：

> 用 KeyValet 的 openai 模板保存我的 OpenAI key。

会弹出一个原生对话框，由**你**输入 key，它不会经过对话。

> 用 KeyValet 列出我的 OpenAI 模型。

Touch ID 弹窗写明要用哪个凭证、做什么。KeyValet 代为请求，agent 只拿到结果。

> 通过 KeyValet 连接我的 GitHub 账号，建一个叫 demo 的仓库。

OAuth、refresh token、私钥都留在 KeyValet 里，agent 只拿到短期 token。

## 为什么用它

- **用而不见**：key 在 root 进程里注入，agent 拿到的是结果，不是秘密；
- **每个凭证一次 Touch ID**：弹窗写明是哪个凭证，以及 agent 自称的目的；
- **SDK 和流式输出**：本地网关让脚本和 SDK（`OPENAI_BASE_URL=…`）边收边输出，却拿不到真实 key；
- **各种认证都支持**：API key（约 50 个模板）、OAuth 2.0、Google 服务账号、GitHub App、JWT、TOTP、AWS STS；
- **审计日志**：每次解锁、读取、调用都连同目的一起记录。只在本机，不上云。

## 了解更多

- [使用指南](docs/guide.zh-CN.md)：概念、全部工具、模板、网关、命令行
- [安全模型](SECURITY.md)：能保证什么，不能保证什么
- [参与贡献](CONTRIBUTING.md)

卸载：`curl -fsSL https://behalfai.github.io/KeyValet/install.sh | sh -s -- --uninstall`

Apache-2.0 · 来自 [BehalfAI](https://github.com/BehalfAI)
