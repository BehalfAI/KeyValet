# KeyValet

**给 AI agent 一把代客钥匙，而不是你的万能钥匙。**

KeyValet 让 Claude Code、Cursor、Devin 等 AI agent 使用你的 API key 和 OAuth 账号，却看不到它们。每个凭证由你用 Touch ID 批准，由 KeyValet 代为调用，每次使用都有记录。

[官网](https://keyvalet.dev/) · [使用指南](site/guide.zh-CN.md) · [安全模型](SECURITY.md) · [English](README.md)

## 安装

```sh
curl -fsSL https://keyvalet.dev/install.sh | sh
```

需要 macOS、Rust 工具链（`cargo`，来自 [rustup.rs](https://rustup.rs)）和 Xcode 命令行工具。安装时要输一次密码。会自动配置好 Claude Code；检测到 Cursor 时安装器也会装好插件（`~/.cursor/plugins/local/keyvalet`，重启 Cursor 生效）；Devin CLI 用户执行 `devin plugins install KeyValet/KeyValet#devin-plugin` 安装插件；其他 MCP 客户端见[使用指南](site/guide.zh-CN.md#安装)。

## 怎么用

直接对 agent 说：

> /keyvalet:add openai

会弹出一个原生对话框，由**你**输入 key，它不会经过对话。如果你还是把 key 贴进了对话，Claude 会主动把它存进 KeyValet，而不是写进 `.env`。

> 用 KeyValet 列出我的 OpenAI 模型。

Touch ID 弹窗只需一句「使用 openai（本会话）」。KeyValet 代为请求，agent 只拿到结果。

会话弹窗显示凭证及这次授权实际放开的能力，由凭证记录决定（非 proxy_only 凭证总会提示「可读取明文（AI 可见）」）；逐次授权会补充真实操作及其参数。请求细节、用途与来源在审计日志中查看。

> 通过 KeyValet 连接我的 GitHub 账号，建一个叫 demo 的仓库。

OAuth、refresh token、私钥都留在 KeyValet 里，agent 只拿到短期 token。

## 为什么用它

- **用而不见**：key 在 root 进程里注入，agent 拿到的是结果，不是秘密；
- **你决定凭证授权的频率**：每次、每个凭证（默认）、每个会话，或记住几个小时；每个新会话仍需认证硬件密钥。在 Claude Code 或 Devin 里用 `/keyvalet:mode`（Cursor 里是 `/keyvalet-mode`）切换，放宽一定要你的指纹；
- **SDK 和流式输出**：本地网关让脚本和 SDK（`OPENAI_BASE_URL=…`）边收边输出，却拿不到真实 key；`per_use` 模式须逐次代理调用，不开放可复用网关；
- **各种认证都支持**：API key（约 50 个模板）、OAuth 2.0、Google 服务账号、GitHub App、JWT、TOTP、AWS STS；
- **自动维护**：在 Claude Code、Cursor 或 Devin 里，你给出的密钥会被自动存进来；要把密钥硬编码进文件或命令时，hook 会先警告或拦截；
- **密码处理**：原始工具结果不额外落盘；锁定即清理主动导出的临时文件。helper 将每次批准绑定到完整操作；
- **审计日志**：每次解锁、读取、调用都连同目的一起记录。只在本机，不上云。

**macOS 必须使用 Secure Enclave。**安装时直接初始化硬件 vault，或迁移已有文件密钥 vault；恢复口令在终端或本机隐藏输入框中设置。每个新会话都需要 Touch ID 或系统密码认证，`remember` 模式也一样。已移除文件密钥运行模式和软件回退。硬件私钥不可导出，但派生 AES 密钥会进入 helper 内存，被攻破的 root 也能自行发起派生，因此不能保证抵御被攻破的 root。Secure Enclave 无法使用时，可用 `keyvalet recovery-read` 以恢复口令只读访问。详见[设置与恢复说明](site/guide.zh-CN.md#secure-enclave-主密钥)。

## 了解更多

- [使用指南](site/guide.zh-CN.md)：概念、全部工具、模板、网关、命令行
- [安全模型](SECURITY.md)：能保证什么，不能保证什么
- [参与贡献](CONTRIBUTING.md) · [行为准则](CODE_OF_CONDUCT.md) · [治理](GOVERNANCE.md) · [商标政策](TRADEMARK.md)

卸载：`curl -fsSL https://keyvalet.dev/install.sh | sh -s -- --uninstall`

Apache-2.0 · 来自 [Simvito Limited](https://github.com/KeyValet)
