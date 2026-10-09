# KeyValet

**给你的 AI agent 一把「代客钥匙」，而不是你的万能钥匙。**

KeyValet 是一个运行在 macOS 本机的「AI agent 凭证代理」。Claude Code、Cursor、Codex 等 agent 可以通过 MCP **使用**你的 API key、OAuth 账号等凭证，但看不到它们。每个凭证都要你用 Touch ID 授权，每次使用都会连同目的一起记录下来。

[English](guide.md) · [安全模型](../SECURITY.md)

> **状态**：早期版本（0.1），仅支持 macOS。界面支持英文和简体中文，跟随 macOS 系统语言；也可以用 `KEYVALET_LANG=en|zh` 指定。

它能做的：

- 保存 API key、密码、token；支持 OAuth 2.0、Google 服务账号、GitHub App、JWT、TOTP、AWS STS 等协议。协议凭证的长期秘密永不离开 root 进程，agent 只能拿到短期 token；
- **代理调用**：由 KeyValet 把凭证注入请求并发出，agent 只拿到响应，全程看不到 key；
- **本地网关**：SDK、脚本这类不能走 MCP 的程序，可以把 base URL 指向 KeyValet 的会话网关。支持流式输出，程序拿不到真实 key；
- 默认**按凭证授权**：每个凭证单独按一次 Touch ID，弹窗写明凭证和授权范围；没有指纹时，系统认证框会改为要求输入登录密码；
- session 结束，授权随之失效；
- 每次读取、使用、修改凭证都必须说明目的，并记入审计日志，agent 可以查询；
- 没有你本人的 Touch ID 或登录密码，任何人（包括 AI agent 和你自己的其他进程）都读不到凭证。

## 安全模型

| 机制 | 作用 |
|---|---|
| 凭证库 `/var/db/keyvalet/` 属于 root:wheel，权限 0700 | 普通用户进程无法读取 |
| AES-256-GCM 加密；macOS 必须使用 Secure Enclave，旧 `master.key` 只用于迁移 | 新 vault 不生成文件密钥；迁移后删除旧密钥，每个新会话认证，恢复口令是独立解密路径 |
| sudoers 规则只允许免密运行 root helper 本身（参数必须完全一致） | 不再需要输入 sudo 密码，且这条规则不能用来运行其他任何东西 |
| root helper 启动后必须先通过 Touch ID（设备所有者认证）才提供服务 | agent 可以启动 helper，但无法替你按指纹；Touch ID 弹窗中显示解锁范围 |
| Touch ID 程序由 root helper 降权为你的用户身份运行；程序归 root 所有、强化运行时签名 | 指纹能送达用户会话；常规授权以退出码返回，硬件解锁通过匿名管道返回派生 AES 密钥 |
| 认证失败后的 30 秒冷却记录在 root-only 目录；同一时间只允许一个认证弹窗 | 即使绕过 MCP server 直接启动 helper，也无法反复弹窗 |
| 默认按凭证授权（`per_credential`） | 一次 Touch ID 只授权一个凭证，符合最小权限原则 |
| 覆盖、删除凭证，以及放宽授权模式，都由 **root helper** 弹窗确认 | 不依赖 MCP server；绕过 server 直接驱动 helper 也必须经你确认 |
| root helper 只通过 sudo 子进程管道通信 | 只有发起认证的那个 session 能用；MCP 进程退出后管道关闭，helper 随即退出 |
| 代码以 root-owned 形式安装到 `/usr/local/lib/keyvalet/` | agent 无法篡改将以 root 身份运行的代码；helper 启动时会自检，不满足条件就拒绝运行 |
| 覆盖、删除凭证会弹窗确认；写入时可省略 value，由原生输入框输入 | 防止误删；密钥可以不经过 LLM 上下文 |
| 认证失败或取消后冷却 30 秒 | 防止 agent 反复弹窗 |
| 审计日志 `/var/db/keyvalet/audit.log` | 记录每次操作（不记录凭证值） |
| 协议凭证的长期秘密只在 root helper 内使用 | refresh token、client secret、私钥、TOTP 种子、AWS secret key 永不返回给 agent，agent 只拿到短期 token |
| 协议端点必须是 https，HTTP 请求禁止重定向 | 秘密不会被发往明文或被重定向的地址 |
| 修改已有协议凭证的配置一律弹窗确认；端点或 client 变化时还必须重新输入 secret | agent 无法把已保存的 secret 改发到恶意地址（只改 scope 时可沿用） |
| 协议凭证带随机版本号，异步刷新写回前校验 | 刷新期间配置被替换时拒绝写入，防止 refresh token 落入新（恶意）配置 |
| 从文件导入秘密前弹窗确认文件路径，确认后才读取 | agent 不能借本工具读取任意文件 |
| 弹窗中只显示经过严格校验的值；输入 secret 的弹窗带「这不是登录密码」的固定警示 | 防止 agent 用诱导文字骗取登录密码 |
| 读取/使用/修改凭证和解锁都必须提供 purpose，写入审计日志（含会话 ID） | 每次使用都有据可查；`credential_audit_log` 可查询 |
| Google 服务账号取 token 时只能请求设置时配置的 scope 子集 | agent 不能擅自扩大权限 |
| root helper 读取远端响应时边读边限制大小 | 恶意端点无法耗尽 root 进程内存 |

**边界（请知悉）：**

- 解锁后，agent 能使用本会话获准的凭证；`per_session` 和 `remember` 模式覆盖全部凭证。只在你信任的会话里解锁。
- 读取到的凭证值会进入该 agent 的上下文，因此也会发给模型服务商。
- 本工具防不住已经以你的用户身份运行、并且你主动配合的恶意程序。例如，你被诱导按下了它触发的 Touch ID。所以要看清弹窗中的凭证和授权范围，以及逐次授权或明文读取时显示的操作；来源目录和完整用途可在审计中查看。
- `purpose` 是 agent 的自述；真实操作由 root helper 根据完整请求生成。`per_use` 授权绑定完整操作和凭证配置，一次授权只能执行一次匹配的操作；其他模式按相应的凭证授权范围生效。

## 安装


需要 Rust 工具链（`cargo`，来自 [rustup.rs](https://rustup.rs)）构建二进制，以及 Swift 编译器（`xcode-select --install`）编译 Secure Enclave helper。

安装会写入 `/etc/sudoers.d/keyvalet`，只允许你免密运行凭证库 helper。写入前后都会用 `visudo` 校验，卸载时会删除。

```sh
curl -fsSL https://keyvalet.dev/install.sh | sh
```

这条命令会下载最新版本（没有正式版本时用 `main` 分支），检查运行环境，运行安装程序（要输一次密码）；如果装了 Claude Code，还会自动注册 MCP。

- 升级：重跑同一条命令，凭证库不受影响；
- 卸载：`curl -fsSL https://keyvalet.dev/install.sh | sh -s -- --uninstall`；
- 从源码安装：克隆仓库后运行 `./scripts/install.sh`；
- 没有 Claude Code 的话，手动注册：`claude mcp add keyvalet --scope user -- /usr/local/lib/keyvalet/bin/kv-mcp`。Cursor 用户：安装器会把插件复制到 `~/.cursor/plugins/local/keyvalet`（重启 Cursor 生效），含 MCP server、密钥检测 hook 和 `/keyvalet-*` 命令；其他客户端加一个命令为 `/usr/local/lib/keyvalet/bin/kv-mcp` 的 stdio server。

## 协议凭证

| 种类 (`kind`) | 设置 | 使用 | agent 拿到的 |
|---|---|---|---|
| `oauth2` | `credential_oauth_login` | `credential_access_token` | access token（自动刷新） |
| `google_service_account` | `credential_setup_google_service_account` | `credential_access_token` | access token（1 小时） |
| `github_app` | `credential_setup_github_app` | `credential_access_token` | installation token（1 小时，可收窄仓库/权限） |
| `jwt` | `credential_setup_jwt` | `credential_access_token` | 按模板签发的 JWT |
| `totp` | `credential_setup_totp` | `credential_totp_code` | 当前验证码 |
| `aws` | `credential_setup_aws` | `credential_aws_credentials` | STS 临时凭证（可 AssumeRole、可关联 TOTP 自动 MFA） |

### OAuth 2.0

三种流程：

- `authorization_code`（默认）：打开浏览器，本地回环地址接收回调，使用 PKCE + state；
- `device_code`：弹窗显示验证码（同时复制到剪贴板）并打开验证页面；
- `client_credentials`：机器对机器，无需用户交互。

内置预设：`google`、`github`、`microsoft`（支持 `tenant`）、`outlook`（Outlook / Microsoft 365 邮箱 IMAP）、`outlook_graph`（Outlook 邮箱，走 Microsoft Graph）、`gitlab`、`dropbox`。其他服务可以用 `issuer`（OIDC 自动发现，如 Okta、Auth0、Keycloak、自建 GitLab），或手动指定 `authorization_url` / `token_url`。

client secret 由用户在弹窗输入（只会发往 token 端点所在的域名，弹窗中会显示）。重新授权时只需传 `name`，会沿用已保存的配置。

各服务商需要注意的地方：

- **Google**：浏览器流程使用 *Desktop app* 类型的 client；设备码流程使用 *TVs and Limited Input devices* 类型的 client。应用处于 Testing 状态时，refresh token 7 天后失效，需要重新授权。
- **GitHub**：OAuth App 的 callback URL 填 `http://127.0.0.1/callback`（端口任意）；设备码流程需在 App 设置中启用 Device Flow。
- **Microsoft**：在 App registration 中添加 *Mobile and desktop* 平台，redirect URI 填 `http://localhost`。
- **Dropbox**：要求精确的 redirect URI，需在 App Console 中登记并用 `redirect_uri` 参数固定端口。

### 邮箱 IMAP（XOAUTH2）

Outlook / Microsoft 365 和 Gmail 的 IMAP/SMTP 都使用 OAuth 的 XOAUTH2 认证：

1. 授权：`credential_oauth_login`，`provider` 为 `outlook` 或 `google`。Gmail 的 scope 要包含 `https://mail.google.com/`。
2. 取认证字符串：`credential_access_token` 传 `format: "xoauth2"`，返回 SASL XOAUTH2 字符串，用于 `AUTHENTICATE XOAUTH2`。
3. 验证：`credential_imap_test` 实际登录 IMAP，以只读方式打开收件箱。失败时会解码服务器返回的错误，并给出排查建议。

Outlook 需要注意：

- App registration 添加「移动和桌面应用程序」平台，并登记 redirect URI，如 `http://localhost:47902/callback`（授权时用 `redirect_uri` 参数指定）。这类平台属于公共客户端，授权时传 `public_client: true`。
- 个人账号（outlook.com / hotmail / live / msn）：`tenant` 用 `consumers` 或 `common`，不能用目录（租户）ID；应用的「受支持的帐户类型」必须包含个人 Microsoft 帐户。
- IMAP 的 scope 是 `https://outlook.office.com/IMAP.AccessAsUser.All`（预设已包含）。发信需要追加 `https://outlook.office.com/SMTP.Send`。

> ⚠️ **个人 Outlook 账号的 IMAP OAuth 目前不可用**：自 2024 年 12 月起，微软服务端存在一个已知问题。OAuth 认证会成功，但随后报 `User is authenticated but not connected`，微软尚未修复（[讨论帖](https://learn.microsoft.com/en-us/answers/questions/5673167/imap-oauth-regression-user-is-authenticated-but-no)）。个人邮箱请改用 Microsoft Graph，见下一节。

### 邮箱 Microsoft Graph（推荐用于个人 Outlook 账号）

```
credential_oauth_login {
  name: "my-outlook-graph", provider: "outlook_graph",
  client_id: "<应用 ID>", public_client: true, tenant: "consumers",
  redirect_uri: "http://localhost:47902/callback"
}
```

- 默认只申请只读权限 `Mail.Read`；需要发信时追加 `Mail.Send`；
- 用 `credential_graph_mail_test` 验证：它会只读查看收件箱的邮件数和最近几封邮件；
- 用 `credential_access_token` 取到的 token 调用 `https://graph.microsoft.com/v1.0/me/messages` 等接口；
- Graph 和 IMAP 的 token 不能混用，所以要单独建一个凭证。

### 私钥类文件

服务账号 JSON、GitHub App `.pem`、`.p8` 等通过文件路径参数导入。MCP 进程读取文件后直接交给 root helper，内容不进入 AI 上下文。导入后建议删除原文件。

## 数据模型

- **凭证类型** (`type`)：如 `api_key`、`password`、`token`、`ssh_key`，带可选说明；
- **凭证** (`type` + `name`)：如 `api_key/openai`，包含 `value`（秘密）、`description`，以及 `attributes`（非敏感信息，如 username、url）。
  协议凭证另有 `kind`，以及 `config`（非敏感配置）、`secrets`（长期秘密）、`state`（缓存的短期 token）。协议凭证默认放在与 kind 同名的类型下。

类型和名称都不区分大小写，统一存成小写。

**写入流程**：先检查凭证类型是否存在，不存在就先创建类型，再写入值。这两步在同一把写锁内、同一次落盘中完成。

## 模板库

模板库分三层，优先级从高到低：

| 来源 | 内容 |
|---|---|
| 内置通用模板 | `bearer`、`header`、`query`、`basic`，适用于任何 HTTP API |
| 自带模板库 `templates/catalog.json` | 约 50 个常用服务，如 OpenAI、Anthropic、Gemini、Mistral、Groq、DeepSeek、GitHub、GitLab、Cloudflare、Vercel、Stripe、Slack、Notion、Jira、Linear、Twilio、SendGrid 等；按各服务官方 API 文档整理，Apache-2.0 授权 |
| 可选：本地 n8n 模板库 `templates/n8n-catalog.json` | 本地有 n8n 源码时，可以运行 `npm run templates:import -- /path/to/n8n` 生成，额外提供约 400 个服务。**仅供你自己使用**：n8n 采用 Sustainable Use License，不允许再分发，所以这个文件已加入 `.gitignore`，不随项目提供 |

每个模板描述：

- 需要哪些字段，哪些是秘密；
- 怎样把凭证注入请求（请求头、查询参数或 Basic 认证）；
- 用哪个接口验证凭证是否有效；
- OAuth2 服务的授权地址、token 地址和默认 scope。

```
credential_templates { query: "openai" }                                # 搜索
credential_set { template: "openai", name: "main", purpose: "..." }     # 按模板保存：秘密字段逐个弹窗输入，
                                                                       # 自动配置代理调用和验证，并立即验证一次
credential_oauth_login { provider: "gmailOAuth2", client_id: "...", name: "..." }  # 生成了 n8n 模板库时，其中的 OAuth2 模板也可作为 provider
```

修改自带模板库：编辑 `scripts/build-catalog.mjs`，然后运行 `npm run templates:build`。欢迎提交修正和新增，请附上官方文档链接。

## 代理调用（推荐）

`credential_http_request` 由 root helper 把凭证注入 HTTP 请求并发出，只把响应返回给 agent。**agent 全程看不到 API key 或 token**。

| 机制 | 说明 |
|---|---|
| 域名白名单 | 每个凭证都有 `allowed_hosts`，只允许 https、默认端口；只接受域名，不接受 IP 和 localhost |
| 不跟随重定向 | 3xx 原样返回，防止凭证被带到别的域名 |
| 响应脱敏 | 响应体和响应头中出现的秘密（含 Base64、URL 编码等形式），以及注入的整个认证值，都替换为 `[REDACTED]`；响应头只返回白名单内的 |
| 支持的凭证 | static 凭证（模板或手动注入规则）；oauth2、google_service_account、github_app、jwt 凭证，自动注入 access token |
| 只能代理调用 | 设置 `proxy_only` 后，`credential_get` 不再返回原值 |
| root helper 弹窗确认 | 新增域名、修改注入规则、关闭「只能代理调用」、删除代理配置时，由 **root helper 自己**以你的用户身份弹窗确认。即使绕过 MCP server 直接驱动 helper，也绕不过这一步 |

没有模板的 API，可以用通用模板，或用 `credential_configure_http` 手动设置：

```
credential_configure_http {
  name: "my-api", allowed_hosts: ["api.example.com"],
  inject: { headers: { "X-Api-Key": "{{value}}" } },
  test: { url: "https://api.example.com/me" }, purpose: "..."
}
```

### 流式响应与本地网关

- `credential_http_request` 会完整接收流式（SSE）响应，并在 `stream.text` 里返回从大模型增量拼出的完整文本。支持 OpenAI（Chat Completions 和 Responses）、Anthropic、Gemini 的格式。
- `credential_gateway` 为程序开通本会话专属的本地网关：`http://127.0.0.1:<端口>/<域名>/<路径>` → `https://<域名>/<路径>`。
  - 网关会去掉程序自己带的认证头，注入真实凭证；只发往白名单域名，不跟随重定向；
  - 响应边转发边脱敏：只扣留「可能是秘密开头」的那几个字节，所以流式输出几乎没有延迟；
  - 令牌按凭证、按会话随机生成；只接受访问 `127.0.0.1` / `localhost` 的请求（防 DNS 重绑定）；每次请求都会记入审计；
  - 对常见模板，会直接给出 SDK 要设置的环境变量，比如 `OPENAI_BASE_URL`。

```sh
# agent 调用 credential_gateway 拿到地址后：
OPENAI_BASE_URL=http://127.0.0.1:52011/<令牌>/api.openai.com/v1 OPENAI_API_KEY=keyvalet python summarize.py
```

需要把秘密落地成本地文件才能用的工具（典型例子：SSH 私钥配合 `ssh -i`），用 `credential_export_file`——只把文件路径还给 agent，内容不经过 AI 上下文，会话结束自动删除。
两者都用不了、必须拿到原值本身的场景（比如数据库密码），仍然用 `credential_get` 读原值。

## 授权模式：多久按一次 Touch ID

| 模式 | 什么时候按 Touch ID |
|---|---|
| `per_use` | 每次使用凭证都按 |
| `per_credential`（**默认**） | 每个会话中，每个凭证按一次；本会话新建的凭证自动获得授权 |
| `per_session` | 每个会话按一次，之后可用全部凭证 |
| `remember` | 凭证授权记住 `remember_hours` 小时（默认 8；`0` 表示永久）；Secure Enclave 每个新会话仍需认证 |

会话解锁后，查看凭证列表和审计日志无需额外的凭证授权；搜索模板无需开启 vault 会话。每个新会话都要认证解锁 Secure Enclave，`remember` 有效期也不能跳过。

**在 Claude Code、Cursor 或 Devin 里用 `/` 命令修改**（Claude Code：一行安装会自动装好插件；Cursor：安装器复制到 `~/.cursor/plugins/local/`，命令写作 `/keyvalet-mode` 等；Devin CLI：`devin plugins install KeyValet/KeyValet#devin-plugin`）：

```text
/keyvalet:mode remember 8      # 凭证授权记住 8 小时；每个新会话仍需认证
/keyvalet:mode per-use         # 最严格：每次都按
/keyvalet:status               # 当前模式、记住到何时、本会话已授权的凭证
/keyvalet:lock                 # 立即锁定，并清除“记住”状态
/keyvalet:audit 20             # 最近的使用记录
/keyvalet:add stripe           # 在私密弹窗里保存新的密钥
```

保证安全的规则：

- 模式保存在 root 专属的 `/var/db/keyvalet/settings.json`。**放宽**（更宽松的模式，或更长的记住时长）必须按 **Touch ID** 确认，而不是一个能被脚本点击的确认框，所以 agent 无法自己放宽。收紧立即生效。修改对当前会话也立即生效。
- 客户端只能**收严**：比如给 Codex 注册时加上 `KEYVALET_GRANT_MODE=per_use`，最终生效的是全局设置和客户端设置中更严格的那个。
- `remember` 模式下，已解锁的会话在有效期内使用凭证无需继续认证。每个新会话仍需认证硬件密钥。想提前结束，用 `/keyvalet:lock`。
- 在终端里：`keyvalet grant-mode remember 8`、`keyvalet grant-mode forget`。

## 让 agent 主动维护凭证库（Claude Code / Cursor / Devin 插件）

装好插件后，agent 会替你维护凭证库：

- **在对话里贴了密钥**（“这是我的 Stripe key：sk_live_…”），agent 会用对应模板把它存进 KeyValet，之后通过代理或网关使用，而不是写进 `.env`。`UserPromptSubmit` hook 能识别约 25 种密钥格式（OpenAI、Anthropic、GitHub、AWS、Stripe、Slack、Google 等），只把掩码后的预览告诉 agent。
- **更推荐 `/keyvalet:add openai`**：在 KeyValet 的私密弹窗里输入密钥，它不会经过对话，也不会进入模型服务商的日志。
- **要把明文密钥写进文件或命令行时**，`PreToolUse` hook 会介入并提示 agent 改用 KeyValet——Claude Code 里是先请你确认，Cursor 和 Devin 里（hook 协议没有「询问」）会直接拦截这次调用。hook 只做格式识别，不保存已返回密码的明文或匹配缓存；没有可识别格式的任意字符串可能无法识别。
- 发现 `.env` 或配置文件里的密钥时，agent 会提议迁移到 KeyValet；已存的密钥失效（401/403）时，会提议替换。

Cursor 有官方插件（`cursor-plugin/`，安装器复制到 `~/.cursor/plugins/local/`）：相同的命令（写作 `/keyvalet-add` 等）、`sessionStart`/`preToolUse`/`beforeShellExecution`/`beforeMCPExecution` hook 和 `keyvalet` MCP server。Devin CLI 也有同款插件（`devin plugins install KeyValet/KeyValet#devin-plugin`）：相同的 `/keyvalet:*` 命令、`UserPromptSubmit`/`PreToolUse` hook 和 `keyvalet` MCP server，都在 `devin-plugin/` 目录里。

如需关闭这些 hook，在 agent 的运行环境中设置 `KEYVALET_HOOKS=off`。

## 目的（purpose）与审计

- 读取凭证（`credential_get`）、获取 token、TOTP 码或 AWS 临时凭证、测试邮箱、写入、修改、删除凭证，以及解锁（`credential_unlock`），都**必须**传 `purpose`；
- 会话授权弹窗显示凭证和这次授权实际放开的能力，由 root helper 根据凭证记录生成，例如「使用 openai（本会话）/ 可读取明文凭证（AI 可见）」；proxy_only 凭证显示「仅代理请求（AI 看不到明文）」。会话解锁只显示凭证库的授权范围。弹窗不显示 purpose，来源目录和完整用途放在审计日志中；
- 会话授权允许在该会话中使用凭证，不限于某条 HTTP 请求。逐次授权显示真实操作及其绑定的全部参数：`credential_http_request` 显示 method、host、path、查询参数、agent 设置的请求头和请求体摘要，获取令牌显示 scopes / 仓库 / 权限，AWS 显示有效期；均由 root helper 根据完整操作生成，agent 的展示文案不能替换。不支持的方法、不在允许列表的域名、与凭证种类不符的操作在弹窗前就被拒绝；
- 每条操作都写入审计日志，记录时间、会话 ID、操作、凭证、种类、目的、结果、来源目录，**不含任何凭证值**；
- root helper 会再检查一次：缺少 `purpose` 的读取或修改请求一律拒绝；
- 用 `credential_audit_log` 查询，可按本会话（`this_session_only`）、凭证、操作、起始时间过滤。

## MCP 工具

| 工具 | 说明 |
|---|---|
| `credential_status` | 查看是否已解锁、会话 ID、授权模式、本会话已授权的凭证（不触发认证） |
| `credential_settings` | 查看或修改授权范围模式（`per_credential` / `all`） |
| `credential_audit_log` | 查询操作记录：解锁、读取、取 token、修改、删除，包含时间、会话、凭证、目的、结果 |
| `credential_unlock` / `credential_lock` | 手动解锁（Touch ID），可同时授权指定凭证 / 立即锁定 |
| `credential_list_types` | 列出类型及数量 |
| `credential_create_type` | 创建类型（通常不需要，`credential_set` 会自动创建） |
| `credential_list` | 列出凭证（不含值） |
| `credential_get` | 读取 static 凭证值，模板凭证含所有秘密字段；设为 `proxy_only` 的凭证和协议凭证只返回配置和状态 |
| `credential_export_file` | 把 static 凭证的原始值写入只有你可读的私有临时文件，只返回路径；用于 SSH 私钥等必须是本地文件的场景 |
| `credential_set` | 保存 static 凭证。推荐传 `template`，秘密字段弹窗输入，并自动配置代理；不传模板时，`value` 留空会弹窗，`value_file` 从文件导入（可加 `delete_source_file: true` 在保存后弹窗确认删除原文件）；覆盖需 `overwrite=true` 并经你确认 |
| `credential_delete` / `credential_delete_type` | 删除（需你确认） |
| `credential_oauth_login` | 配置并完成 OAuth 授权 |
| `credential_access_token` | 获取 oauth2 / 服务账号 / GitHub App / JWT 的短期 token |
| `credential_setup_google_service_account` / `credential_setup_github_app` / `credential_setup_jwt` / `credential_setup_totp` / `credential_setup_aws` | 设置各类协议凭证 |
| `credential_totp_code` | 获取 TOTP 验证码 |
| `credential_aws_credentials` | 获取 AWS 临时凭证 |
| `credential_imap_test` | 用 OAuth 凭证以 XOAUTH2 登录 IMAP，验证邮箱授权 |
| `credential_templates` | 搜索凭证模板 |
| `credential_http_request` | 代理调用：注入凭证后发出 HTTP 请求，只返回响应；支持流式（SSE）响应 |
| `credential_gateway` | 为 SDK 或命令行开通本地网关，支持流式输出 |
| `credential_test` | 用验证请求检查凭证是否有效 |
| `credential_configure_http` | 设置或修改代理配置：允许的域名、注入规则、验证请求、只能代理调用 |
| `credential_graph_mail_test` | 用 OAuth 凭证通过 Microsoft Graph 只读查看邮件夹，验证邮箱授权 |

可选环境变量 `CREDENTIAL_MCP_SESSION_TTL_MINUTES`：解锁多少分钟后自动锁定。默认不限，即整个 session 有效。

## 终端 CLI

```sh
keyvalet set api_key openai --desc "个人账号" --attr url=https://platform.openai.com
pbpaste | keyvalet set token github          # 从剪贴板读入
keyvalet list
keyvalet get api_key openai
keyvalet get oauth2 google-work                # 协议凭证：输出完整配置和秘密（备份/迁移用）
keyvalet audit 20
keyvalet grant-mode all                       # 切换授权范围（per-credential / all）
```

每条命令都会以 `sudo -k` 运行，也就是每次都要输入密码。访问 vault 的命令还需要系统认证来解锁 Secure Enclave 密钥。

### Secure Enclave 主密钥

Secure Enclave 是 macOS 唯一支持的 vault 模式（Apple silicon 或支持的 T2 Mac）。安装时运行 `setup-enclave`：新 vault 直接使用硬件保护；旧文件密钥 vault 在隐藏输入恢复口令后迁移。硬件不可用或取消设置时，正常操作不可用，不提供软件回退。通过 CryptoKit 保存设备绑定的加密密钥表示，使用 `userPresence` ACL：macOS 在硬件密钥操作时校验 Touch ID 或设备密码；没有明文硬件私钥文件，也无需创建 Keychain 项目。

从已登录 Mac 的图形会话运行。无图形会话 / SSH 上下文可能无法认证；硬件失败不会启用软件回退。本机验证使用 Apple silicon 与 macOS 26.5.1；T2 硬件、未录入指纹时的密码回退仍需分别做设备验证。

```sh
keyvalet protection             # provider、hardware_required、recovery_configured、legacy_key_present
keyvalet enclave-test           # 两次系统认证，临时密钥，不修改 vault
keyvalet setup-enclave          # 初始化或迁移；隐藏输入两次恢复口令、两次系统认证
keyvalet migrate-to-enclave     # setup-enclave 的别名
keyvalet rotate-recovery        # 更换硬件密钥、凭证库密钥与恢复口令，并启用设备绑定
keyvalet recovery-check         # 验证恢复口令；不用硬件、不修改、不输出值
keyvalet recovery-read list     # 应急：用恢复口令只读访问（types / list / get）
```

设置独立的强恢复口令，建议至少六个随机选择的单词，离线保管。允许 12–1024 字节，但长度不代表强度。无终端时用本机隐藏输入框，口令经私有管道直接交给 root CLI，不进入 agent、命令行参数、环境变量或文件。恢复包裹使用 Argon2id（64 MiB、三轮、单并行度）和 AES-256-GCM。**拥有 vault 密文和恢复口令的人无需原 Mac 或 Touch ID 就能解密**；弱口令可被离线猜测。

安装器在替换程序与迁移前结束已有 KeyValet helper / MCP 会话；手动运行设置时需先关闭这些会话。迁移先验证新硬件密钥能在独立子进程中重新载入，再更换 AES 主密钥，把新密文与密钥元数据一起原子提交，最后删除 `master.key`。`vault.migration-backup.enc` 是迁移时的凭证快照，已使用新密钥和恢复口令加密；已有备份不会覆盖。若迁移失败后留下不完整备份，而 `protection` 仍显示 `migration_required`，保留完好的 `vault.enc` 和 `master.key`，移走不完整备份后重试。`uninitialized` 表示未完成设置，这两种状态都不能正常使用 vault。崩溃后若显示 `secure_enclave` 且 `legacy_key_present: true`，运行 `keyvalet finish-enclave-migration`，认证后清理遗留文件密钥；再次设置也会在认证后执行该清理。旧版 KeyValet 无法读取迁移后的 vault。

用管理员权限备份**最新**的 `/var/db/keyvalet/vault.enc`，其中包括加密密钥表示和恢复包裹。每份副本都只能让 root 读取，或放进加密归档。本版本设置或轮换过的 vault 带设备绑定：密钥还依赖 `/var/db/keyvalet/device-binding.key`，该文件只有 root 可读且不进 Time Machine，所以单有 `vault.enc` 副本，一次获批的系统弹窗也无法解密。不要把 `device-binding.key` 和 vault 放在同一份备份里。若 `keyvalet protection` 显示 `device_binding: false`，运行一次 `keyvalet rotate-recovery`。在同一台 Mac 上恢复 `vault.enc` 时，只要绑定文件还在就能直接使用；否则用 `keyvalet recover-vault`。设置可另外备份。换机时安装 KeyValet，将 `vault.enc` 恢复到 root 所有、`0700` 的 vault 目录，文件为 root 所有、`0600`，关闭所有会话后执行 `keyvalet recover-vault`。隐藏输入恢复口令，在新 Mac 创建并验证新硬件密钥，重新加密 vault。需要回到迁移时快照时，把 `vault.migration-backup.enc` 替代 `vault.enc` 再恢复；其中只有迁移当时的数据。设备访问能力与恢复口令同时丢失时无法恢复。

设置完成后运行一次 `keyvalet recovery-check`，之后不确定口令时也可以再运行：它在 root CLI 中用恢复口令解密，只显示凭证条数。若本机 Secure Enclave 无法使用（例如系统更新后认证失败），vault 不会回退到文件密钥。此时可用 `keyvalet recovery-read types|list|get <type> <name>` 以恢复口令读取凭证：写入会被拒绝，helper 与 AI 会话无法使用该模式，每次使用都记入审计。要恢复正常使用，在 Secure Enclave 正常的 Mac 上运行 `keyvalet recover-vault`。恢复口令可能泄露时运行 `keyvalet rotate-recovery`：硬件解锁后同时更换硬件密钥、凭证库密钥和口令，旧口令不能再打开当前凭证库（旧备份仍可用旧口令打开）。

硬件私钥不可导出；复制当前 vault 文件后，旧文件密钥也无法解密新密文。但派生 AES 密钥和凭证明文仍会进入普通进程内存。加密密钥表示绑定的是这台 Mac 的 Secure Enclave，而不是 KeyValet：被攻破的 root 无需等待解锁，可以自己发起派生、使用任意认证文案，获批一次即取得 AES 主密钥（设备绑定挡不住 root，因为 root 能读取绑定文件）；也可以在获准解锁期间截获密钥或明文。截获 AES 主密钥后，轮换前仍可离线解密。出现意料之外的系统认证弹窗时要警惕。历史 `master.key` 副本加历史 vault 备份仍可解密，删除文件不保证抹除 APFS 快照或 SSD 残留。详见 [SECURITY.md](../SECURITY.md)。

## 开发

```sh
cd rust
cargo test --workspace --locked   # 在临时目录中以普通用户身份测试凭证库与各协议（本地模拟服务端 + RFC/AWS 官方测试向量），不需要 root
```

### 获取与使用密码的安全边界

`per_use` 授权由 root helper 根据完整操作生成提示并计算绑定，包含操作类型、参数和已保存的凭证配置。更换操作、参数或验证配置，以及重复使用批准，都会拒绝。该模式不开放可复用网关；有效授权模式变更会撤销现有网关令牌。

原始工具结果不额外落盘。主动导出的密码文件和网关环境文件使用私有目录及 0600 权限，拒绝符号链接；锁定、超时或 helper 退出即删除。异常退出后的文件会在下次 MCP 启动时清理。已经返回给调用方的密码无法撤回。OAuth 错误只返回状态及固定错误代码，不返回可能包含长期秘密的上游诊断。
