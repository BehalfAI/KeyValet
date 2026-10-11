+++
title = "安全模型"
description = "KeyValet 的安全模型：保护什么、信任边界、能保证什么——以及防不住什么的完整清单。"
+++

本页是 [SECURITY.md](https://github.com/KeyValet/KeyValet/blob/main/SECURITY.md) 的可读摘要，原文是权威文档。一个要以 root 运行代码的凭证工具应该把边界讲清楚——所以下面「防不住什么」是完整清单，不是挑好听的一半。

## 保护什么

- 静态秘密：API key、密码、token，以及附加的秘密字段。
- 协议凭证的长期秘密：OAuth client secret 与 refresh token、Google service account 私钥、GitHub App 私钥、JWT 签名密钥、TOTP 种子、AWS secret access key。
- 凭证库主密钥，以及审计日志和设置的完整性。

## 保护状态

安装时和 `keyvalet status --summary` 会展示实际密钥方案、硬件证据和本机 TPM 检测结果。
`credential_status` 在锁定时也能读取这些公开元数据，不触发认证或秘密访问。
Secure Enclave 不是 TPM；Hello 证明不可用或 Linux TPM 实现无法确认时，明确标为 unknown。
Linux 的 polkit 批准本身不是 TPM PIN 或启动状态策略。三种系统的完整分类见
[密钥保护与 TPM 状态](https://github.com/KeyValet/KeyValet/blob/main/docs/key-protection.zh-CN.md)。

## 信任边界

AI agent / MCP 客户端是*半可信*的：它可能被提示注入，可以调用 KeyValet 的 MCP 服务，也能以你的用户身份执行任意命令。KeyValet 的 MCP 服务只是便利层——**安全检查从不只依赖它**。每个安全决策都由 root helper（或 launchd 守护进程 `dev.keyvalet.helper`）做出，它在空闲时不持有凭证库密钥。Touch ID 和 Secure Enclave 的工作由每用户代理 `dev.keyvalet.agent` 完成，守护进程只有在校验了对端 uid 和代码签名（`dev.keyvalet.touchid`、team `PWCRJPY7YC`、精确安装路径）后才接受它——同用户的其他进程无法冒充它来替你批准。

## KeyValet 能保证什么

前提是 macOS 和安装文件没有被攻破：

1. **没有设备主人认证就没有秘密。** 凭证库（`/var/db/keyvalet`，只有 root 可读，AES-256-GCM）在服务任何请求前都要求 Touch ID 或登录密码认证。
2. **节奏由你定，也只有你能放宽。** 授权模式——逐次、按凭证（默认）、按会话、记住——存在只有 root 能改的设置里；放宽需要你的 Touch ID，agent 自己改不了。
3. **协议凭证的长期秘密不出 root 进程。** agent 拿到的只是派生的短期材料或代理后的响应。
4. **仅代理凭证永不返回明文**——不通过读取、token、错误信息，也（尽力）不通过代理响应。
5. **秘密只去你允许的地方。** 仅 HTTPS 443 端口、精确/通配域名白名单——不允许 IP、不允许 localhost、不跟随跳转。
6. **本地网关有令牌门控、只监听回环。** 每条路由需要一个绑定单一凭证和当前会话的随机令牌；逐次模式下不存在可复用网关。
7. **暴露面只能经你同意才能扩大，由 root 强制。** 新增域名、放宽规则、覆盖或删除都要 root 进程弹出确认框。绕过 MCP 服务并不能绕过这些检查。
8. **你亲手输入的秘密不经过 agent**——它们在原生对话框里输入，或从你确认过的文件导入。
9. **每次使用都有记录。** 解锁、授权、读取、取 token、代理调用和配置修改都写入只有 root 能读的审计日志；秘密值从不写入。
10. **弹窗和授权绑定由 root helper 自己生成**，依据完整操作——客户端给的提示文案不能替代。逐次弹窗显示真实请求：方法、域名、路径、查询参数、agent 请求头，以及已知 API 按固定业务字段白名单生成的请求体行，绝不显示任意请求体内容。逐次模式下一次批准只能执行那一次操作。
11. **随会话失效。** agent 会话结束，授权即结束。
12. **macOS 上要求 Secure Enclave。** 凭证库密钥每次会话由 Secure Enclave P-256 密钥派生，并混入只有 root 能读的设备绑定秘密，所以复制的 vault 文件加一次批准的弹窗也不够；Argon2id 恢复口令是离线途径。

## KeyValet 防不住什么

- **你批准的授权在范围内被滥用**——会话持有授权后，恶意或被注入的 agent 可以在授权范围内使用它。`proxy_only`、收窄 `allowed_hosts`、受限 token 和逐次模式可以缩小它。
- **网关令牌在锁定、会话退出或授权模式变更前可重复使用。**
- **`remember` 模式用弹窗换暴露面**——窗口期内不再有提示。
- **自述的 purpose 不做核验**——它是 agent 的声明，只记录（不显示在弹窗），不与实际行为对照。
- **你亲手批准的恶意弹窗**——以你用户身份运行的恶意程序也能触发同样的 Touch ID 弹窗；你批准了，授权就给出去。
- **超出脱敏能力的上游回显**——允许的域名若以脱敏器不认识的方式回显秘密，仍可能泄露。只允许你信任的域名。
- **root 或 macOS 被攻破**、物理攻击、或构建产物被替换。
- **任何时刻的 root 失陷**——不止解锁期间：它可以自己发起 Secure Enclave 派生，或在合法解锁时截获派生出的密钥。
- **恢复口令泄露**——`vault.enc` 密文加口令即可离线解密。Argon2id 拖慢猜测，救不了弱口令。
- **历史副本与回滚**——旧文件密钥加旧 vault 副本仍可解密；APFS 快照和备份不会被安全抹除。
- **交付出去之后的秘密**——`credential_get` 返回的值和短期 token 会留在 agent 上下文里。
- **拒绝服务**——agent 可以刷屏请求（弹窗有限频，认证失败后有 30 秒冷却）。

## 发布完整性

发布包由 GitHub Actions 从打 tag 的提交构建。工作流构建的包中每个二进制都用 Simvito Limited Developer ID 签名（team `PWCRJPY7YC`，hardened runtime，带时间戳）；安装器在启用守护进程模式前会校验签名——以及同一份发布里的 `SHA256SUMS`。源码构建路径（Intel Mac，或没有发布产物的版本）对下载的源码没有签名或校验——在意的话请自行审计发布或源码。

## 报告漏洞

请**不要**开公开 issue。使用 GitHub 的[私密漏洞报告](https://github.com/KeyValet/KeyValet/security/advisories/new)（Security 页 → "Report a vulnerability"），附复现步骤和受影响版本。报告会在几天内得到确认。

完整的权威模型——包括设计说明和确切的密码学构造——见 [SECURITY.md](https://github.com/KeyValet/KeyValet/blob/main/SECURITY.md)。
