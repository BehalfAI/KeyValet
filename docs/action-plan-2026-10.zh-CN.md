# KeyValet 行动指南：从今天到第 24 个月

- 日期：2026-10-08
- 决策更新：2026-10-09，平台支持与密钥保护顺序已确认，见[产品 §1.4](product-2026-10.zh-CN.md#14-平台支持与密钥保护)及架构 §8.0；macOS 首版、安装整合与本机真实 vault 迁移已完成，其他平台按后续阶段推进。
- 进度更新：2026-10-10，阶段 0 的代码项与站点 / 文案项全部收口（v0.1.0、v0.2.0 已发布，0.2.1 已就绪待打 tag），剩余项都是需要人操作的发布动作，见「2026-10-10 阶段 0 收口」一节；第一次月度复盘见 `review-2026-10.zh-CN.md`。
- 用法：这是五份规划文档（战略、产品、架构、营销、开源）的执行版。每一条都写明做什么、产出是什么、怎么算完成。按顺序做，遇到门槛先复盘再往下走。
- 时间假设：一个人，每周约 40 小时投入 KeyValet（其余时间自由职业），其中约 8 小时营销与社区。
- 章节索引：战略 S、产品 P、架构 A、营销 M、开源 O，例如「A §7.6」指架构文档第 7.6 节。
- ⚠️ **2026-10-09 事故记录**：六份规划文档（本文件及战略、架构、产品、开源、商标检索）曾被当成普通文件放进 `docs/`，而 `docs/` 同时是 GitHub Pages 的发布根目录——结果财务假设、商业决策理由等内部内容被公开发布在 keyvalet.dev 上，从 push 到发现大约数十分钟。已把官网文件（`index.html`、`guide.md`、`guide.zh-CN.md`、`install.sh`、`CNAME`、`favicon.svg`）迁到新的 `site/` 目录，Pages 发布源改成 `site/`，内部规划文档留在 `docs/` 不再对外发布；已验证修复后不再可公开访问。教训：任何新建目录先确认它是不是某个发布流程的根目录，别事后才查。

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
| 0.1 | `代码` 提交五份规划文档和本文 | ✅ 已完成 | `git log` 可见 |
| 0.2 | `运营` 商标检索：USPTO、WIPO Global Brand Database、UKIPO、CNIPA、香港知识产权署，第 9 类与第 42 类，查 "KeyValet" 与 "Key Valet" | ✅ 初步检索已完成：`docs/trademark-check.md`——没查到软件/SaaS 类的注册商标冲突；"Key Valet" 这个名字被几家不相关的小公司在用（新泽西一家做汽车防盗硬件的 Key Valet Inc.、卡塔尔一家代客泊车公司），均非软件领域，WIPO 库被验证码挡住没能直接查。**这只是网络搜索式的初筛，不是专业检索**，真要正式注册商标或大规模投广告前建议花钱找律师或检索服务做一次正式查询 | 初筛无直接冲突，可以继续用这个名字；正式注册前再做一次专业检索 |
| 0.3 | `运营` ~~注册 keyvalet.dev~~ **已完成**；防御性注册 .ai / .io / .app（可选，非阻塞）；DNS 托管；提交 HSTS 预加载；开 DNSSEC；设 CAA | ✅ 域名与 DNS 已完成（Cloudflare 托管，10-09 从 GitHub Pages 切到 Cloudflare Pages，见下方记录）；10-10 新站点的 `_headers` 已发 `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`；**👤 还要做**：hstspreload.org 提交、Cloudflare 开 DNSSEC（并在注册商填 DS 记录）、加 CAA（`0 issue "letsencrypt.org"` + `0 issue "pki.goog"`——Cloudflare Pages 证书用这两家，开之前在 Cloudflare SSL 页确认） | `https://keyvalet.dev` 返回官网——已验证，证书有效 |
| 0.4 | `运营` GitHub 组织 `KeyValet` **已创建**；仓库 **已转移**到 `KeyValet/KeyValet`；本机 remote、README、`package.json`、两个插件 manifest、`install.sh`、`index.html` 里的地址 **已更新为 keyvalet.dev**（这几个文件后来又从 `docs/` 迁到了 `site/`，见下方 2026-10-09 的记录） | 旧链接自动重定向 | `curl -fsSL https://keyvalet.dev/install.sh` 可用（待 DNS 生效） |
| 0.5 | `运营` 占住 npm、crates.io、PyPI 的 `keyvalet` 包名（发布占位版本） | — | ⏸ 2026-10-09 决定暂不占位：三个包名目前都还没人用，优先级不高，先放着；想占的时候 npm 已登录，crates.io/PyPI 还需单独登录 |
| 0.6 | `运营` D-U-N-S **已完成**；Apple Developer Program 组织账号 **已完成**（10-10 起 release 全部用 Simvito Limited 的 Developer ID `PWCRJPY7YC` 签名）；开 Stripe 账号（待办——Antom 已配置好但技术选型复盘后改用 Stripe 作为 Team 自助订阅的主要收款渠道，理由见下方说明；Antom 保留配置，以后若做 APAC 场景可用） | 两个账号 | Stripe 可创建 Product；Apple 账号可建 App ID |
| 0.7 | `开源` 开启 GitHub Private Vulnerability Reporting；加 `CODE_OF_CONDUCT.md`（Contributor Covenant 2.1）；加 issue 模板 4 种与 PR 模板（O 附录 D）；`CONTRIBUTING.md` 加 DCO 与 Rust 规范 | ✅ 10-10 核对：PVR 已开启（API `private-vulnerability-reporting.enabled = true`）；`CODE_OF_CONDUCT.md`、`.github/ISSUE_TEMPLATE/`（bug / feature / template_request + config.yml，3 种而不是 4 种）、`PULL_REQUEST_TEMPLATE.md`、`CONTRIBUTING.md`（含 DCO）都在仓库里 | 新建 issue 时出现模板选择 |
| 0.8 | `开源` 写 `GOVERNANCE.md`（O 附录 A）与商标政策页（O 附录 B） | ✅ `GOVERNANCE.md`、`TRADEMARK.md` 在仓库根目录，README 第 51 行已链接 | 从 README 链接到它们 |
| 0.9 | `市场` 写事故复盘第一篇（Nx s1ngularity）和 vs 1Password 对比页初稿 | ✅ `marketing/blog-s1ngularity.md`（含配套 X 长帖）、`marketing/compare-1password.md`——`site/` 还没搭，先放 `marketing/`，等 1.5 做完官网改版再搬进 `site/content/` | 1,057 字 / 886 字，均 < 1,200；来源见各文末 |

---

## 2. 阶段 0（第 1–4 周）：发布

目标：v0.1 发布进 HN 首页；500 star；500 安装；每一次弹窗都显示真实请求。

### 第 1 周

| # | 任务 | 产出 | 完成标准 |
| --- | --- | --- | --- |
| 1.1 | `代码` 操作与请求摘要绑定（A §7.2） | ✅ 2026-10-09 安全修订：`kv-ipc::operation_digest` 递归排序 object key，摘要包含操作名及全部执行参数（只排除不影响执行的 purpose）；root helper 另加入凭证版本、已保存的 HTTP / 验证配置。客户端不能指定受信摘要；旧 HTTP-only `request_digest` 仅保留兼容测试 | 修改操作、请求字段或 root 配置都会使单次批准失效；`kv-ipc` 与 `kv-core` 回归测试通过 |
| 1.2 | `代码` Touch ID 显示凭证、真实操作与 agent 自述用途、来源（P 附录 A） | ⏳ root helper 已直接从完整待授权操作生成 method / host / path，验证工具从 root 保存的配置生成；明文读取等也显示具体动作。`kv-core::prompt` 将用途和来源标为 agent 自述并清除换行、控制符、双向文本控制；风险分级仍待策略引擎 | 伪造客户端展示提示不能替换 root 的请求行；用途显示为非验证声明 |
| 1.3 | `代码` 批准绑定与一次性消费（A §7.3） | ✅ 2026-10-09 安全修订：`SessionAuth::one_shot` 保存 root 计算的完整操作摘要，执行时复核，匹配或不匹配都会消费；非 HTTP 操作同样绑定。MCP 不再缓存批准；并发请求串行请求授权。其他授权模式保持已声明的凭证 / 会话范围。IPC 升至 v4，旧客户端不被默默接受 | 替换 HTTP 请求、跨操作明文读取、重放批准及更改已保存验证配置均被拒绝；攻击回归测试通过 |
| 1.4 | `代码` 把 `rust/` 工作区提交进 git，CI 跑 `cargo test` 与 clippy | ✅ 早就做了：10-07 那次「Rewrite KeyValet in Rust」commit 已经把整个工作区提交，CI 的 `rust` job（`.github/workflows/test.yml`）本来就在跑 `fmt --check`/`clippy -D warnings`/`build`/`test` 四件套 | CI 绿 |
| 1.5 | `市场` 官网改版：Zola 项目 `site/`，首页（主张、GIF 占位、安装命令、三条支撑）、定价页、对比页、安全页；GitHub Pages 源切到 Actions 构建 | ✅ 10-10 完成（提交后 `pages` 工作流首次用 Zola 构建并部署，需看一眼 Actions 是否绿）：`site/` 重建为 Zola 0.23.6 多页站，`/` 与 `/zh-CN/` 两棵独立语言树（hreflang 需要独立 URL，所以放弃了原来单页里的 JS 切换），页面：首页（主张 + 泊车票 + 三条支撑 + 安装命令，`extra.demo_gif = true` 时显示 `/demo.gif`）、`/pricing/`（Free / Team $15 / Team+手机 $18 + FAQ，Team 明确标「计划中」）、`/security/`（SECURITY.md 的可读摘要，「不防什么」全列）、`/compare/1password/`（`marketing/compare-1password.md` 搬上站并修掉了把 1Password 后端等未做功能写成现在时的句子）、`/guide/`、`/blog/s1ngularity/`、404；sitemap、atom、OG 图（`static/og.png` 1280×640，也用作 GitHub 社交预览）、`_headers`（HSTS preload + 严格 CSP）、robots。无 JS、无 Google Fonts（系统字体栈）。CI：`pages.yml` 下载固定 SHA-256 的 Zola，`zola build` 后部署 `site/public`。首页措辞按真实默认模式写：默认按凭证授权，逐次模式才绑定每次请求。原记录：部分完成，且走了不同的路：10-09 把原来混在 `docs/` 里的站点文件（`index.html`/`guide.md`/`install.sh` 等）迁到新的 `site/` 目录——这是因为发现 `docs/` 同时是发布根目录又放着内部规划文档，财务假设等内容被公开发布了，必须马上拆开（见上方事故记录）。顺带把发布方式从 GitHub Pages 换成了 Cloudflare Pages（CI 用 `cloudflare/wrangler-action`，一次性项目创建和域名绑定已手动做完）。**还没做的**：Zola 本身、定价页、对比页（内容已经在 `marketing/compare-1password.md` 写好，还没搬上站）、安全页、GIF、三条支撑的首屏文案——现在 `site/` 里还是旧的 `index.html`，不是这一项原本设想的改版 | ✅ 本地 `zola build` 9 页 0 警告、内链 0 断、CSP grep 0 命中、6 页 headless Chrome 截图人工看过；线上生效以提交后 `pages` 工作流为准 |
| 1.6 | `代码` macOS Secure Enclave 本地主密钥保护：先做不接触真实 vault 的可行性 spike，再迁移旧 vault 并停用文件密钥模式；保护状态、禁止降级、换机与恢复一并落地（P §1.4、A §8.0） | ✅ 首版与安装整合完成：CryptoKit 加密表示 + `userPresence`；`MasterKeyProvider`、保护状态、初始化 / 迁移、Argon2id 恢复与崩溃清理 CLI；原子提交与旧会话失效；macOS 只支持硬件 vault，安装器隐藏收集恢复口令后完成设置。永久 Keychain 项目受 entitlement 限制，因此采用不创建 Keychain 项目的加密表示；详见 A §8.0 | 本机 arm64 / macOS 26.5.1，普通用户跨进程派生通过；root 在用户 GUI 会话下临时 vault 迁移、再次解锁、恢复通过；全工作区测试通过。真实 vault 迁移与安装验收记录另附。T2、无指纹密码回退、跨 OS 更新仍待发布矩阵验证；文案明确派生 AES 密钥进入 helper 内存的边界 |

### 2026-10-09 本机安装与迁移验收

- 在本机 macOS 26.5.1 / arm64 上安装最新 Rust release 二进制；`kv-touchid` 的 ad-hoc hardened-runtime 签名验证通过，其余四个安装产物与本机构建一致。
- `/var/db/keyvalet` 的真实 vault 已完成主密钥轮换与 Secure Enclave 迁移，生成 `vault.migration-backup.enc` 加密快照；旧 `master.key` 和旧安装目录已删除。恢复口令由用户在本机隐藏输入框中输入两次；长度无效或不一致时可重输，口令不经过代理输出。
- 最新 root helper 通过一次新的硬件认证开启会话，成功读取 **6 条凭证**的列表，仅输出数量；`sessionInfo.vault_protection` 确认 `provider: secure_enclave`、`hardware_required: true`、`recovery_configured: true`、`legacy_key_present: false`。没有读取或输出凭证值。
- `cargo fmt --all -- --check`、全工作区 Clippy（`-D warnings`）、locked build、locked test 均通过：279 项测试通过，1 项交互硬件测试按默认规则跳过；独立临时 vault 的硬件迁移、解锁与恢复此前已验证。真实 vault 本次只做迁移和新会话解锁，T2、无指纹密码回退、跨机 / 跨 OS 更新仍待发布矩阵验证。

### 2026-10-09 获取与使用凭证的安全修复验收

- 已修复四类问题：原始结果的隐式明文缓存、信任客户端授权展示 / 摘要造成的操作替换、可复用网关绕过每次批准、上游 OAuth 诊断泄漏秘密至响应或审计。具体边界见 [SECURITY.md](../SECURITY.md)。
- 原始结果不额外落盘；主动导出采用私有目录描述符、排他创建与拒绝符号链接。锁定、超时、helper 断开即删除文件并阻止迟到写入；后续启动清理旧缓存及已退出进程留下的文件。会话代次隔离旧 reader / timer，避免旧会话撤销新会话。
- `per_use` 必须提供完整操作，由 root 生成提示与绑定；不支持可复用网关，改用逐次 `credential_http_request`。有效授权模式变更撤销已发网关令牌。OAuth 错误只返回状态和固定代码，响应与审计写入前再次脱敏。
- 全工作区 fmt、Clippy（warnings 为错误）、locked build、locked test 通过：280 个测试通过、0 失败、1 个交互硬件测试按规则跳过；另有 3 个 Node 回退 hook 安全回归测试通过。认证弹窗超时后子进程会终止，其回归测试一并通过。
- 本机安装最新 release，安装权限和 hardened-runtime 签名验证通过；当前 Codex 会话原生 MCP 已重载。通过原生 `credential_test` 验证 Cloudflare 保存的只读 GET，返回 HTTP 200；密钥未返回给 agent。6 条凭证完整保留，保护状态为 `secure_enclave`、强制硬件、恢复已配置、旧文件密钥不存在；验收后已锁定，私有临时目录为空。
- 此次部署为本机安装与当前会话 MCP 更新；未提交、推送或发布公共版本。已返回调用方的秘密无法追溯撤回，任意格式 hook 检测和已批准期间的 root 内存攻击边界仍按安全文档说明。

### 2026-10-09 平台方案复核与 macOS 应急恢复

- 安全文档的修正：SE 加密表示只绑定设备，不绑定 KeyValet 签名（Apple DTS 2026-05 更正），被攻破的 root 可随时自行发起派生；Apple 不支持在 `launchd` daemon 中使用 SE，Mac helper 迁到 Unix socket 前须把 SE 操作移到每用户 LaunchAgent。见 A §8.0、§13、§20。
- 代码：新增 `keyvalet recovery-check` 与 `recovery-read <types|list|get>`，SE 不可用时用恢复口令只读访问；vault 句柄只读，写入与删除旧密钥均被拒绝，审计标记 `recovery_passphrase_read_only`，helper 不接受该模式。新增 2 项 vault 测试。
- 规划文档修正：Nitro 证明文档 `public_key` 改为 RSA（KMS `Recipient` 只支持 `RSAES_OAEP_SHA_256`），HPKE P-256 公钥放入 `user_data`；新增 KMS key policy 模板（去掉账号级 `kms:*`、缺少证明即 Deny、禁止 `ReEncrypt*`）；enclave 不再以 relay 时间为准；c7g.large 只能给 enclave 1 个 vCPU。Linux TPM 无用户在场、Windows Hello 为 RSA-2048 且 session 0 无法弹窗，见 A §8.1、§11。
- fmt、Clippy（`-D warnings`）、locked build、locked test 通过：283 项测试通过、0 失败、1 项交互硬件测试按规则跳过。新 CLI 命令须以 root 身份运行，尚未在真实 vault 上验证。

### 2026-10-09 安全复审修复

- 授权弹窗：会话授权的说明改由 root 根据凭证记录生成，非 proxy_only 的静态凭证一律提示「可读取明文（AI 可见）」，客户端填写或省略的 operation 不再影响弹窗；与凭证种类不符的操作、不支持的方法和不在允许列表的 URL 在弹窗前拒绝。逐次授权显示查询参数、请求头、请求体摘要、scopes / 权限和 AWS 有效期。
- 逐次授权：同一凭证可并存多个待用批准（每凭证 4 个、每会话 16 个），并发请求不再互相覆盖；设备码登录的轮询批准在 30 分钟内可复用。终端或其他会话收紧授权模式后，正在运行的会话在下一次请求时生效并撤销网关令牌；撤销会中断正在进行的网关流式响应（以错误结束，而不是正常结束）。
- vault：新增设备绑定（root-only `device-binding.key` 参与 HKDF，不进 Time Machine），vault 副本单靠一次获批弹窗无法解密；新增 `keyvalet rotate-recovery` 同时更换硬件密钥、主密钥与恢复口令。`setup-enclave` 在提示输入口令前先检查旧文件密钥，`recover-vault` 先检查恢复信息；会话检查会等待正在退出的 helper 最多 5 秒；恢复口令和硬件派生密钥改用固定的清零缓冲区读取，`kv-touchid` 直接写管道。
- MCP 与导出文件：`/keyvalet:lock` 即使清除 remember 失败也先锁定；stdin 关闭时同步完成锁定与清理；导出文件按 PID 加进程启动时间标记，PID 复用不再导致残留；旧命名格式的导出会被清理；HOME 为符号链接时可用；过长的文件名会被截短。
- 其他：AWS STS 错误只返回状态与格式合法的错误码（也修掉了多字节截断导致的 panic）；purpose 去除 bidi / 零宽 / C1 控制字符；MCP 工具说明不再声称弹窗显示 purpose。
- fmt、Clippy（`-D warnings`）、locked test 通过：299 项测试通过、0 失败、1 项交互硬件测试按规则跳过。真实 vault 仍为未绑定状态，需在终端运行 `keyvalet rotate-recovery` 启用设备绑定；新二进制尚未安装。

### 2026-10-10 阶段 0 收口

- 发布：v0.1.0 与 v0.2.0 正式发布（Developer ID 签名，launchd daemon 模式）；本机已装 v0.2.0，daemon 与 agent 运行中。release 工作流随后加入 notarization，尚未在真实 release 中执行。
- 代码（本次提交）：2.1 root 侧请求体白名单摘要；4.1 `scan` 导入套用模板为 `proxy_only` + `keyvalet get` 修复；2.4 Codex 适配器按官方契约重写（`codex-tool`、deny-only、`apply_patch` 覆盖、旧 hooks.json 自动升级）；版本号 bump 到 0.2.1。全工作区 `cargo fmt --check` / `clippy -D warnings` / `build --locked` / `test --locked` 通过：342 项通过、0 失败、2 项按规则忽略。
- 站点：1.5 Zola 双语多页站重建（首页 / 定价 / 对比 / 安全 / 指南 / 博客 / 404），HSTS preload 头与严格 CSP，OG 图；`pages.yml` 改为 Zola 构建后部署 `site/public`。
- 内容：2.6 文案全部按 v0.2 重写 + FAQ；4.6 Comment and Control 复盘草稿；4.8 中文 release notes 与 v0.2.1 notes；第一次月度复盘 `docs/review-2026-10.zh-CN.md`。
- 文档修正：SECURITY.md 第 10 条和 AGENTS.md / SECURITY.md 的 notarization 描述；`docs/runtimes.md` Codex 行。
- 剩给人做的（agent 做不了）：录 60 秒 GIF；上传社交预览图；GitHub 仓库 homepage 字段改成 keyvalet.dev；notarization `workflow_dispatch` 干跑后打 `v0.2.1` tag；在干净 Mac 计时 J1；`keyvalet protection` 确认 `device_binding: true`（否则 `rotate-recovery`）；重跑 `install.sh` 让本机 Codex hook 升级并在 Codex `/hooks` 里信任；HSTS 预加载 / DNSSEC / CAA；Stripe；发布周全部发帖、目录与插件市场提交、外联。

### 第 2 周

| # | 任务 | 产出 | 完成标准 |
| --- | --- | --- | --- |
| 2.1 | `代码` 模板 `summarize` 规则：先写 OpenAI、Anthropic、GitHub、Stripe、AWS、Slack 六个（P §8） | ✅ 10-10 完成，但白名单**放在 Rust 里（`kv-core/src/summarize.rs`）而不是模板 JSON 里**：`templates/catalog.json` 是非特权 MCP server 也读的文件，不在 root 的信任链里，root 不能拿它决定弹窗显示什么。按 host 后缀匹配六家 API，只取请求体**顶层**的白名单字段（OpenAI/Anthropic 的 `model`、`max_tokens`、`stream`；Stripe 的 `amount`、`currency`、`price`…；Slack 的 `channel`、`text`；GitHub 的 `name`、`ref`、`private`…；AWS 的 `Action` 和 `x-amz-target` 头），JSON 和 form-urlencoded 都支持，每个值截到 40 字。命中规则的 host 若没有白名单字段，只显示字节数，不再显示原文；没有规则的 host 保持原来的 60 字预览。另有一个单测保证白名单里永远没有 `password`/`token`/`key`/`card`/`number` 这类名字 | ✅ root 生成摘要、只展示安全字段；13 个单测覆盖 messages / system prompt / 卡号 / token 等敏感字段不出现在弹窗文本里 |
| 2.2 | `代码` 全部 MCP 工具加 annotations（A §5.1） | ✅ 已完成：13 个工具标了注解——`credential_status/list/list_types/get/audit_log/templates` 标 `readOnlyHint`，`delete/delete_type` 标 `destructiveHint`，`http_request/gateway` 标 `openWorldHint`，`test/imap_test/graph_mail_test` 同时标 `readOnlyHint`+`openWorldHint`；其余（`set`、`configure_http`、各 `setup_*`、`oauth_login` 等）不打注解，按 MCP 规范默认当作"可能有副作用"处理，没有强行分类。新增 4 个单测（`kv-mcp/src/tools/basic.rs` 的 `annotation_tests`） | `credential_list` 等在 Claude Code 中不再触发写操作级权限提示；`cargo test` 验证注解值 |
| 2.3 | `代码` `kv-hook` 二进制与 Claude Code 适配器（A §5.2） | ✅ Rust hook 已部署；`run.sh` 优先调用安装的二进制，缺失时回退 Node。2026-10-09 安全修订：两条路径均移除读取已返回凭证明文缓存的精确匹配，只保留厂商格式、提示词识别与掩码；不创建或读取 `.redact`。任意无已知格式的字符串可能无法识别 | Rust hook 回归通过；Node 回退的缓存忽略、密钥格式识别及安全命令放行 3 个测试通过 |
| 2.4 | `代码` Codex 适配器（同一 JSON 结构，目标 `~/.codex/hooks.json`） | ✅ 10-10 按官方文档（developers.openai.com/codex/hooks）核实后重做。之前「最佳努力版」其实有两处失效：① `kv-hook tool` 输出的 `permissionDecision: "ask"` Codex 只解析不支持——hook 被标记为失败、工具照常执行，等于什么都没拦；② Codex 的文件编辑工具叫 `apply_patch`，补丁正文放在 `tool_input.command`，旧的 `tool_text` 对它返回空串，文件写入根本没扫。现在：新增 `kv-hook codex-tool` 模式（只发 `deny`，并同时 exit 2 + stderr 两条官方拒绝通道；`Bash`/`apply_patch` 扫 `command`，MCP 工具扫全部字符串字段，keyvalet 自己的 server 豁免）；`install.sh` 写入 `matcher: "Bash|apply_patch|mcp__.*"`，检测到我们早先写的旧文件（指向 `kv-hook tool`）会自动升级，其他已有文件仍不覆盖；安装提示告诉用户 Codex 要先在 `/hooks` 里信任这个 hook 才生效。`docs/runtimes.md` Codex 行改为「中等置信度」。6 个新单测 | ✅ 配置格式已按官方文档核实；仍未在真实 Codex 会话里端到端跑过（本机 Codex 的 `~/.codex/hooks.json` 还是旧版，重跑 `install.sh` 会升级） |
| 2.5 | `市场` 录 60 秒演示（`marketing/demo-script.md`）；GIF 进 README 顶部；社交预览图 | 🟡 社交预览图 ✅（`site/static/og.png`，1280×640，深绿主题，待 👤 上传到 GitHub Settings → Social preview）；**GIF / MP4 未录**——需要真人在 Touch ID 前操作，录好后放 `site/static/demo.gif` 并把 `config.toml` 的 `demo_gif` 改成 `true`，README 顶部再加一行图片 | ⏳ README 首屏还没有 GIF |
| 2.6 | `市场` 按 `marketing/*.md` 定稿 Show HN、X 长帖、Reddit、Product Hunt 文案；附录 B 的质疑回答写成 FAQ 草稿 | ✅ 10-10 全部按 v0.2 的真实状态重写（原稿还写着 BehalfAI、`./scripts/install.sh` + `claude mcp add`、「弹窗显示用途」、sudoers 规则、Node.js）：`show-hn.md`（标题 73 字符）、`x-thread.md`、`reddit.md`、`product-hunt.md`（tagline 47 字符）、`repo-metadata.md`、`directories.md`、`launch-plan.md`（清单按现状勾选），新增 `faq.md`（附录 B 的 9 条质疑各 ≤150 词，每条引 SECURITY.md 的对应条目；明确「今天没有 MITM 代理」「用途不进弹窗」「无遥测」）。`marketing/` 在 .gitignore 里，不进仓库 | ⏳「另一个人读一遍」还没做 |

### 第 3 周：发布周

| # | 任务 | 产出 | 完成标准 |
| --- | --- | --- | --- |
| 3.1 | `代码` 打 tag `v0.1.0`，GitHub Release（`marketing/release-notes.md`），安装脚本指向 release 产物 | ✅ 10-10 完成，而且已经发到 v0.2.0：`v0.1.0`（14:44，commit `da78fcb`）和 `v0.2.0`（16:56，`5de019f`）两个 release 都已在 GitHub **正式发布**（非 draft），各带 `keyvalet-<tag>-macos-arm64.tar.gz` + `SHA256SUMS`，release notes 在 `.github/release-notes/`。release workflow 在受保护的 `release` 环境里跑，用 Simvito 的 Developer ID 签名；v0.2.0 之后又加了 notarization（commit `0fe872b`，**还没有任何一次 release 跑过这段，需要先 `workflow_dispatch` 干跑一次验证**）。`site/install.sh` 默认拉最新 release。v0.2.0 的主要改动：helper 从「每会话 sudo 启动」改成 launchd daemon `dev.keyvalet.helper` + 每用户 agent `dev.keyvalet.agent`，daemon 校验 agent 的签名 | ✅ Release 页有；⏳「全新 Mac 上 `curl … \| sh` 到首次代理调用 < 5 分钟」还没在干净机器上计时过（本机是升级安装） |
| 3.2 | `市场` D-3 预热帖（不提产品） | X 一条 | — |
| 3.3 | `市场` D0 周二或周三美西 8–10 点 Show HN；1 小时后 X 长帖；同日 r/ClaudeAI、r/mcp | 三处帖子 | 前两小时每条评论都回；安全质疑引用 SECURITY.md 条目 |
| 3.4 | `市场` D1 r/selfhosted、r/macapps、r/cursor；D2 dev.to 长文 | 帖子与文章 | — |
| 3.5 | `代码` 当天修 bug，当天发补丁版本，回帖附提交链接 | `v0.1.x` | HN 讨论里的可复现 bug 24 小时内修复 |
| 3.6 | `市场` D3 起提交 MCP 目录与 awesome 列表（`marketing/directories.md`） | PR 与提交记录 | 至少 5 处收录 |

### 第 4 周

| # | 任务 | 产出 | 完成标准 |
| --- | --- | --- | --- |
| 4.1 | `代码` `keyvalet scan`：扫描 `.env*`、`~/.claude.json`、`.cursor/mcp.json`、`~/.codex/config.toml`、shell rc；原生窗口勾选；导入；替换占位符；确认后删备份（P J2） | ✅ 10-10 关闭。**勘误**：下面那段「只做了一半」已经过时——写入半边其实在 commit `0772afc` 就补上了（AppleScript `choose from list` 多选弹窗 → `vault.set` 导入 → 先备份到 `<file>.bak-keyvalet` → 只改写命中的那一行 → 最后一个原生弹窗问要不要删备份），占位符刻意用 `KEYVALET_MOVED_RUN_keyvalet_get_<type>_<name>_TO_RETRIEVE` 这种一眼看出坏掉的字符串而不是 `${KEYVALET:…}`，因为目前没有运行时能解析后者，装成能用反而更糟。10-10 补上最后一个缺口：导入时按 `templates/catalog.json` 里同 id 的模板套上注入规则和 `allowed_hosts`，**默认 `proxy_only`**，所以 `scan` 迁进来的 `openai/env` 马上就能走 `credential_http_request`，而 AI 读不到明文（终端 `keyvalet get` 仍可读，顺带修了 `keyvalet get` 对模板凭证打印空行的 bug）；模板需要多个秘密字段（如 datadog）或没有 hosts（如 jira）的仍按纯值导入。J2 里「每条发一次验证请求」没做：kv-cli 是同步二进制，没拉 tokio，验证留给 agent 的 `credential_test`。原文：只做了一半，刻意的：`kv-cli scan` 已完成——扫描 cwd 的 `.env*`/`.cursor/mcp.json` 和（经 `SUDO_USER` 解出的真实用户 home 下的）`~/.claude.json`/`~/.codex/config.toml`/`~/.zshrc` 等 shell rc，逐行复用 `kv_hook::detect`（跟 hook 用的同一套识别引擎），报告文件、行号、识别出的服务、建议的 `keyvalet set <id> <name>`；AWS 这类多字段凭证（`tool` 字段非空）识别出来但明确说做不了，指向 MCP 的专属 setup 工具。4 个单测。**勾选、导入、替换占位符、删备份这四步没做**——这些是会直接改写用户真实配置文件的操作，想先让这部分改写逻辑单独过一遍审查再写，不想在赶功能的时候一次性做完一个「写错了就是真的损坏用户文件」的功能；只做只读扫描+报告，用户看着建议手动 set 再手动删，比一次性做完但没人复核的自动改写更负责任 | ✅ 10-10：`cargo test -p kv-cli` 15 项覆盖扫描 / 建议 / 行内改写 / 模板套用 / 临时 vault 端到端导入；"原文件 grep 不到有效密钥"由行内改写 + 占位符保证；"10 条密钥 2 分钟内迁完"还没拿真实 `.env` 计时过 |
| 4.2 | `代码` Cursor 适配器原型（`~/.cursor/hooks.json`，退出码 2） | ✅ 已完成，且先去核实了 Cursor 的真实 hook 契约（原计划写的"退出码 2"只是其中一种路径，不是全部）：真正的决策通道是 stdout 的一段 JSON（`{"permission": "allow"\|"deny"\|"ask", ...}`），退出码 2 只是等价快捷方式；能拒绝的事件只有 `beforeShellExecution`/`beforeMCPExecution`，`beforeReadFile` 是观察型、没有否决权（跟架构文档原来写的不一样，已经在架构文档里更正）；`permission: "ask"` 在 schema 里但 Cursor 不强制执行，所以 `kv-hook` 在这两个事件下从不输出 ask，一律降级成 deny。`kv-hook` 加了两个新子命令 `cursor-shell`/`cursor-mcp`，复用同一套密钥检测核心；`beforeMCPExecution` 的工具名不是 Claude Code 的五种已知形状，`tool_input` 还是 JSON 字符串不是对象，所以新写了一个递归扫描所有字符串字段的办法（`mcp_tool_text`），不按字段名取值。还处理了一个 Cursor 特有的坏天气路径：Cursor 的文档说这两个事件如果没收到合法响应就会直接拒绝放行（跟 Claude Code"没输出就放行"正好反过来），所以 `kv-hook` 在这两个模式下，不管是 `KEYVALET_HOOKS=off`、读 stdin 失败还是 JSON 解析失败，都会明确打印一个 `{"permission":"allow"}` 而不是什么都不打印。`install.sh` 在 `~/.cursor` 目录存在且没有 `hooks.json` 时写入配置，已有文件则不覆盖。6 个新单测 | `cargo test -p kv-hook`：命令里带密钥时拒绝且不是 ask；MCP 工具调用嵌套参数里的密钥也能被扫到；`tool_input` 解析失败时放行而不是卡死 |
| 4.3 | `代码` 核实 Grok 的 MCP 与 hook 能力；MCP 配置写进安装脚本 | ✅ 已完成：Grok Build（xAI 的 agent CLI）MCP 和 hooks 都是原生支持，不是"待核实、先空实现"。MCP：`grok mcp add`/`config.toml` 注册，工具按 `server__tool` 命名，KeyValet 自己的 MCP server 应该不用改代码就能在 Grok 里用（这次没改，因为本来就是标准 MCP，不需要 Grok 专属代码）。Hooks：原生支持 `PreToolUse`/`UserPromptSubmit`/`PostToolUse`/`Stop` 等事件，配置在 `~/.grok/hooks/*.json`（用户级，默认信任）或 `<project>/.grok/hooks/*.json`（项目级，需要 `/hooks-trust`）；但只有 `PreToolUse` 真正能拦截。关键发现：Grok 会读 `~/.claude/settings.json` 里的 Claude Code hook 配置做兼容，但不解析 Claude Code 输出里嵌套的 `hookSpecificOutput.permissionDecision`——读不懂的决定一律当作"没给决定"，等于放行；真正生效的契约是退出码（0=放行，2=拒绝）。所以没有复用 Claude Code 现有 hook 配置,而是在 `kv-hook` 加了专属的 `grok-tool` 模式，写进独立的 `~/.grok/hooks/keyvalet.json`（见 4.2 行的技术细节）。写了 `docs/runtimes.md` 记录四个运行时的支持现状和置信度，而不是一节嵌在这份 action-plan 里——内容太细，单独放更合适 | `docs/runtimes.md` 存在；`cargo test -p kv-hook` 覆盖 `grok-tool` |
| 4.4 | `代码` MCP SDK 升级到 2026-07-28 规范；per-session 绑 stdio 进程 | ✅ 其实早就达标，这次只是确认：`kv-mcp` 用的 `rmcp = "3"` 解析到 3.5.1，这个版本的 `ProtocolVersion::LATEST` 本身就是 `2026-07-28`（`rmcp` 的 CHANGELOG 能看到这个版本号下的真实改动，不是占位），kv-mcp 没有在任何地方把协议版本锁定在更老的值，所以是跟着 SDK 默认走的最新规范，不需要额外改代码；「per-session 绑 stdio 进程」这条本来就是 Rust 重写时就定下的设计（`kv-mcp/src/session.rs` 的 `HelperSession`：一个 MCP server 进程 = 一个 agent 会话，进程退出会话就结束），不是这次新做的 | `cargo test` 全过；`rmcp` 的 `ProtocolVersion::LATEST == V_2026_07_28` |
| 4.5 | `市场` 提交 Claude Code 官方插件市场、Codex plugins、cursor.directory | 三处提交 | 至少一处上架 |
| 4.6 | `市场` Product Hunt（star 与反馈攒够后）；事故复盘第二篇（Comment and Control） | 🟡 博客草稿 ✅ `marketing/blog-comment-and-control.md`（约 1,400 词含 8 条 X 长帖；事实对照了 2026-04-15 的原始披露文和 CSA 4-17 研究简报：三家 agent、泄露的 secret 列表、$100 / $1,337 / $500 赏金、无 CVE；VentureBeat 只作为报道引用，没从它取事实；「KeyValet 怎么切断」一段老实写明今天只覆盖本机，CI 的能力令牌是计划项）。**还没上站**，等人工读一遍再搬到 `site/content/blog/`。PH 按计划等 star 攒够 | ⏳ |
| 4.7 | `市场` 开始外联设计合作伙伴：从 HN/Reddit 评论和 GitHub issue 里挑 20 个目标，每周 5 封（M 附录 A） | 外联记录表 | 第 8 周前至少 3 次通话 |
| 4.8 | `运营` 发布 v0.2，中英文 release notes；第一次月度复盘（附录 C） | ✅ v0.2.0 已发（见 3.1）；10-10 给 `v0.1.0.md`、`v0.2.0.md` 补了 `## 中文` 段（GitHub 上已发布的 release 正文是创建时复制的，要同步得 👤 手动编辑 release）；`v0.2.1.md` 中英文已写好，版本号已全部 bump 到 0.2.1（12 个 crate、Cargo.lock、Info.plist、package.json、三个插件 manifest），**打 tag 由你决定**——建议先 `workflow_dispatch` 干跑一次验证 notarization。第一次月度复盘：`docs/review-2026-10.zh-CN.md` | ✅ |

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
| 6.1 | `代码` Linux / CI 调用与身份接入、本地 helper 兼容路径：系统用户 `keyvalet`、systemd 服务、Unix socket + peer-uid；TPM2 可选，软件保护明确显示，已启用硬件后失败不静默降级；远程执行按配对 / relay 前置条件推进（P §1.4、A §8.0、§9） | `install.sh` Linux 分支及接入示例 | Ubuntu 22.04 与 Debian 12 上 J1 可完成；无 TPM 可用；硬件访问失败不改用文件密钥；远程路径不把长期凭证交给 runner |
| 6.2 | `代码` TTY Approver（仅 T0/T1）；无 GUI 时自动选用 | `kv-core/approvers/tty.rs` | T2 在无手机的 Linux 上被拒并说明 |
| 6.3 | `代码` `keyvalet hooks install --all`：检测四个运行时，幂等写入 | CLI | 卸载可逆 |
| 6.4 | `代码` 审计哈希链 + `keyvalet audit export/verify`（A §12） | `kv-audit` | 篡改一条后 `verify` 报错 |
| 6.5 | `市场` 事故复盘第三篇（GhostSplice）；5 分钟演示视频；争取第一个播客 | 内容 | — |
| 6.6 | `市场` r/selfhosted 与 Linux 社区发 Linux 支持；v0.4 发布 | Release | — |

**2026-10-10 Linux 方案决定（排在 v0.1 发布与 5.1 策略引擎之后）：** helper 按规划做常驻服务（系统用户 `keyvalet`、systemd、Unix socket + `SO_PEERCRED` 识别调用者），不沿用 macOS 的「每会话 sudo 启动 root helper」。审批优先用 polkit：每次都要求重新验证（`auth_self`），由用户会话里的 polkit 代理要求输入登录密码或指纹，AI 不知道密码就无法批准；无 GUI 时用 polkit 的终端代理，没有 polkit 时才退回 6.2 的确认码方式（只允许 T0/T1）。Linux 验证在内网 Ubuntu 机器 `ndu` 上通过 ssh 进行。

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
| 第 15–17 月 | 首个云端隔离执行方案仅做 AWS Nitro Enclaves + KMS：`kv-enclave` 的授权、解密、凭证使用及 TLS 均留在 enclave；可复现 EIF；PCR0 随客户端发布；iOS 与 Mac 端证明验证（A §11）；BYO-KMS 默认；托管 KMS 信任声明进产品 | 找 3 家有 CI 离线 / 无人值守需求的付费团队试用；Terraform 文档 |
| 第 18–20 月 | 远程 MCP 端点（Hydra 作 AS、PRM、CIMD）（A §10.4）；ChatGPT 与 Claude App 接入测试；Android App（StrongBox） | Enterprise 自托管 Terraform 发布；SOC 2 Type I 启动；第一份企业合同 |
| 第 21–24 月 | SCIM；Okta Cross-App Access；Vault/OpenBao 后端；macOS 菜单栏（可选）；Windows TPM + Hello 本地客户端仅在明确需求后另行排期，当前不承诺本季度交付 | SOC 2 Type I 完成；参与 MCP ext-auth 讨论；第 24 个月结局评估（§9） |

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
