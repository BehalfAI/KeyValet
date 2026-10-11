# 密钥保护方案与 TPM 状态

[English](key-protection.md)

大白话：TPM 是电脑里的“钥匙保险箱”。它保管不可导出的私钥，并在内部用钥匙计算。
加密的密钥包、密码和凭证仍可以是硬盘上的文件。KeyValet 拿到计算出的密钥材料后，在普通
进程内存里解密凭证库；整个凭证库并不是运行在 TPM 或 Secure Enclave 里面。

## 查看当前方案和设备

```sh
keyvalet status                 # JSON；protection 是别名
keyvalet status --summary       # 醒目的可读保护摘要
```

在 AI 客户端中调用 `credential_status`，或插件的 status 命令。即使会话锁定，也会返回
`vault_protection`：通过校验过身份的 helper 连接读取公开元数据后立即关闭，不触发认证、
不解锁、不授予凭证权限，不返回凭证内容、密钥包或私钥。解锁后还会显示本会话授权。
macOS/Linux CLI 仍需 sudo，但查看状态无需 Touch ID、Hello 或 polkit 密钥授权。
Windows 的凭证库主人可直接查询正在运行的服务，无需 UAC；已提权的 CLI 直接读取元数据。
无法连接 helper 时，MCP 返回 `vault_protection: null` 和 `protection_error`，不猜测安全状态。
helper 回复缺少保护方案、检测结果或必要字段时也会报错，不把空对象当作查询成功。
查询过程中若会话被锁定或重新解锁，返回当前会话状态，并丢弃旧连接的授权列表。
保护状态查询和凭证请求必须使用有效 UTF-8，每行最多 1 MiB（包含换行符）；非法字节会在
消息被处理前拒绝。

macOS、Linux、Windows 安装器都显示同一份保护摘要。Linux 在设置前显示初始状态、设置后显示
实际选择的方案，`--software` 也一样。Linux `--no-setup` 和 Windows `-SkipSetup` 仍显示真实
状态。升级时报告已有凭证库的方案，不把本次安装参数当作已经生效的保护方式。

## 应该分成哪些情况

| 情况 | 在哪里运算 | 保护边界 |
| --- | --- | --- |
| macOS Secure Enclave | Apple 隔离的安全处理器 | 硬件隔离；不是 TPM，也不使用 TPM 接口。KeyValet 必须使用它，并要求用户在场认证，不提供正常软件回退。 |
| 独立 TPM（dTPM），Windows/Linux | 单独的安全芯片 | 正确配置时提供硬件隔离和不可导出密钥；物理攻击能力取决于设备与使用策略。 |
| 集成 TPM（iTPM），Windows/Linux | 集成到更大芯片中的专用逻辑 | 有硬件隔离，不一定在主板上看到独立 TPM 芯片。 |
| 固件 TPM（fTPM），Windows/Linux | CPU/安全环境内受硬件隔离的固件 | 可以有硬件保护；“固件”不等于普通软件模拟器。 |
| 虚拟 TPM（vTPM），虚拟机/云主机 | 虚拟机基础设施，位于客户机之外 | 可提供 TPM 接口；保障取决于宿主机、云厂商实现及证明。客户机有设备节点不能证明是物理 TPM。 |
| 软件 TPM 模拟器 | 普通宿主软件，例如 swtpm | 可通过相应传输提供 TPM 指令，没有等价的硬件隔离。KeyValet 不会自动启动模拟器。 |
| 没有 TPM 的系统/文件保护 | Windows Hello 软件密钥，或 KeyValet 显式启用的 Linux 软件方案 | 依赖系统、账号和文件权限；硬件保护缺失或未确认。这些并不是 TPM API 的等价实现。 |
| 未确认 / 尚未配置 | 证据不足，或凭证库尚未初始化 | `unknown` 不代表某个安全等级，也不能证明有或没有硬件保护。 |

不能简单给所有情况排一个固定高低顺序：还要看硬件实现、密钥使用条件、用户授权和证明。
“电脑有 TPM”不代表 KeyValet 的密钥正在用它；“指纹弹窗成功”也不能证明密钥由 TPM 保护。

## status 字段怎么读

`vault_protection` 保留原来的 provider、恢复口令、设备绑定等字段，并增加：

| 字段 | 意思 |
| --- | --- |
| `key_protection.scheme` | 已配置方案：`secure_enclave`、`windows_hello_tpm`、`windows_hello_unconfirmed`、`windows_hello_software`、`tpm2_ecdh`、`software_key_file`、`legacy_key_file` 或 `uninitialized`。 |
| `key_protection.hardware` | Secure Enclave 为 `hardware_backed`；创建 Hello 密钥时系统报告证明成功为 `os_reported`；显式软件/旧文件方案为 `software`；物理硬件保护未确认为 `unknown`；未配置为 `not_configured`。 |
| `key_protection.evidence` | 分类依据。Hello 的创建时证明只是系统报告，没有独立验证证书；Linux TPM 元数据只能证明选择了 TPM 接口，不能证明底层实现。 |
| `key_protection.authentication` | 密钥使用授权：`secure_enclave_user_presence`、`windows_hello`、系统层的 `polkit`，未初始化/待迁移时为 `none`。 |
| `key_protection.summary` | 本地化说明，安装器也使用它。 |
| `tpm.availability` | 当前系统检测：`detected`、`not_detected`、`unknown`；macOS 为 `not_applicable`。 |
| `tpm.version` | `"1.2"`、`"2.0"`；无法确定或不适用时为 `null`。 |
| `tpm.implementation` | 检测到时仍为 `unknown`：当前探测无法可靠区分独立/集成/固件/虚拟 TPM。`none` 只表示没检测到设备，不代表云宿主机没有物理 TPM。 |
| `tpm.evidence` | Linux 为 `linux_sysfs`，Windows 为 `windows_tbs`，macOS 为 `none`。Linux 另用 `resource_manager_present` 表示 `/dev/tpmrm0` 是否存在：`true` / `false`；路径检查失败为 `null`。 |

例如，本机检测到 TPM，也可能还不能确认 Hello 的这把钥匙由它保护：

```json
{
  "provider": "windows_hello",
  "tpm_backed": null,
  "key_protection": {
    "scheme": "windows_hello_unconfirmed",
    "hardware": "unknown",
    "evidence": "hello_attestation_unavailable",
    "authentication": "windows_hello"
  },
  "tpm": { "availability": "detected", "version": "2.0", "implementation": "unknown" }
}
```

方案描述的是已保存的配置，不是现场验证这把钥匙仍能使用；status 不执行密钥操作。
它会检查加密文件、恢复密钥包和设备绑定的格式、版本、编码及长度，发现格式损坏会报错。
格式正常仍不能证明密文完整、恢复口令正确；实际验证恢复路径可私下运行
`keyvalet recovery-check`。

Linux 检查已注册的 `tpmN` 设备，优先读取 `tpm0`；检测到设备但读不到版本时，保留
`detected` 并将版本设为 `null`。没有可读取的 sysfs 设备时，若设备路径可见或路径检查失败，结果为
`unknown`，不会当作没有 TPM。Linux 安装器依据同一份状态报告检查 TPM 设备是否可用。
Linux 的 `tpm_backed` 为 `null`，因为 vTPM 也能暴露相同的设备接口。旧的 `hardware_required`
表示 provider 的要求，不能当作物理硬件证明：Linux TPM 模式仍为 true，Hello 与软件模式为 false。

Windows 开发预览支持 Windows 11 24H2+（build 26100+），允许 Hello 证明为 unknown。
这是 **KeyValet 的支持范围与策略**，不是“哪个 Windows 版本开始允许/禁止 unknown”的系统规则。
当前 provider 在证明成功时记录 `true`；证明不可用、失败、不支持时记录 `null`，不会当作已确认
的软件密钥。Hello 本身仍必须可用，KeyValet 不生成替代的文件密钥。Linux 默认使用 TPM 2.0 与
`tpm2-tools`；无 TPM 的机器必须显式选择 `--software` / `setup-software`。已配置的 TPM 方案
遇到错误不会自动切换到软件。

## 文件、内存、整机失窃与云密钥

复制硬盘和抱走整台电脑是两回事。整机被偷时，TPM 也被带走；这时要看磁盘是否加密、启动环境
是否受保护、钥匙需要什么授权。KeyValet 的 Linux TPM 方案目前由系统层 polkit 批准，**没有把
TPM PIN 或启动度量/PCR 条件绑定到密钥使用上**。它本身不能解决 root 失陷或整机被偷。
其他方案与恢复路径的限制见 [SECURITY.md](../SECURITY.md) 与 [Windows 支持说明](windows.md)。

派生出的凭证库密钥、解密后的凭证仍会进入进程内存。恢复口令是独立的离线解密途径。
硬件保护或界面显示锁定，都不能保证所有密钥/明文副本已经消失。

云 KMS/HSM 是远程密钥运算服务；凭据管理服务存放可以由获授权程序取出的秘密。
它们不会自动让云主机出现 TPM 设备。KeyValet 目前没有云 KMS/HSM provider；客户机没有
`/dev/tpm0` 或 `/dev/tpmrm0` 时，不能因为厂商提供 KMS 就认为可用本项目的 TPM 模式。

例如，AWS NitroTPM 是绑定到 EC2 实例的虚拟 TPM 2.0，通过 Nitro 基础设施提供，客户机使用
TPM 指令访问。AWS KMS 则在主机之外提供密钥服务，通过网络 API 调用；普通 KMS 密钥由
HSM 保护。前者适合本机密钥与启动状态绑定，后者适合多台机器统一管理权限与审计。
二者都不能阻止已获授权的受攻击程序调用密钥，或读取解密后进入进程内存的秘密。

云厂商 KMS/HSM、NitroTPM 与 Enclave 的区别、多云适配结论、价格和 AWS 主机检查快照，
见 [云端密钥与隔离执行研究记录](cloud-key-protection.zh-CN.md)。

参考：[微软 TPM 原理](https://learn.microsoft.com/en-us/windows/security/hardware-security/tpm/tpm-fundamentals)、
[Hello 证明状态](https://learn.microsoft.com/en-us/uwp/api/windows.security.credentials.keycredentialattestationstatus)、
[Windows TPM 设备信息](https://learn.microsoft.com/en-us/windows/win32/api/tbs/ns-tbs-tpm_device_info)、
[Apple Secure Enclave](https://support.apple.com/guide/security/the-secure-enclave-sec59b0b31ff/web)、
[tpm2-tools 传输接口](https://tpm2-tools.readthedocs.io/en/latest/man/common/tcti/)、
[BitLocker 物理攻击防护](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/countermeasures)、
[AWS NitroTPM](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/nitrotpm.html)、
[AWS KMS 密钥](https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html)。
