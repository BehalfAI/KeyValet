# 云端密钥与隔离执行：KMS、HSM、TPM、Enclave

记录日期：2026-10-10。本文归档云厂商调研、方案取舍和一次 AWS 主机检查；产品规格、
开放范围与价格以实际部署时的官方信息为准。文中的接入建议属于设计结论，不表示已经实现。
当前实现见 [密钥保护说明](key-protection.zh-CN.md) 与 [Linux 支持](linux.md)。

个人、多机、组织 SaaS、API 使用场景及开源/收费建议，见
[产品模式与商业分层](product-modes-and-pricing.zh-CN.md)。

## 1. 大白话：保险柜和上锁工作室

| 名称 | 怎么理解 | 主要保护什么 |
| --- | --- | --- |
| TPM / 云主机 vTPM | 这台机器的钥匙保险柜；程序请它用钥匙计算 | 不可导出的设备密钥；还可以把使用条件绑定到启动状态 |
| KMS | 云端钥匙柜，通过网络 API 请它加密、解密、签名 | 统一管理密钥、使用权限、禁用与审计；不要求云主机有 TPM |
| HSM | 保管和使用钥匙的硬件密码机，可以作为 KMS 的底层 | 密钥存储与密码运算的硬件边界；独享程度取决于产品 |
| Enclave / SGX | 上锁工作室，敏感程序和使用中的明文留在里面 | 运行中的代码、密钥与数据；能否隔离普通主机的 root，要看具体方案 |
| 整台机密虚拟机 | 把整栋房子与云端宿主机隔开 | 虚拟机相对于宿主机的内存边界；虚拟机内部的操作系统通常仍被信任 |

KMS 与 HSM 可以组合使用：应用接 KMS API，密钥运算由背后的 HSM 完成。但不同厂商和
实例类型也提供软件保护，不能只看到“KMS”三个字就认定有 HSM。凭据管理服务则存放
获授权程序可以取出的密码或 token，和不可导出密钥的运算服务也有区别。
参见 [AWS KMS 概念](https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html)、
[Google KMS 保护等级](https://docs.cloud.google.com/kms/docs/protection-levels)、
[阿里云密钥管理概述](https://help.aliyun.com/zh/kms/key-management-service/user-guide/overview-of-key-management)。

## 2. KMS 和 TPM：不能脱离攻击场景排安全等级

以下比较以“用 KMS 或 TPM 解开数据密钥，再在普通 helper 内存中解密凭证”的接法为前提。
这也是当前 KeyValet 本地密钥保护需要说明的边界。

| 场景 | KMS | TPM / NitroTPM |
| --- | --- | --- |
| 只复制加密凭证库和相关磁盘文件 | 没有有效的云身份和解密权限，通常不能解开 | 正确配置的不可迁移密钥不能仅靠复制密钥包在另一台机器使用 |
| 原机器被攻破，攻击者取得 root | 若仍能取得获授权的云身份，可能继续请求 KMS 解密；本地明文也可能被读取 | 可能调用原机器的 TPM；本地数据密钥和凭证明文仍可能被读取 |
| 抱走整台物理机器 | 还要看能否取到云身份、权限是否撤销、是否仍可联网 | TPM 也被带走；要结合磁盘加密、密钥授权和启动策略判断 |
| 集中撤权与审计 | 适合通过云 IAM、密钥策略及审计统一管理 | 主要依赖本机策略；远程撤权需额外设计 |
| 无网络运行 | 一般需要访问服务；缓存数据密钥会改变撤权与内存保护边界 | 可以本地运算，是否需要额外在线授权由应用决定 |

因此，KMS 在集中治理上更方便，TPM 在设备绑定和本地运行上更方便。
“钥匙不可导出”和“攻击者不能使用钥匙”是两个要求；二者都不会自动保护已经进入普通
进程内存的明文。启动度量也不等于持续证明系统没有在启动后被攻破。
参见 [NitroTPM 原理](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/nitrotpm.html)
以及 [KeyValet 的本地保护限制](key-protection.zh-CN.md#文件内存整机失窃与云密钥)。

恢复口令是 KeyValet 独立的离线解密途径。讨论硬件绑定、KMS 撤权或 Enclave 时，也必须
考虑恢复口令、旧备份和已经解密的副本，不能把硬件方案写成所有路径都无法取出秘密。

## 3. KeyValet 当前支持什么，接入后会改变什么

截至本记录，`ProviderId` 包含 Secure Enclave、Windows Hello、TPM2 和软件密钥，
没有云 KMS/HSM provider，也没有已实现的云 Enclave executor。
`MasterKeyProvider::create/unlock` 返回本地使用的主密钥材料；实现见
[master_key.rs](../rust/crates/kv-vault/src/master_key.rs)。

Linux TPM2 已实现 P-256 ECDH，通过 `tpm2-tools` 和 `/dev/tpmrm0` 运算，使用
`fixedTPM` / `fixedParent` 限制密钥迁移。它目前没有 TPM PIN、PCR 绑定或独立验证的
远程证明；使用授权由系统层 polkit 提供。root 或受攻击的服务可能绕过这层授权使用 TPM，
派生出的 AES 密钥和解密后的凭证会进入服务内存。详见 [Linux 保护与恢复](linux.md#protection-and-recovery)。

| 接入方式 | 改善什么 | 实现与保护边界 |
| --- | --- | --- |
| Linux 主机提供兼容的 TPM2，包括 NitroTPM | 使用设备绑定密钥，替代明确选择的软件保护 | 可以复用现有 TPM2 路径；仍需验证设备访问、算法、工具和实际密钥往返，设备存在不等于已通过 KeyValet 验收 |
| 普通云 KMS provider | 将包裹密钥交给云端，增加统一权限、撤权和审计 | 可复用主密钥抽象，但需要设计密钥包格式和各家适配器；若数据密钥仍返回普通 helper，就保留其内存边界 |
| Enclave executor + 按证明放行的 KMS | 将普通主机 root 放在敏感执行边界之外 | 需要把解密、授权校验、凭证注入、上游 TLS 和结果处理放入隔离环境；只替换主密钥 provider 不够 |

云厂商提供 KMS 不会让客户机自动出现 `/dev/tpm0` 或 `/dev/tpmrm0`。
当前无 TPM 的 Linux 主机仍需显式选择软件方案；已经配置 TPM 的凭证库出错时不能静默降级。

## 4. 多云适配：哪些可以共用，哪些需要各家接入

| 接口层 | 可以共用的部分 | 需要分别处理的部分 |
| --- | --- | --- |
| 云 KMS API | 凭证库格式、数据密钥包裹流程、错误分类和业务策略 | 每家的 API/SDK、身份认证、密钥标识、密文格式、权限策略与审计接入 |
| TPM 2.0 | 标准 TPM 指令与 Linux TPM2 provider | 系统接口、设备权限、兼容性验证；云端远程证明和身份绑定仍可能有厂商差异 |
| HSM 的 PKCS#11 / KMIP | 在产品确实暴露对应接口时，共用相关调用逻辑 | 厂商客户端、连接与登录、支持的算法和对象属性，以及运维配置 |
| Enclave / SGX / Confidential Space | 敏感业务逻辑、授权规则和请求处理 | 启动镜像、SDK、证明格式、信任根、允许的程序版本、密钥放行和网络代理 |

PKCS#11 是密码设备的调用接口，通常由厂商客户端库实现；KMIP 是密钥管理互通协议。
它们能减少重复工作，但不是所有云 KMS 都支持的共同入口，也不保证更换产品后完全不用适配。
参见 [AWS CloudHSM PKCS#11 库](https://docs.aws.amazon.com/cloudhsm/latest/userguide/pkcs11-library.html)
和 [OASIS KMIP](https://www.oasis-open.org/committees/tc_home.php?wg_abbrev=kmip)。

设计结论：核心接口保持统一，按实际需要增加厂商适配器；无需一开始接完所有云厂商。
TPM 基础密钥运算可以优先复用标准接口，远程证明与云权限治理单独处理。

### 主流厂商的 KMS / HSM 入口

| 厂商 | 产品与官方资料 | 选型时怎么理解 |
| --- | --- | --- |
| 腾讯云 | [KMS 独享版](https://cloud.tencent.com/document/product/573/74735)、[云加密机 CloudHSM](https://cloud.tencent.com/document/product/639/34130) | 日常应用优先评估 KMS；独享版在独享的物理密码机内运算 |
| AWS | [KMS](https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html)、[CloudHSM](https://docs.aws.amazon.com/cloudhsm/latest/userguide/introduction.html) | KMS 适合直接接 API；CloudHSM 提供更多 HSM 与密钥管理控制，需要额外运维 |
| Azure | [Key Vault 密钥](https://learn.microsoft.com/en-us/azure/key-vault/keys/about-keys)、[Managed HSM](https://learn.microsoft.com/en-us/azure/key-vault/managed-hsm/overview) | 区分软件与 HSM 保护的密钥；Managed HSM 提供专用的托管 HSM 服务 |
| Google Cloud | [Cloud KMS / Cloud HSM 保护等级](https://docs.cloud.google.com/kms/docs/protection-levels) | 可通过 KMS API 使用 HSM 保护的密钥；软件、共享硬件和独享硬件等级需分别核对 |
| 阿里云 | [KMS 软件与硬件实例](https://help.aliyun.com/zh/kms/key-management-service/product-overview/service-selection)、[加密服务 HSM](https://help.aliyun.com/zh/kms/) | KMS 有不同保护类型，需要硬件保护时确认实例和密钥类型 |
| 华为云 | [DEW：KMS、专属加密 DHSM](https://support.huaweicloud.com/intl/zh-cn/productdesc-dew/dew_01_0093.html) | KMS 提供托管密钥服务；DHSM 提供专属加密资源 |

针对现有腾讯云和 AWS 主机，普通云密钥管理需求可先评估各自的 KMS。
如果明确要求普通主机 root 无法读取使用中的 API 凭证，则需要继续评估隔离执行。

## 5. NitroTPM 与 Nitro Enclaves 的关键差别

| 问题 | NitroTPM | Nitro Enclaves |
| --- | --- | --- |
| 本质 | EC2 实例的虚拟 TPM 2.0 | 从父实例切出 CPU、内存的独立隔离虚拟机 |
| 程序在哪里跑 | 普通 EC2 操作系统里 | 敏感程序在 Enclave 内运行 |
| 外面主机的 root 能否读取使用中的明文 | 明文返回普通进程后，TPM 不保护该进程内存 | 不能直接读取 Enclave 的内存；应用还必须避免把明文交回外面 |
| 网络和存储 | 使用普通主机网络与磁盘 | 无直接外网、持久化存储或 SSH；通过 vsock 与父实例通信 |
| 改造范围 | 接设备密钥接口；高级启动策略需额外实现 | 拆出完整敏感执行流程、制作镜像、验证证明并处理通信 |

参见 [NitroTPM](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/nitrotpm.html)
和 [Nitro Enclave 的隔离边界](https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave.html)。
使用 Nitro Enclaves 不要求同时启用 NitroTPM。

普通接法：KMS/TPM → 普通 helper 拿到数据密钥 → 普通 helper 解密、调用 API。

隔离接法：经过验证的 Enclave 拿到数据密钥 → 在内部解密、校验授权并建立上游 TLS →
父实例仅转发加密流量，结果按授权过滤或加密后返回。

TLS 必须在隔离环境内终止，不能让父实例解密带凭证的 HTTP 请求。还要绑定真实上游身份、
操作范围、有效期和用量，防止受攻击的父实例利用隔离服务代做未授权操作。
Enclave 的内存隔离不会自动提供业务授权，也不会阻止父实例停掉服务或丢弃网络流量。

AWS KMS 当前同时支持 Nitro Enclaves 和 NitroTPM 的证明请求，可将返回数据加密给证明中
绑定的公钥。但 NitroTPM 收到的结果最终仍可能用于普通实例内存，不能因此把它当作
Enclave 的运行时隔离。参见 [AWS KMS 证明支持](https://docs.aws.amazon.com/kms/latest/developerguide/cryptographic-attestation.html)。

KMS + Enclave 必须拒绝绕过证明、直接向普通主机返回数据密钥的路径。能修改密钥策略的
账号管理员仍可能撤掉这些限制；BYO-KMS 默认方案、托管 KMS 的账号治理信任声明及具体
策略约束，已记录在 [架构 §11](architecture-2026-10.md#11-nitro-enclave-executor-phase-4)。

## 6. 其他厂商的类似隔离执行方案

以下是按隔离形态作出的比较，不代表这些产品具有完全相同的安全实现、接口或认证等级。

| 厂商 | 产品与官方资料 | 与 Nitro Enclaves 的关系及使用条件 |
| --- | --- | --- |
| AWS（参照） | [Nitro Enclaves](https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave.html) | 独立隔离虚拟机，父实例通过 vsock 通信；需要支持该特性的实例并预留 CPU、内存 |
| 阿里云 | [虚拟化 Enclave / 神龙 Enclave](https://help.aliyun.com/zh/ecs/user-guide/build-a-confidential-computing-environment-by-using-enclave) | 运行方式很接近 AWS：切出资源建立独立 EVM，父实例不能访问对应内存；仅通过 vsock 通信。文档列出 hfg9i、hfc9i、hfr9i、g8i、c8i、r8i 的指定规格，至少 4 vCPU；每实例一个 Enclave |
| 华为云 | [QingTian Enclave](https://support.huaweicloud.com/productdesc-ecs/ecs_03_1421.html) | 同样是独立隔离虚拟机；官方明确说明父实例 root 不能访问或 SSH 进入。仅部分 QingTian ECS 实例支持，具体规格与地域需购买时确认 |
| 腾讯云 | [Tencent SGX 机密计算](https://cloud.tencent.com/document/practice/213/63353) | 使用 Intel SGX 保护程序内部的执行区域；需要适配 SGX 与远程证明。支持 M6ce、S8ce；S8ce 在本次查阅的文档中为白名单开放 |
| Azure | [SGX Enclaves](https://learn.microsoft.com/en-us/azure/confidential-computing/confidential-computing-enclaves) | 同属 SGX 程序级隔离，需 Enclave 感知的代码或框架；指定机型包括 DCsv3 / DCdsv3 |
| Google Cloud | [Confidential Space](https://docs.cloud.google.com/confidential-computing/confidential-space/docs/confidential-space-overview) | 用机密虚拟机、经过加固的系统、证明与容器组成受限工作环境，保护工作负载的数据免受部署运维方直接访问；不是在可自由管理的普通主机里划一个 SGX 区域 |

调研结论：阿里云虚拟化 Enclave 和华为云 QingTian Enclave 在运行方式上最接近 AWS；
腾讯云可以先评估 M6ce SGX。普通云主机不能只靠安装软件获得缺失的硬件或平台支持。
本次未验证这些厂商的实际购买库存、报价或 KeyValet 运行兼容性。

Google Confidential Space 的保护来自完整部署方式，包括关闭 SSH、受限系统和工作负载
证明，不能只选普通 Confidential VM 就认为效果相同。
参见 [Confidential Space 安全设计](https://docs.cloud.google.com/docs/security/confidential-space)。
一般整台机密虚拟机隔离的是云端宿主机与客户虚拟机，客户虚拟机内的操作系统仍在信任
范围内，不能据此保证防住其中的 root。这是根据隔离边界作出的判断，参见
[Azure 机密虚拟机 FAQ](https://learn.microsoft.com/en-us/azure/confidential-computing/confidential-vm-faq)。

如果只寻找 NitroTPM 一类的设备接口，已有明确文档的替代项包括
[Azure Trusted Launch vTPM](https://learn.microsoft.com/en-us/azure/virtual-machines/trusted-launch)
和 [Google Shielded VM vTPM](https://docs.cloud.google.com/compute/shielded-vm/docs/shielded-vm)。
它们属于钥匙与启动状态保护，不应与上表的隔离执行混为一谈。

## 7. 价格结论：功能费为零，资源和配套服务仍计费

| AWS 方案 | 功能额外收费 | 实际成本来源 |
| --- | --- | --- |
| NitroTPM | 无额外功能费 | 原有 EC2、磁盘等资源费用 |
| Nitro Enclaves | 无额外功能费 | 原有 EC2 与配套服务；隔离环境占用父实例的 CPU、内存，可能需要更大机型 |
| 与 Enclave 或普通 helper 配套的 KMS | 单独计费 | 客户管理密钥存储、轮换、API 调用；其他日志、网络与计算服务另外核算 |

来源：[NitroTPM 定价](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/nitrotpm.html)、
[Nitro Enclaves 计费 FAQ](https://aws.amazon.com/ec2/nitro/nitro-enclaves/faqs/)。

AWS KMS 当前定价页列出的客户管理密钥基础费用为每把每月 1 美元。
普通对称加解密的官方示例按每一万次请求 0.03 美元计算，并有每月两万次请求的免费额度，
部分操作不适用免费额度。首次、第二次轮换分别增加每月 1 美元，此后轮换不再继续增加；
多地域副本和不同请求类型还需分别核算。这里记录的是官方定价页的规则与示例，具体地域
和调用类型应在部署时核对。[AWS KMS 定价](https://aws.amazon.com/kms/pricing/)

因此，“Enclaves 不另收费”不等于“运行敏感程序不占资源”，也不能将 AWS 的功能免费
结论直接套到其他厂商。其他云的专用机型、HSM、白名单和报价本次未作价格对比。

## 8. AWS 主机检查的匿名结论

2026-10-10 对一台 AWS 主机完成只读检查。仅记录规格、功能状态和适配结论；文档不保存
连接命令、地址、私钥路径或具体资源编号。以下为当时的快照，配置可能改变。
检查没有安装软件、启用特性、停止或重启实例。

| 项目 | 检查结果 |
| --- | --- |
| 实例类型 | `m6i.xlarge`，4 vCPU、16 GiB 内存 |
| 系统 | Ubuntu 22.04.4 LTS，内核 `6.8.0-1057-aws` |
| 启动方式 | `BootMode=uefi-preferred`，`CurrentInstanceBootMode=uefi` |
| 镜像 | 未设置 NitroTPM 的 `tpmSupport` |
| 实例类型能力 | EC2 实例类型 API 明确报告支持 Nitro Enclaves、NitroTPM 2.0 |
| Nitro Enclaves 实际状态 | 实例属性 `EnclaveOptions.Enabled=false`，没有 `/dev/nitro_enclaves` |
| NitroTPM 实际状态 | 当前实例未启用；没有 `/dev/tpm0` 或 `/dev/tpmrm0` |
| 工具 | 未安装 AWS CLI、`nitro-cli`、`tpm2-tools` |
| 内核配置 | `TCG_TPM=y`、`TCG_CRB=y`、`NITRO_ENCLAVES=m`；未发现已加载的 Nitro Enclaves 模块 |

结论是“型号支持，但这台实例现在没有启用”，不能只根据内核配置或型号就报告已受保护。

- **Nitro Enclaves**：可在现有支持的实例上配置；需要停机设置实例属性，并准备驱动、
  工具和资源分配。此记录没有执行这些变更，也没有完成 Enclave 运行验收。
- **NitroTPM**：AWS 规定只能在启动新实例时启用。当前实例不能通过安装 `tpm2-tools`
  或普通重启补上；需要使用满足 NitroTPM 前提的 AMI 启动新实例，再迁移业务。
- **KMS**：不依赖这台实例的 TPM；但当前 KeyValet 尚无 KMS provider，不能直接把云端
  KMS 当作已可使用的本地主密钥后端。

依据：[修改 EC2 实例属性](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_ModifyInstanceAttribute.html)、
[Enclaves 入门](https://docs.aws.amazon.com/enclaves/latest/user/getting-started.html)、
[NitroTPM 启用限制](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/nitrotpm-instance.html)。

## 9. 后续实施取舍

1. 本地版继续明确报告实际 provider、设备检测与证据；TPM 出错不降级，云端 KMS 服务
   存在不等于本机 TPM 存在，也不等于 KeyValet 已接入它。
2. 需要统一撤权、审计和多机器密钥管理时，按需求实现 KMS 适配器，保留普通 helper
   内存中存在数据密钥和凭证的信任声明。
3. 需要排除普通主机 root 时，实现完整隔离 executor；敏感操作与 TLS 留在隔离环境，
   密钥服务验证证明，执行端验证业务授权，防止绕过证明和代做未授权操作。
4. 维持现有 [架构 §11](architecture-2026-10.md#11-nitro-enclave-executor-phase-4)
   与 [行动计划](action-plan-2026-10.zh-CN.md) 的决定：首个云端隔离执行方案只做
   AWS Nitro Enclaves + KMS，BYO-KMS 默认；其他云随客户需求增加。

本次记录没有改变开发排期，没有新增云 provider，也没有启用任何主机安全特性。
