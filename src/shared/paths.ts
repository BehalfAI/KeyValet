// 所有路径都是固定常量，刻意不允许通过环境变量覆盖：
// 否则 agent 只要改一下 MCP 配置里的 env，就能让 root 去执行它自己写的代码。

/** 安装目录（root:wheel，0755），里面的代码会以 root 身份运行，必须不可被普通用户修改 */
export const INSTALL_DIR = "/usr/local/lib/keyvalet";
/** 安装目录内的 node 副本（避免使用用户可写的 nvm/homebrew node 以 root 运行） */
export const NODE_BIN = `${INSTALL_DIR}/bin/node`;
/** Touch ID 认证程序（Swift 编译，强化运行时签名）；root helper 降权为用户后调用 */
export const TOUCHID_BIN = `${INSTALL_DIR}/bin/touchid`;
/** 只允许免密运行 helper 的 sudoers 规则（helper 启动后必须先通过 Touch ID） */
export const SUDOERS_FILE = "/etc/sudoers.d/keyvalet";
/** 以 root 运行的 helper 入口 */
export const HELPER_JS = `${INSTALL_DIR}/app/dist/helper/main.js`;

/** 凭证库目录（root:wheel，0700） */
export const VAULT_DIR = "/var/db/keyvalet";

export const SUDO_BIN = "/usr/bin/sudo";
export const OSASCRIPT_BIN = "/usr/bin/osascript";
/** 终端管理 CLI 入口（通过 /usr/local/bin/keyvalet 以 sudo 运行） */
export const CLI_JS = `${INSTALL_DIR}/app/dist/cli/main.js`;
