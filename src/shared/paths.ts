// All paths are fixed constants, deliberately not overridable via environment variables:
// otherwise an agent could just change the env in the MCP config and get root to run its own code.

/** Install directory (root:wheel, 0755); code inside runs as root, so it must not be writable by regular users */
export const INSTALL_DIR = "/usr/local/lib/keyvalet";
/** Copy of node inside the install directory (avoids running a user-writable nvm/homebrew node as root) */
export const NODE_BIN = `${INSTALL_DIR}/bin/node`;
/** Touch ID authentication program (compiled Swift, hardened runtime signed); invoked after the root helper drops privileges to the user */
export const TOUCHID_BIN = `${INSTALL_DIR}/bin/touchid`;
/** sudoers rule that only allows running the helper passwordless (the helper must still pass Touch ID after starting) */
export const SUDOERS_FILE = "/etc/sudoers.d/keyvalet";
/** Entry point for the helper that runs as root */
export const HELPER_JS = `${INSTALL_DIR}/app/dist/helper/main.js`;

/** Credential vault directory (root:wheel, 0700) */
export const VAULT_DIR = "/var/db/keyvalet";

export const SUDO_BIN = "/usr/bin/sudo";
export const OSASCRIPT_BIN = "/usr/bin/osascript";
/** Entry point for the terminal management CLI (run via /usr/local/bin/keyvalet with sudo) */
export const CLI_JS = `${INSTALL_DIR}/app/dist/cli/main.js`;
