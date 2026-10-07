//! All paths are fixed constants, deliberately not overridable via environment variables:
//! otherwise an agent could just change the env in the MCP config and get root to run its own code.
//! Direct port of src/shared/paths.ts, updated for the Rust binary layout (no more node/dist/*.js).

/// Install directory (root:wheel, 0755); code inside runs as root, so it must not be writable by
/// regular users.
pub const INSTALL_DIR: &str = "/usr/local/lib/keyvalet";
/// Touch ID authentication program (hardened runtime signed); invoked after the root helper drops
/// privileges to the user.
pub const TOUCHID_BIN: &str = "/usr/local/lib/keyvalet/bin/kv-touchid";
/// sudoers rule that only allows running the helper passwordless (the helper must still pass Touch
/// ID after starting).
pub const SUDOERS_FILE: &str = "/etc/sudoers.d/keyvalet";
/// Entry point for the helper that runs as root.
pub const HELPER_BIN: &str = "/usr/local/lib/keyvalet/bin/kv-helper";
/// Credential vault directory (root:wheel, 0700).
pub const VAULT_DIR: &str = "/var/db/keyvalet";

pub const SUDO_BIN: &str = "/usr/bin/sudo";
pub const OSASCRIPT_BIN: &str = "/usr/bin/osascript";
/// Entry point for the terminal management CLI (run via /usr/local/bin/keyvalet with sudo).
pub const CLI_BIN: &str = "/usr/local/lib/keyvalet/bin/kv-cli";
/// Bundled + generated credential template catalogs (catalog.json, n8n-catalog.json). Not
/// security-sensitive (read by the unprivileged MCP server, never by the root helper), so unlike
/// the paths above it isn't part of `verify_root_environment`'s trust chain.
pub const TEMPLATES_DIR: &str = "/usr/local/lib/keyvalet/templates";
