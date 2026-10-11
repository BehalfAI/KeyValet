//! All paths are fixed constants, deliberately not overridable via environment variables:
//! otherwise an agent could just change the env in the MCP config and get root to run its own code.
//! Direct port of src/shared/paths.ts, updated for the Rust binary layout (no more node/dist/*.js).
//! Windows mirrors the same layout under Program Files / ProgramData, with the helper reached over
//! named pipes instead of Unix sockets.

/// Install directory (root:wheel, 0755); code inside runs as root, so it must not be writable by
/// regular users.
#[cfg(target_os = "macos")]
pub const INSTALL_DIR: &str = "/usr/local/lib/keyvalet";
/// Touch ID authentication program (hardened runtime signed); invoked after the root helper drops
/// privileges to the user.
#[cfg(target_os = "macos")]
pub const TOUCHID_BIN: &str = "/usr/local/lib/keyvalet/bin/kv-touchid";
/// sudoers rule that only allows running the helper passwordless (the helper must still pass Touch
/// ID after starting).
#[cfg(target_os = "macos")]
pub const SUDOERS_FILE: &str = "/etc/sudoers.d/keyvalet";
/// Entry point for the helper that runs as root.
#[cfg(target_os = "macos")]
pub const HELPER_BIN: &str = "/usr/local/lib/keyvalet/bin/kv-helper";
/// Credential vault directory (root:wheel, 0700).
#[cfg(target_os = "macos")]
pub const VAULT_DIR: &str = "/var/db/keyvalet";

#[cfg(target_os = "macos")]
pub const SUDO_BIN: &str = "/usr/bin/sudo";
#[cfg(target_os = "macos")]
pub const OSASCRIPT_BIN: &str = "/usr/bin/osascript";
/// Entry point for the terminal management CLI (run via /usr/local/bin/keyvalet with sudo).
#[cfg(target_os = "macos")]
pub const CLI_BIN: &str = "/usr/local/lib/keyvalet/bin/kv-cli";
/// Bundled + generated credential template catalogs (catalog.json, n8n-catalog.json). Not
/// security-sensitive (read by the unprivileged MCP server, never by the root helper), so unlike
/// the paths above it isn't part of `verify_root_environment`'s trust chain.
#[cfg(target_os = "macos")]
pub const TEMPLATES_DIR: &str = "/usr/local/lib/keyvalet/templates";
/// Runtime directory for the launchd daemon's Unix sockets (root:wheel 0755).
#[cfg(target_os = "macos")]
pub const RUN_DIR: &str = "/var/run/keyvalet";
/// Session socket for MCP servers (`kv-mcp`) and the root CLI's control queries.
#[cfg(target_os = "macos")]
pub const HELPER_SOCKET: &str = "/var/run/keyvalet/helper.sock";
/// Socket the per-user LaunchAgent connects to for prompt/hardware work.
#[cfg(target_os = "macos")]
pub const AGENT_SOCKET: &str = "/var/run/keyvalet/agent.sock";
#[cfg(target_os = "macos")]
pub const DAEMON_LABEL: &str = "dev.keyvalet.helper";
#[cfg(target_os = "macos")]
pub const AGENT_LABEL: &str = "dev.keyvalet.agent";
#[cfg(target_os = "macos")]
pub const DAEMON_PLIST: &str = "/Library/LaunchDaemons/dev.keyvalet.helper.plist";
#[cfg(target_os = "macos")]
pub const AGENT_PLIST: &str = "/Library/LaunchAgents/dev.keyvalet.agent.plist";
/// Code-signing team: the agent process must carry this identity, else a same-user process
/// could impersonate it and answer "approved" to every prompt.
#[cfg(target_os = "macos")]
pub const TEAM_ID: &str = "PWCRJPY7YC";
/// `codesign designated requirement` for kv-touchid (the agent binary shares it).
#[cfg(target_os = "macos")]
pub const AGENT_REQUIREMENT: &str =
    "identifier \"dev.keyvalet.touchid\" and anchor apple generic and certificate leaf[subject.OU] = \"PWCRJPY7YC\"";

/// Linux code/configuration is root-owned; the vault and runtime socket belong to the
/// dedicated, non-login service account. None of these paths accept environment overrides.
#[cfg(target_os = "linux")]
pub const INSTALL_DIR: &str = "/usr/local/lib/keyvalet";
#[cfg(target_os = "linux")]
pub const HELPER_BIN: &str = "/usr/local/lib/keyvalet/bin/kv-helper";
#[cfg(target_os = "linux")]
pub const CLI_BIN: &str = "/usr/local/lib/keyvalet/bin/kv-cli";
#[cfg(target_os = "linux")]
pub const MCP_BIN: &str = "/usr/local/lib/keyvalet/bin/kv-mcp";
#[cfg(target_os = "linux")]
pub const HOOK_BIN: &str = "/usr/local/lib/keyvalet/bin/kv-hook";
#[cfg(target_os = "linux")]
pub const TEMPLATES_DIR: &str = "/usr/local/lib/keyvalet/templates";
#[cfg(target_os = "linux")]
pub const VAULT_DIR: &str = "/var/lib/keyvalet";
#[cfg(target_os = "linux")]
pub const RUN_DIR: &str = "/run/keyvalet";
#[cfg(target_os = "linux")]
pub const HELPER_SOCKET: &str = "/run/keyvalet/helper.sock";
#[cfg(target_os = "linux")]
pub const OWNER_UID_FILE: &str = "/etc/keyvalet/owner.uid";
#[cfg(target_os = "linux")]
pub const SERVICE_USER: &str = "keyvalet";
#[cfg(target_os = "linux")]
pub const SERVICE_NAME: &str = "keyvalet.service";
#[cfg(target_os = "linux")]
pub const POLKIT_POLICY: &str = "/usr/share/polkit-1/actions/dev.keyvalet.policy";
#[cfg(target_os = "linux")]
pub const PKCHECK_BIN: &str = "/usr/bin/pkcheck";

/// Install directory (SYSTEM/Administrators only writable); binaries under `bin\`.
#[cfg(windows)]
pub const INSTALL_DIR: &str = r"C:\Program Files\KeyValet";
#[cfg(windows)]
pub const HELPER_BIN: &str = r"C:\Program Files\KeyValet\bin\kv-helper.exe";
#[cfg(windows)]
pub const CLI_BIN: &str = r"C:\Program Files\KeyValet\bin\kv-cli.exe";
#[cfg(windows)]
pub const MCP_BIN: &str = r"C:\Program Files\KeyValet\bin\kv-mcp.exe";
#[cfg(windows)]
pub const HOOK_BIN: &str = r"C:\Program Files\KeyValet\bin\kv-hook.exe";
/// Per-user agent executable (Windows Hello prompts and dialogs; lives in the interactive session).
#[cfg(windows)]
pub const AGENT_BIN: &str = r"C:\Program Files\KeyValet\bin\kv-agent.exe";
/// Credential vault directory (Administrators/SYSTEM only).
#[cfg(windows)]
pub const VAULT_DIR: &str = r"C:\ProgramData\KeyValet";
/// Bundled + generated credential template catalogs; not security-sensitive (same reasoning as
/// the macOS constant).
#[cfg(windows)]
pub const TEMPLATES_DIR: &str = r"C:\Program Files\KeyValet\templates";
/// Session pipe for MCP servers (`kv-mcp`) and elevated `kv-cli` control queries. One connection
/// is one session, exactly like the Unix socket.
#[cfg(windows)]
pub const HELPER_PIPE: &str = r"\\.\pipe\keyvalet-helper";
/// Pipe the per-user agent connects to for Windows Hello / dialog work (services live in
/// session 0 and cannot show UI).
#[cfg(windows)]
pub const AGENT_PIPE: &str = r"\\.\pipe\keyvalet-agent";
/// Stdio MCP launchers connect here; the service hosts the protected MCP worker separately.
#[cfg(windows)]
pub const MCP_PIPE: &str = r"\\.\pipe\keyvalet-mcp";
/// Windows service name for the helper daemon (LocalSystem).
#[cfg(windows)]
pub const SERVICE_NAME: &str = "KeyValetHelper";
/// Text SID of the user the install was done for; written by install.ps1 and read by the
/// service at startup. Session acceptance is keyed on it.
#[cfg(windows)]
pub const OWNER_SID_FILE: &str = r"C:\ProgramData\KeyValet\owner.sid";
/// Debugging escape hatch: when this (ACL-trusted) marker exists, the agent binary's signature
/// check is skipped and the acceptance is audited as `agent-accepted-unsigned`.
#[cfg(windows)]
// The client must read this non-secret policy before sending anything to an unsigned helper.
// Keep it in the readable, privileged-write installation rather than the private vault.
pub const ALLOW_UNSIGNED_AGENT: &str = r"C:\Program Files\KeyValet\allow-unsigned-agent";
/// Authenticode leaf-certificate CN the agent binary must be signed by.
#[cfg(windows)]
pub const AGENT_PUBLISHER: &str = "Simvito Limited";
