# Windows development status

Windows is a development preview. The service, Hello provider, UI agent and local installer are
implemented in this branch; a public Windows release still requires native Windows verification
and the Windows signing certificate. Do not infer a successful Windows runtime or hardware test
from a cross-target Rust check on macOS.

The target is Windows 11 24H2 or later (build 26100+), with Windows Hello configured for the
installing account. Current paths assume Windows is installed on `C:`. One Windows account owns
each installation. Native x64 and ARM64 builds are defined; ARM64 runtime testing is pending.
WSL is not supported yet: the Windows stdio bridge remains unimplemented.

| Area | Implementation | Verification still needed |
| --- | --- | --- |
| W1: portability and CI | Shared Rust code, Windows paths, x64 native CI and ARM64 MSVC build job | Run the changed CI on Windows; ARM64 execution |
| W2: privileged service | SCM LocalSystem service, protected vault ACL, owner SID, local named pipes, service-created agent and MCP workers, authenticated server and client process identities | Second account rejection, SCM stop/restart, ACL and process isolation checks on a clean Windows installation |
| W3: Hello and UI | `kv-agent.exe`, fixed challenge signature + HKDF, shared device binding/recovery/rotation, TaskDialog and hidden secret input | Real Hello round trip, cancelled/expired prompts, no-Hello rejection, protected process/thread access |
| W4: installation and packages | UAC installer, login launcher, client config merge, PowerShell exports, signed or explicit development x64/ARM64 ZIPs | Fresh install/upgrade/uninstall and live Claude Code/Codex/Cursor sessions; WSL bridge remains open |
| W5: distribution | Manual artifact workflow with signing required by default | Certificate provisioning, hardware matrix, SmartScreen observation, maintainer publication |

## Build and try a local development package

Use a Windows development machine with stable Rust, Visual Studio C++ build tools and the Windows
SDK. Add the ARM64 C++ tools when building that target. Enable Windows Hello first. Build from
the repository root in PowerShell; the tag must match `rust/crates/kv-cli/Cargo.toml`:

```powershell
rustup target add x86_64-pc-windows-msvc
.\scripts\package-windows.ps1 -Tag v0.2.1 -Architecture x64 -AllowUnsigned
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\install.ps1 `
    -PackagePath .\dist\keyvalet-v0.2.1-windows-x64.zip -AllowUnsignedAgent
```

Start installation from the intended account's **unelevated** interactive PowerShell. UAC handles
only the system phase. The original user then gets the MCP/hook configuration and Hello setup.
If installation starts elevated, sign out and back in before running setup from an elevated
terminal. The installer does not create a Hello key as SYSTEM or as a different UAC account.
An existing vault owner cannot be silently changed by rerunning the installer as another account.

Unsigned development requires the explicit installer switch; an unsigned archive alone does not
enable it. The protected `C:\Program Files\KeyValet\allow-unsigned-agent` marker records the choice.
It changes the reported `agent_trust` to `unsigned`. Installing a signed package without that
switch removes the marker. Ordinary users cannot create a valid marker in the protected installation.
This non-secret marker is readable by clients so they can verify the helper before sending data;
the vault and device binding files retain their private ACLs.

For a signed build, replace `-AllowUnsigned` with
`-SigningCertificateThumbprint <certificate-thumbprint>`, then install without
`-AllowUnsignedAgent`. Every executable must have valid Authenticode with leaf publisher CN
`Simvito Limited`. The workflow is **Actions → Windows package → Run workflow**; it uploads
artifacts, without publishing a release. Signed runs use the protected `release` environment's
`WINDOWS_SIGNING_PFX_BASE64` and `WINDOWS_SIGNING_PFX_PASSWORD` secrets. Windows uses its own
certificate, separate from the macOS Developer ID credentials.

The online installer can verify a published ZIP against the release's `SHA256SUMS`, but those
Windows assets must first be attached to a release and their checksum entries merged with the
macOS entries. Each package job emits `SHA256SUMS-windows-x64` or `SHA256SUMS-windows-arm64` to
avoid overwriting another architecture. Until publication, use `-PackagePath` as above.

## Operation and recovery

Run administrative CLI commands in an elevated terminal. UAC can use a separate administrator
account; Hello still runs as the recorded vault owner in the original interactive session:

```powershell
& 'C:\Program Files\KeyValet\bin\kv-cli.exe' setup-hello
& 'C:\Program Files\KeyValet\bin\kv-cli.exe' protection
& 'C:\Program Files\KeyValet\bin\kv-cli.exe' hello-test
& 'C:\Program Files\KeyValet\bin\kv-cli.exe' rotate-recovery
```

`keyvalet.ps1` in the install bin directory provides a UAC wrapper for interactive CLI use. Use
`kv-cli.exe` directly in the elevated terminal when input/output must stay in that terminal.
`keyvalet status --summary` (or `kv-cli.exe status`) is the read-only exception: the owner can
query the authenticated service without UAC or Hello. The installer prints this summary in the
original console after setup, including when `-SkipSetup` leaves the vault uninitialized.
Recovery passphrases go through hidden terminal input or native secret input, never a CLI argument
or the AI chat. `recover-vault` rebinds using the recovery passphrase and a new Hello key;
`recovery-read list` or `recovery-read get <type> <name>` provides emergency read-only recovery.
Rotation refuses to proceed while helper sessions exist. Close or lock all clients first.

`status` / `protection` report `provider: "windows_hello"`, recovery configuration and device binding.
`key_protection` describes the scheme, hardware evidence and Hello authorization; `tpm` reports
the current system device through TBS, without inferring physical vs virtual implementation.
The creation-time Hello attestation and current device detection are separate. A detected system
TPM does not prove that this key uses it. See the [protection matrix and fields](key-protection.md).
`tpm_backed: true` means the OS returned successful key attestation. `null` means unknown, not
proof that the device lacks a TPM; this preview does not independently validate attestation
certificates. Windows Hello may use OS-managed software protection when a TPM is absent. KeyValet
currently accepts unknown attestation on its supported Windows 11 24H2+ target, displaying
`hardware: "unknown"` prominently. This is an application policy, not a Windows-version rule that
permits or forbids unknown. Successful recorded attestation displays `hardware: "os_reported"`;
KeyValet does not claim independent verification. `hardware_required` is false for this provider.
KeyValet requires Hello and does not generate a `master.key` fallback. It rejects signatures that do not
verify as RSA-2048 PKCS#1 v1.5/SHA-256, rather than deriving an unstable key from a different format.
The implementation follows the signing flow in Microsoft's
[Windows Hello guidance](https://learn.microsoft.com/en-us/windows/apps/develop/security/windows-hello).

The vault and audit log live in `C:\ProgramData\KeyValet`, with access restricted to SYSTEM and
Administrators. Recovery depends on the recovery passphrase and the encrypted vault. The device
binding files add a separate privileged local secret; a copied `vault.enc` and a Hello signature
alone cannot decrypt a bound vault. Do not expose the binding files to an unprivileged client.
Administrators/SYSTEM remain outside the protection boundary.

`KeyValetAgent` is a login **launcher**. It asks `KeyValetHelper` to start the real UI worker using
the interactive owner's WTS token. The service assigns restricted process/thread descriptors
before that worker starts, retains its process handle and accepts only that child PID. The
worker's executable must also pass owner SID, installation path, ancestor ACL and publisher
checks. Its token descriptor disallows changing the protected default DACL of subsequent worker
threads. Creation-time mitigation attributes disable legacy extension points/global hook DLLs,
dynamic code and non-Microsoft DLL loading, using Microsoft's
[process attribute API](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute).
This must be tested with
WinRT/Hello on a real Windows desktop; Rust type checks do not establish compatibility of those
restricted descriptors with every OS component. The service restarts a crashed worker or a
worker whose broker connection has expired, so a late Hello response cannot leave a permanently
retired agent in place. Reopen/reauthenticate credential sessions after an agent restart. A worker
enters an unnamed, non-inherited Job Object during process creation. Its kill-on-close policy
also terminates the process tree if the helper crashes; see Microsoft's
[Job Object lifecycle](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects).
Closing the service terminates the child. An ordinary invocation of `kv-agent.exe` only launches it;
`--serve` started outside the service is rejected by the helper. Privileged confirmations also
require a fresh signature against the pinned Hello key after the purpose dialog; desktop button
automation alone cannot approve them. Workers require an unelevated owner token with UAC enabled.
Hello operations share one 120-second request budget (shorter than the helper's 130-second
deadline); expired WinRT operations are cancelled. A new key is removed if credential retrieval,
public-key validation, metadata creation or initial signing fails. Approval requests with missing
or invalid pinned metadata do not open a dialog or invoke Hello.
These process restrictions are not VBS/PPL isolation or a secure input desktop. The generic
secret-entry dialog uses the ordinary interactive desktop; protection against same-desktop
keyboard/screen monitoring is not established by this preview and needs separate validation.

Before listening, the service grants the recorded owner only process query-limited and token
query rights, allowing clients to verify its kernel PID, SYSTEM SID, installed path and publisher
without administrator/debug privileges. Token duplication, impersonation and adjustment remain
denied to that owner. Windows checks the token DACL separately from the process DACL; see
[access-token object rights](https://learn.microsoft.com/en-us/windows/win32/secauthz/access-rights-for-access-token-objects).
Signature verification is bounded and happens before any client protocol bytes are sent.

MCP clients run `C:\Program Files\KeyValet\bin\kv-mcp.exe` as a stdio launcher. The authenticated
SYSTEM service starts a separate protected `kv-mcp.exe --worker` in the owner's interactive
session, with the same process/thread/token restrictions as the Hello agent. A private random
named pipe accepts only the retained child PID. The service relays the MCP stream; native secret
input and imported private files are handled inside the worker. Only the project directory,
language, session TTL (zero or at most one year) and requested grant mode are forwarded from the launcher; its environment,
executable and claimed session identity cannot select the worker. Raw values deliberately
requested with `credential_get` still reach the MCP client under the normal authorization policy.
Client EOF closes the whole channel, locks the helper session and removes session files. A stuck
worker is terminated, followed by a protected cleanup process; startup also purges dead creators.

The installer merges Claude Code, Codex and Cursor configuration, backs up existing files to
`.bak-keyvalet`, preserves unrelated MCP servers/hooks and sets Cursor hook schema version 1.
JSON updates use atomic replacement. Mixed user/KeyValet hook rows retain their user commands;
invalid hook schemas are refused without replacing the existing configuration. Before extraction,
the installer checks a single version/architecture root, required files, case-insensitive duplicate
names, path traversal, reserved Windows names, ZIP links and expansion limits. Every executable
must have a matching x64/ARM64 PE32+ header even in unsigned development mode. Upgrades validate
existing owner-record/binary ACLs and service configuration before stopping the running service.
An existing Codex `mcp_servers.keyvalet` table is kept and must be reviewed if its command is stale.
An upgrade stops existing installed agent/MCP processes. Restart clients after installation,
and trust Codex hooks with `/hooks` before expecting them to
run. Slash-command/plugin distribution for Windows is a separate follow-up; MCP and hooks are
configured directly by this installer.

Gateway exports are PowerShell `.ps1` files. Use the returned instruction in PowerShell:

```powershell
. 'C:\Users\you\.keyvalet\run\<generated-file>.ps1'; <your-command>
```

Session files have protected owner-only ACLs from creation, pin their private directory handles
and use create-new filenames. Locking deletes the actual created files by handle and blocks late
writes; startup removes files whose creator PID is dead or reused. Explicit plaintext exports
remain readable by the owning account while the session is active. Gateway TCP clients are
checked against that account's SID using the **client source port**, before bearer-token handling.

Close AI clients before uninstalling. Run `scripts/uninstall.ps1` from an elevated terminal. It
removes the service, task and executables; the vault is retained unless `-RemoveVault` is supplied.
It prints the remaining user-config/PATH cleanup steps rather than removing unrelated settings.

## Validation before a public Windows release

Rust unit tests and offline script checks run without an installed KeyValet, elevation, a desktop
session or real Hello.
They include synthetic Hello vault unlock/recovery/rotation, framed agent replies, pipe identity
checks, SID parsing, loopback identity, private export ACL rejection and PID-reuse cleanup. The
launch protocol rejects extra environment/executable/session parameters, and relay tests require
client EOF to terminate an open worker stream. Handshake schemas reject duplicate fields directly
from the original JSON frame. Tests cover byte-wise slow peers, deadlines that include flushing,
short writes, I/O failures and draining buffered output at worker EOF. Agent-channel tests cover
late approvals after timeout/cancellation, concurrent replies arriving out of order, unknown
payload IDs containing JSON-like bytes, and revocation when an agent connection is replaced.
They also require disconnect/cancellation to clear pending requests, reject binary key frames
as authentication or confirmation approvals, and strictly pin decoded Hello response metadata.
Aligned Win32 buffer and SID parsing tests run on every Rust test host, covering initialized
prefixes, arithmetic overflow, unaligned structures, invalid SID pointers and truncated counts.
Portable Hello tests cover deterministic RSA/HKDF,
corrupt/replaced public keys and signatures, incompatible padding, invalid requests, cancellation,
backend failures, shared prompt deadlines, creation cleanup and raw-payload boundaries. Synthetic
Hello vault tests check that cancelled or inconsistent setup/recovery/rotation preserves existing
data, broken binding files are rejected before prompting, copied vaults require binding or explicit
recovery, and valid-looking metadata edits cannot bypass ciphertext authentication. Native
Windows tests use filtered tokens with `AccessCheck` to verify process/thread/token permissions
and create a disposable child to verify Job Object membership and kill-on-close.
The PowerShell test parses installers without running their system actions and exercises config
merging, Unicode, backups, atomic writes, quoting, malformed archives/checksums and PE headers;
CI runs it under PowerShell 7 and Windows PowerShell 5.1.
Environment export rendering is tested without Windows or filesystem access. Scripts use a UTF-8
BOM for [Windows PowerShell 5.1 Unicode compatibility](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_character_encoding)
and escape [PowerShell's smart single quotes](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_quoting_rules).
NUL-containing values and malformed variable names are rejected before creating a file. Windows
CI explicitly runs an opt-in subprocess test with both PowerShell engines: it executes Rust-rendered
scripts containing synthetic Unicode, multiline values and attempted quote injections, checking
that values survive exactly and the injected code does not run. On a development host with
PowerShell installed, run it without installing KeyValet or requesting elevation:

```sh
cd rust
KEYVALET_TEST_POWERSHELL=pwsh cargo test -p kv-mcp windows_script::tests::powershell_executes_export_fixture --locked -- --ignored --exact
```

The Windows CI job separately invokes `scripts/test-windows-service.ps1` on a disposable clean
runner, with explicit system-change authorization. It builds a development ZIP from the tested
binaries and checks installation, the real SYSTEM service/pipe peer, no-Hello public status from
a newly created standard test account without administrator/debug privileges,
untrusted file ACL rejection before service stop, wrong-owner refusal, upgrade, SCM restart and
uninstall with vault retention/removal. Its JSON report is uploaded as an artifact. This integration
script refuses any existing KeyValet installation/task/service/vault and removes its temporary
local account/profile during cleanup. It does not create a Hello
key. To run it on a **clean disposable** Windows 11 test machine, from an elevated terminal:

```powershell
cd rust
cargo build --workspace --locked
cd ..
.\scripts\test-windows-service.ps1 -AllowSystemChanges
```

After its cleanup, install a development package normally as the intended unelevated owner to
exercise the interactive Hello and MCP paths. A hosted Windows Server CI result does not replace
Windows 11 desktop/Hello testing. Native integration results are pending until these checks run.

On each real target record the Windows build, CPU architecture, Hello method, signing status and
TPM/attestation result, then check:

- New setup, unlock, cancellation/timeout, missing Hello/key and public-key replacement rejection;
  recovery read-only mode, rebind, rotation and stale-session revocation.
- SYSTEM service boot/stop/restart, agent crash/restart and MCP client disconnect/crash; ordinary same-user processes cannot
  obtain VM-read/write, remote-thread, thread-context or DACL-write access to the service child.
  They cannot change its token default DACL or inject through a third-party/global hook DLL.
  WinRT/TaskDialog/Hello still work with those restrictions, in signed and unsigned test packages.
- MCP native secret input/import stays inside the protected worker; project cwd, language and
  grant mode reach it correctly. Stdout remains valid MCP JSON, with no worker handshake leakage;
  EOF and service stop revoke helper sessions and clean exported files even after worker failure.
- A second local account cannot connect to any service pipe or use the gateway. A squatted pipe cannot
  collect any protocol/key data; an unsigned or externally launched agent is rejected and audited.
- Fresh install (including a standard owner with separate UAC administrator credentials),
  same-owner upgrade, wrong-owner refusal, Unicode paths/configuration, hooks in
  live Claude Code/Codex/Cursor, PowerShell gateway/secret files, lock cleanup and uninstall.
- Signed x64 + ARM64 packages, signature revocation behavior and actual SmartScreen behavior.
  WSL waits for the stdio bridge.

The interactive key test is opt-in, from an unelevated Windows 11 terminal with Hello enabled:

```powershell
cd rust
cargo test -p kv-agent hardware_roundtrip -- --ignored --nocapture
```

The protected SCM-launched worker needs a separate installed end-to-end test; the opt-in key
test alone does not exercise service process isolation. No hardware result is recorded yet.
