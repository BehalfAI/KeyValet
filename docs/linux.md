# Linux support

The local Linux implementation uses a systemd service running as the non-login system user
`keyvalet`, a Unix socket with kernel peer credentials, and polkit for independent user
authorization. The Rust MCP server, CLI, hooks, proxy, streaming gateway and protocol engines
run natively. Linux does not use the macOS passwordless sudo helper path.

## Install

The supported build is GNU/Linux on x86_64 or aarch64, with systemd, polkit and sudo. Ubuntu
22.04 and Debian 12 have CI jobs; Ubuntu 24.04 x86_64 is the current real-machine test target.
ARM64 packaging is defined but has not been tested on ARM64 hardware. Native archives require
the builder's glibc baseline: the archive tested on `ndu` requires glibc 2.39 (Ubuntu 24.04);
the x64 packaging workflow builds on Ubuntu 22.04, while ARM64 builds on Ubuntu 24.04.
Build from source on an older supported distribution. Public Linux release
archives have not yet been published; install the current source checkout with stable Rust and
a C compiler:

```sh
# Ubuntu / Debian
sudo apt install build-essential pkg-config sudo policykit-1 tpm2-tools
sh scripts/install.sh
```

Run the installer as the regular user who will own the vault. It uses sudo to install trusted
code, create the system account and register the service, then initializes a TPM vault. Keep
the separately entered recovery passphrase offline. Installation displays the protection
summary; `keyvalet status --summary` displays it again without unlocking the vault.

When there is no TPM 2.0, software protection requires an explicit choice:

```sh
sh scripts/install.sh --software
# After an installation made with --no-setup:
keyvalet setup-software
```

Software setup is refused when a TPM 2.0 is detected. Missing TPM permissions, broken TPM tools,
bad metadata or a failed hardware operation never select software automatically. An existing
software vault remains software on upgrade; use `keyvalet setup-tpm` to migrate it after adding
a working TPM. This rotates the vault key and recovery passphrase.

`--no-setup` installs without initializing a vault; `--no-register` skips AI client configuration.
Re-running the installer preserves the configured provider and vault. The installer registers
Claude Code when available, installs hooks for detected Codex, Cursor and Grok configurations,
and installs the Cursor plugin and a Devin MCP configuration when appropriate. Existing custom
configuration is preserved. Devin's commands and hooks use the repository's Devin plugin.
For another MCP client, configure the stdio command
`/usr/local/lib/keyvalet/bin/kv-mcp`.

## Desktop and SSH approval

A desktop session needs a running polkit authentication agent. Polkit's PAM configuration
decides whether the login password or a fingerprint is accepted. The three KeyValet actions
use `auth_self`, without a retained authorization: unlock, credential use and sensitive changes
are checked independently by the service. Existing grant modes determine when use approval is
needed; each new connection still requires fresh unlock authorization.

For SSH, run this in a separate terminal belonging to the vault owner:

```sh
keyvalet approve <kv-mcp-pid>
```

This registers `pkttyagent` for that MCP process and its start time. The login password belongs
in the polkit agent's terminal, never in chat or a KeyValet secret-entry dialog. Without an agent,
denied or canceled authentication fails closed. There is no confirmation-code fallback.
Secret entry uses Zenity on a desktop (install `zenity`), or hidden input on `/dev/tty`; it never
consumes MCP's JSON stdin. A detached client without a terminal or desktop cannot collect a
secret interactively; use the terminal CLI to add it first.

OAuth opens a browser with `xdg-open` when available, otherwise prints the authorization URL to
the user's terminal. For a localhost OAuth callback over SSH, forward the callback port or use
a provider's device-code flow. Clipboard tools (`wl-copy` or `xclip`) are optional.

## Protection and recovery

TPM mode creates a P-256 ECDH key using trusted `tpm2-tools` executables and the kernel resource
manager `/dev/tpmrm0`. The child object's `fixedTPM` and `fixedParent` attributes prohibit
migration. Its encrypted public/private blobs and a public peer point are stored in authenticated
vault metadata; the private scalar is never exported. The derived secret crosses an anonymous
pipe and is expanded with HKDF-SHA256. No persistent TPM handle, PCR binding, TPM clearing or
firmware changes are needed.

The TPM enforces device binding, while polkit supplies user authorization. This implementation
does not put a user-presence, PIN or PCR policy into the TPM key. Root, a compromised service,
or someone with the necessary blobs and TPM access can use it without polkit. The derived AES
key and decrypted records enter service memory. A firmware TPM such as Intel PTT can provide
hardware isolation; a device node alone does not prove the host's physical implementation.
See the [protection matrix](key-protection.md) for the distinction between detection and evidence.

Software mode stores a random key outside `vault.enc`, in a digest-named `0600` file in the
service's `0700` directory. Metadata contains only its digest. It depends on service-account
and filesystem isolation, not TPM hardware. Both modes mix a separate local device-binding
secret into the vault key. Linux backup tools do not automatically exclude these files: a full
directory backup includes them. Protect backups and keep the recovery passphrase separately.

```sh
keyvalet tpm-test                   # Hardware round trip; vault unchanged
keyvalet recovery-check             # Verify passphrase without hardware or printing values
keyvalet recovery-read list         # Audited read-only recovery
keyvalet rotate-recovery            # Rotate provider key, vault key and recovery passphrase
keyvalet recover-vault              # Recover and bind a fresh TPM key
keyvalet recover-vault --software   # Explicit recovery on a machine without TPM
```

Recovery uses the encrypted vault and passphrase independently of the original TPM and binding
file. Rotation invalidates the old passphrase for the current vault, while old backups still
accept their old passphrases. Maintenance refuses active helper sessions. Writes from the root
CLI retain service ownership, and superseded software and device-binding keys are removed
after a successful commit.

## Installed boundaries

| Path / identity | Ownership and use |
| --- | --- |
| `/usr/local/lib/keyvalet` | Root-owned binaries and templates, checked before use |
| `/var/lib/keyvalet` | `keyvalet`, `0700`; vault, settings, audit and local key files |
| `/run/keyvalet/helper.sock` | Service socket; only the configured owner's kernel UID receives credential sessions; root receives control queries only |
| `/etc/keyvalet/owner.uid` | Root-owned owner configuration; client-supplied UID/PID is ignored |
| `keyvalet.service` | Non-login service account; no capabilities, no new privileges, restricted filesystem access and core dumps disabled |
| `dev.keyvalet.unlock/use/modify` | Polkit verifies the socket peer's PID, start time and UID |

The AI user's ability to obtain root defeats this boundary. Do not give the AI account
passwordless general-purpose sudo. The MCP process disables core dumps and same-user ptrace;
that does not isolate the entire interactive desktop or a compromised OS.

`sh scripts/uninstall.sh` stops and removes the service and installed code, preserving the vault,
owner configuration and service account. `--purge` asks for explicit confirmation before
deleting the vault and owner configuration; the non-login service account is retained. WSL can
run this independent Linux service when systemd and polkit are available; access to a Windows
vault through a WSL bridge remains a separate pending feature.

## Verification

Routine CI needs no installed KeyValet, root, GUI or TPM: format, strict clippy, locked workspace
build and all workspace tests run as a regular user. Hardware tests are ignored by default.

### Unit-test coverage

From the repository root on Linux:

```sh
rustup component add llvm-tools-preview
sh scripts/test-linux-coverage.sh
```

The script runs locked workspace tests and writes `summary.md`, `coverage.json` and `lcov.info`
to `rust/target/linux-coverage`. Set `KV_COVERAGE_DIR` to change the report directory and
`KV_LLVM_BIN` for an explicitly installed matching LLVM toolset. Python 3 is required.
Ubuntu 22.04 and Debian 12 CI upload these reports as artifacts. Failed tests fail the coverage
step too, and their status is retained in the report. Every reported module must have exactly
100% production line coverage; missing source files or empty counters also fail the step.

The summary measures production lines in Linux key protection, kernel peer identity, daemon
startup and terminal management, plus shared master-key metadata. Unit tests and their fixtures
live in separate module files and do not enter these production-line counts.

The 2026-10-10 expansion covers approval identity and revocation, child
exit/timeout/cancellation, NSS lookup errors, private file ownership and permissions,
software-key cleanup, TPM creation/unlock and file-write failures, workspace cleanup,
metadata corruption and device-binding mismatches. Daemon tests cover startup policy,
lock/socket errors, session limits, root control queries, disconnects and shutdown. CLI tests
cover executable trust, target-process ownership, home lookup and terminal failures.
Private system interfaces let the same production paths run against temporary files,
Unix sockets and controlled child processes. TPM command fixtures exercise metadata and
key derivation without installing binaries, creating service accounts or accessing hardware.
Signal and exec fixtures run in subprocesses so they cannot affect the test runner; their
parent tests invoke them automatically even though the child entry points are marked ignored.

Measured on `ndu` with native Rust 1.99.0, excluding test code:

| Production module | Previous report | Current production lines | Coverage |
| --- | ---: | ---: | ---: |
| Key protection and polkit (`kv-platform/src/linux.rs`) | 65.67% | 557/557 | 100.00% |
| Kernel peer identity (`kv-platform/src/peer_linux.rs`) | 93.55% | 65/65 | 100.00% |
| Daemon startup (`kv-helper/src/daemon_linux.rs`) | 41.07% | 146/146 | 100.00% |
| Terminal management (`kv-cli/src/linux_cli.rs`) | 35.25% | 160/160 | 100.00% |
| Shared master-key metadata (`kv-vault/src/master_key.rs`) | 96.48% | 235/235 | 100.00% |

The final coverage run covers all 1,163 measured production lines and passes 631 workspace tests,
with six hardware, environment or subprocess-fixture entry points ignored by the top-level runner.
The matching format, strict clippy and locked build checks pass; macOS regression passes 583 tests
with four ignored. Native LLVM 23 reports 18 zero-hash profile mismatches in `base64ct`, `rand` and
`tokio`; none belong to these five measured modules. Real polkit/PAM, physical TPM and GUI behavior
need their integration checks in addition to these isolated unit tests. The physical TPM
round-trip and corrupted-key rejection test also passes separately on `ndu`.

The TPM integration test can be run on a TPM 2.0 host as root or a user with device access:

```sh
cargo test -p kv-platform tpm_round_trip -- --ignored
```

Real-machine verification uses synthetic credentials only. See the acceptance record below;
desktop fingerprint approval, ARM64 hardware and live AI client UI remain additional release
matrix checks.

### Acceptance record — 2026-10-10

Host: `ndu`, Ubuntu 24.04.4 / kernel 6.8.0, x86_64, MSI MPG Z790 EDGE WIFI and Core i9-13900K.
Sysfs and TPM commands report TPM 2.0, manufacturer `INTC`, firmware 600.18; the platform and
vendor indicate Intel PTT. BIOS H.10 is dated 2022-11-15. These observations establish a
working TPM interface on this host; they are not certificate-based hardware attestation.

| Check | Result |
| --- | --- |
| Native Rust 1.99 format, strict clippy, locked build and tests | Passed; 461 Linux tests after removing the installation, vault, service account and rules; three environment-dependent tests ignored. macOS regression checks also pass |
| Real TPM test, including a corrupted private blob with a software key present | Passed; no hardware fallback |
| Install / upgrade / uninstall and reinstall, service ownership, systemd sandbox and owner configuration | Passed; default uninstall preserves the synthetic vault and reinstall opens it; no real AI client configuration touched |
| Runtime configuration | Passed in an isolated home: valid JSON, user ownership, idempotence and custom-file preservation |
| Installed native MCP initialize, tool discovery, locked protection probe, unlock, grant, get, lock and EOF | Passed with synthetic credentials and temporary PID-scoped test authorization |
| Independent polkit password authentication | Passed with a temporary Unix account: separate real PAM unlock, use and modify approvals; account removed afterwards |
| Owner's SSH agent and cancellation | Password prompt appears for the non-dumpable MCP process; cancellation refuses access |
| Forged approval/UID, foreign UID, per-use parameter changes and replay | Refused; audit records kernel UID/PID and omits credential values |
| Gateway peer UID, bad token, hostile Host, proxy-only and disconnect | Passed; foreign user disconnected, owner reaches validation, EOF closes the listener |
| Maintenance during active sessions | Refused |
| TPM recovery check/read, rotation, old-passphrase rejection and fresh-key recovery | Passed; files retain service ownership |
| No TPM / broken TPM | Private mount namespaces only: default setup refuses, explicit software setup and service use pass, rotation/recovery pass, broken TPM refuses despite a software key being present |
| Linux x64 archive and checksum | Native archive built and SHA-256 verified; glibc 2.39 baseline |

No real credentials, TPM persistent handles, TPM clearing, BIOS changes or the owner's login
password were used. Temporary polkit rules, users and isolated state were removed. `guang`
currently has passwordless general-purpose sudo, so this host does not demonstrate isolation
from that account obtaining root. Desktop fingerprint, ARM64 hardware, older-distribution CI
runs, signed public distribution and live AI client UI remain unverified.
