# Key protection and TPM status

[中文](key-protection.zh-CN.md)

A TPM is a small security processor that protects keys and performs operations with them. A
nonexportable private key stays inside its security boundary. Encrypted key blobs and encrypted
credentials can still be files on disk. KeyValet receives derived key material and decrypts the
vault in ordinary process memory; the complete vault does not run inside the TPM or Secure Enclave.

## View the configured scheme and current device

```sh
keyvalet status                 # JSON; protection is an alias
keyvalet status --summary       # prominent, readable protection summary
```

In an AI client, call `credential_status` or the plugin's status command. The result includes
`vault_protection` even while the session is locked. The probe uses an authenticated helper
transport, returns public metadata, and closes without authentication, unlocking or granting
access. It never returns credentials, key blobs or private keys. An unlocked session also reports
its grants. CLI status needs sudo on macOS/Linux, but does not need Touch ID, Hello or polkit key
authorization. On Windows the owner can query the running service without UAC; elevated status
reads the vault metadata directly. If the helper cannot be reached, MCP returns
`vault_protection: null` and `protection_error`, rather than guessing a protection level.
Incomplete replies also fail explicitly; an empty object is never treated as a successful report.
If the session is locked or replaced during the query, status refreshes its public state and
discards grants from the old connection.
Protection probes and credential requests must use valid UTF-8. Each line is limited to 1 MiB,
including the newline; malformed bytes are rejected before the message is processed.

The macOS, Linux and Windows installers display the same summary. Linux displays the initial
state before setup and the chosen provider afterwards, including with `--software`; `--no-setup`
and Windows `-SkipSetup` still display the actual current state. An upgrade reports the existing
provider, not a protection mode inferred from installer arguments.

## Implementations and security boundaries

| Implementation | Where key operations happen | Protection and limits |
| --- | --- | --- |
| Secure Enclave, macOS | Apple's isolated security processor | Hardware isolation; not a TPM and not the TPM interface. KeyValet requires this provider and a user-presence check, with no normal software fallback. |
| Discrete TPM (dTPM), Windows/Linux | Separate security chip | Hardware isolation and nonexportable keys when configured accordingly. Physical attack resistance depends on the device and policy. |
| Integrated TPM (iTPM), Windows/Linux | Dedicated logic integrated into a larger chip | Hardware isolation; a separate motherboard chip is not required. |
| Firmware TPM (fTPM), Windows/Linux | Firmware in a hardware-isolated CPU/security environment | Can provide hardware isolation despite the word "firmware"; not equivalent to a software emulator. |
| Virtual TPM (vTPM), virtual/cloud machines | VM infrastructure outside the guest | TPM-compatible interface; assurance depends on the hypervisor, cloud implementation and attestation. A guest device node does not establish physical hardware isolation. |
| Software TPM emulator | Ordinary host software, for example swtpm | Can expose TPM commands through supported transports, without equivalent hardware isolation. KeyValet does not launch an emulator automatically. |
| OS or file protection without TPM | Windows Hello software key storage, or KeyValet's explicit Linux software provider | OS/account/file permissions protect access; hardware protection is absent or unconfirmed. These are not interchangeable implementations of the TPM API. |
| Unknown or uninitialized | Insufficient evidence, or no configured vault | Unknown is not a safety level and is not proof of either hardware or software protection. |

These categories are not a universal ranking: hardware implementation, key policy, user
authorization, and attestation all affect security. Merely having a TPM does not mean that
KeyValet's key uses it, and a successful biometric prompt does not establish TPM backing.

## What status means

`vault_protection` retains the existing provider/recovery/binding fields and adds:

| Field | Meaning |
| --- | --- |
| `key_protection.scheme` | Configured scheme: `secure_enclave`, `windows_hello_tpm`, `windows_hello_unconfirmed`, `windows_hello_software`, `tpm2_ecdh`, `software_key_file`, `legacy_key_file`, or `uninitialized`. |
| `key_protection.hardware` | `hardware_backed` for the Secure Enclave provider; `os_reported` for successful Hello attestation recorded at creation; `software` for explicit software/legacy metadata; `unknown` when physical hardware backing is unconfirmed; `not_configured` before setup. |
| `key_protection.evidence` | Basis for that classification. Hello's creation-time attestation is an OS report, not independent certificate validation. Linux TPM metadata establishes a TPM interface, not its physical implementation. |
| `key_protection.authentication` | Key-use authorization: `secure_enclave_user_presence`, `windows_hello`, OS-level `polkit`, or `none` before setup/migration. |
| `key_protection.summary` | Localized explanation, also shown by installers. |
| `tpm.availability` | Current host observation: `detected`, `not_detected`, `unknown`, or `not_applicable` on macOS. |
| `tpm.version` | `"1.2"`, `"2.0"`, or `null` when unavailable/unknown. |
| `tpm.implementation` | `unknown` when detected: current probes cannot reliably distinguish dTPM/iTPM/fTPM/vTPM. `none` means no device was detected, not that the physical host has no TPM. |
| `tpm.evidence` | `linux_sysfs`, Windows `windows_tbs`, or `none` on macOS. Linux additionally reports whether `/dev/tpmrm0` exists as `resource_manager_present`: `true` / `false`, or `null` if the path lookup failed. |

Example: Hello can be configured while hardware backing remains unconfirmed, even if a system
TPM is detected:

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

The scheme describes stored configuration, not a live test that the key can currently be used.
Status checks the file format, supported versions, encodings and lengths of the encrypted
envelope, recovery wrapper and device binding. Malformed data produces an error. Status performs
no key operation, so valid formatting alone does not verify ciphertext integrity or the recovery
passphrase. Use `keyvalet recovery-check` to test the recovery path privately.

Linux checks registered `tpmN` devices, preferring `tpm0`.
A registered device with unreadable version information remains `detected` with a `null` version.
A visible device path or failed path lookup without a readable sysfs device remains `unknown` rather
than being classified as absent. The Linux installer uses this same report to check device availability.
Linux `tpm_backed` is `null` because vTPMs expose the same device
interface. The older `hardware_required` field indicates the provider requirement, not attested
physical hardware: it remains true for Linux TPM mode but is false for Hello and software mode.

The Windows preview targets Windows 11 24H2+ (build 26100+) and accepts unknown Hello attestation.
This is KeyValet's support target and policy, not a Windows version boundary where unknown
becomes forbidden. The current provider records `true` on successful attestation; unavailable,
failed or unsupported attestation is recorded as `null`, not as a confirmed software key. Hello
itself must work; KeyValet does not generate a replacement file key. Linux defaults to TPM 2.0
with `tpm2-tools`; no-TPM hosts must explicitly choose `--software` / `setup-software`. TPM errors
never switch a configured TPM vault to software automatically.

## Files, memory, theft and cloud keys

Copying encrypted files is different from stealing the whole computer. A thief who takes the
computer also takes its TPM. Protection then depends on disk encryption, boot integrity and the
key's authorization policy. KeyValet's Linux TPM provider currently uses OS-level polkit approval;
it does **not** bind key use to a TPM PIN or measured-boot/PCR policy. Guest/root compromise and
physical theft are not solved by that provider alone. Other providers and recovery paths also
have the limits described in [SECURITY.md](../SECURITY.md) and [Windows support](windows.md).

Derived vault keys and decrypted credentials enter process memory. The configured recovery
passphrase provides a separate offline decryption route. Neither hardware backing nor a locked
UI proves that all copies of keys/plaintext have disappeared.

Cloud KMS/HSM services are remote key-operation services; secret managers store values that
authorized applications can retrieve. Neither automatically creates a TPM device in a cloud VM.
KeyValet currently has no cloud KMS/HSM provider. A guest without `/dev/tpm0` or `/dev/tpmrm0`
cannot use KeyValet's TPM mode just because its cloud provider offers KMS.

For example, AWS NitroTPM is a virtual TPM 2.0 bound to an EC2 instance and provided by the
Nitro infrastructure; the guest accesses it through TPM commands. AWS KMS is a key service
outside the VM, accessed through network APIs; ordinary KMS keys are protected by HSMs.
NitroTPM suits local keys and boot-state policies, while KMS suits shared key management,
permissions and auditing across machines. Neither prevents a compromised authorized application
from using keys or reading decrypted secrets in process memory.

See the [cloud key protection and isolated execution research notes (Chinese)](cloud-key-protection.zh-CN.md)
for provider comparisons, KMS/TPM/enclave boundaries, multi-cloud integration, pricing and the EC2
inspection snapshot.

References: [Microsoft TPM fundamentals](https://learn.microsoft.com/en-us/windows/security/hardware-security/tpm/tpm-fundamentals),
[Hello attestation statuses](https://learn.microsoft.com/en-us/uwp/api/windows.security.credentials.keycredentialattestationstatus),
[Windows TPM device info](https://learn.microsoft.com/en-us/windows/win32/api/tbs/ns-tbs-tpm_device_info),
[Apple Secure Enclave](https://support.apple.com/guide/security/the-secure-enclave-sec59b0b31ff/web),
[tpm2-tools transports](https://tpm2-tools.readthedocs.io/en/latest/man/common/tcti/),
[BitLocker physical attack countermeasures](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/countermeasures),
[AWS NitroTPM](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/nitrotpm.html),
[AWS KMS keys](https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html).
