//! Public protection information only: no key operations, authentication or secret values.
use kv_vault::{ProtectionStatus, Vault};
use serde_json::{json, Value};
#[cfg(any(target_os = "linux", test))]
use std::path::Path;

pub fn status(vault: &Vault) -> kv_vault::Result<Value> {
    let protection = vault.protection()?;
    let mut report = serde_json::to_value(&protection)?;
    report["key_protection"] = describe(&protection);
    report["tpm"] = detect_tpm();
    Ok(report)
}

/// Allows the Windows owner to view public metadata without an elevation or Hello prompt.
#[cfg(windows)]
pub async fn service_status() -> std::io::Result<Value> {
    use tokio::io::AsyncWriteExt;
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        // This verifies the kernel-reported server PID, SYSTEM token and installed executable.
        let mut pipe = crate::pipe::connect_service(crate::paths::HELPER_PIPE).await?;
        let message = kv_ipc::ProtectionProbe::Status {
            protocol: kv_ipc::PROTOCOL_VERSION,
            lang: Some(kv_i18n::lang().as_str().to_string()),
        };
        let mut line = serde_json::to_vec(&message)?;
        line.push(b'\n');
        pipe.write_all(&line).await?;
        read_probe_response(pipe).await
    })
    .await
    .map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "Protection status probe timed out",
        )
    })?
}

/// Read one bounded public-metadata response from an already verified helper connection.
pub async fn read_probe_response<R: tokio::io::AsyncRead + Unpin>(
    reader: R,
) -> std::io::Result<Value> {
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};
    let mut reader = BufReader::new(reader.take((kv_ipc::MAX_LINE_BYTES + 1) as u64));
    let mut line = Vec::new();
    let size = reader.read_until(b'\n', &mut line).await?;
    if size > kv_ipc::MAX_LINE_BYTES || line.last() != Some(&b'\n') {
        return Err(std::io::Error::other("Invalid protection status response"));
    }
    match serde_json::from_slice::<kv_ipc::Response>(&line) {
        Ok(kv_ipc::Response::Ok { id: 0, result, .. })
            if result["protocol"] == kv_ipc::PROTOCOL_VERSION =>
        {
            validate_report(&result["vault_protection"])?;
            Ok(result["vault_protection"].clone())
        }
        Ok(kv_ipc::Response::Err { id: 0, error, .. }) => Err(std::io::Error::other(error)),
        _ => Err(std::io::Error::other(
            "Protection status unavailable; reinstall matching KeyValet components",
        )),
    }
}

/// Missing or malformed metadata must be an error, rather than a successful security report.
/// Used for both the startup probe and the protection view embedded in sessionInfo.
pub fn validate_report(report: &Value) -> std::io::Result<()> {
    fn text_field(value: Option<&Value>) -> bool {
        value
            .and_then(Value::as_str)
            .is_some_and(|text| !text.trim().is_empty())
    }
    let key = &report["key_protection"];
    let tpm = &report["tpm"];
    let valid = text_field(report.get("provider"))
        && report
            .get("tpm_backed")
            .is_some_and(|value| value.is_null() || value.is_boolean())
        && [
            "recovery_configured",
            "device_binding",
            "migration_backup_present",
            "legacy_key_present",
            "hardware_required",
        ]
        .iter()
        .all(|field| report.get(field).is_some_and(Value::is_boolean))
        && [
            "scheme",
            "hardware",
            "evidence",
            "authentication",
            "summary",
        ]
        .iter()
        .all(|field| text_field(key.get(field)))
        && text_field(tpm.get("implementation"))
        && text_field(tpm.get("evidence"))
        && matches!(
            tpm["availability"].as_str(),
            Some("detected" | "not_detected" | "unknown" | "not_applicable")
        )
        && tpm.get("version").is_some_and(|version| {
            version.is_null() || matches!(version.as_str(), Some("1.2" | "2.0"))
        })
        && tpm
            .get("resource_manager_present")
            .is_none_or(|value| value.is_boolean() || value.is_null());
    if valid {
        Ok(())
    } else {
        Err(std::io::Error::other(
            "Incomplete or invalid protection status; reinstall matching KeyValet components",
        ))
    }
}

fn describe(status: &ProtectionStatus) -> Value {
    let (scheme, hardware, evidence, authentication, zh, en) = match status.provider {
        "secure_enclave" => (
            "secure_enclave", "hardware_backed", "secure_enclave_provider", "secure_enclave_user_presence",
            "Secure Enclave 硬件保护；密钥使用要求 Touch ID 或系统密码。",
            "Secure Enclave hardware protection; key use requires Touch ID or the system password.",
        ),
        "windows_hello" => match status.tpm_backed {
            Some(true) => (
                "windows_hello_tpm", "os_reported", "hello_attestation_at_creation", "windows_hello",
                "Windows Hello；系统在创建密钥时报告 TPM 证明成功，KeyValet 未独立验证证明证书。",
                "Windows Hello; the OS reported successful TPM attestation at key creation. KeyValet has not independently validated its certificates.",
            ),
            Some(false) => (
                "windows_hello_software", "software", "hello_metadata", "windows_hello",
                "Windows Hello 软件密钥保护；没有已确认的 TPM 硬件隔离。",
                "Windows Hello software key protection; no confirmed TPM hardware isolation.",
            ),
            None => (
                "windows_hello_unconfirmed", "unknown", "hello_attestation_unavailable", "windows_hello",
                "Windows Hello；密钥是否由 TPM 硬件保护尚未确认，可能使用系统软件保护。",
                "Windows Hello; TPM hardware protection of this key is unconfirmed. OS software protection is possible.",
            ),
        },
        "tpm2" => (
            "tpm2_ecdh", "unknown", "tpm_interface_only", "polkit",
            "TPM 2.0 ECDH 设备密钥；物理、固件或虚拟实现未确认。polkit 是系统层授权，未配置 TPM PIN 或启动状态绑定。",
            "TPM 2.0 ECDH device key; physical, firmware or virtual implementation unconfirmed. Authorization uses OS-level polkit, without a TPM PIN or boot-state policy.",
        ),
        "software_key" => (
            "software_key_file", "software", "software_key_provider", "polkit",
            "软件保护：密钥保存在受权限保护的文件中；没有 TPM 硬件隔离，管理员可读取密钥。",
            "Software protection: the key is stored in a permission-protected file. There is no TPM hardware isolation; administrators can read the key.",
        ),
        "migration_required" => (
            "legacy_key_file", "software", "legacy_vault", "none",
            "旧文件密钥方案；必须迁移后才能正常使用。",
            "Legacy file-key protection; migration is required before normal use.",
        ),
        _ => (
            "uninitialized", "not_configured", "none", "none",
            "凭证库尚未初始化；没有已配置的密钥保护方案。",
            "The vault is not initialized; no key protection scheme is configured.",
        ),
    };
    json!({
        "scheme": scheme,
        "hardware": hardware,
        "evidence": evidence,
        "authentication": authentication,
        "summary": kv_i18n::t(zh, en),
    })
}

#[cfg(target_os = "linux")]
fn detect_tpm() -> Value {
    linux_tpm(Path::new("/sys/class/tpm"), Path::new("/dev/tpmrm0"))
}

#[cfg(any(target_os = "linux", test))]
fn linux_tpm(class: &Path, resource_manager: &Path) -> Value {
    // A failed path lookup does not establish absence. Containers can also expose a device
    // without mounting its sysfs class, in which case the result remains unconfirmed.
    let resource_manager_present = resource_manager.try_exists().ok();
    let absent = if resource_manager_present == Some(false) {
        "not_detected"
    } else {
        "unknown"
    };
    let devices = std::fs::read_dir(class).and_then(|entries| {
        let mut devices = Vec::new();
        for entry in entries {
            let name = entry?.file_name();
            if let Some(index) = name
                .to_str()
                .and_then(|name| name.strip_prefix("tpm"))
                .filter(|suffix| !suffix.is_empty() && suffix.bytes().all(|b| b.is_ascii_digit()))
                .and_then(|suffix| suffix.parse::<u32>().ok())
            {
                devices.push((index, name));
            }
        }
        devices.sort_by_key(|(index, _)| *index);
        Ok(devices)
    });
    let (availability, version) = match devices {
        Ok(devices) => match devices.first() {
            None => (absent, None),
            Some((_, device)) => {
                let version = std::fs::read_to_string(class.join(device).join("tpm_version_major"))
                    .ok()
                    .and_then(|version| match version.trim() {
                        "1" => Some("1.2"),
                        "2" => Some("2.0"),
                        _ => None,
                    });
                ("detected", version)
            }
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (absent, None),
        Err(_) => ("unknown", None),
    };
    json!({
        "availability": availability,
        "version": version,
        "resource_manager_present": resource_manager_present,
        "implementation": if availability == "not_detected" { "none" } else { "unknown" },
        "evidence": "linux_sysfs",
    })
}

#[cfg(windows)]
fn detect_tpm() -> Value {
    use windows::Win32::Foundation::TBS_E_TPM_NOT_FOUND;
    use windows::Win32::System::TpmBaseServices::{
        Tbsi_GetDeviceInfo, TPM_DEVICE_INFO, TPM_VERSION_20,
    };
    let mut info = TPM_DEVICE_INFO {
        structVersion: TPM_VERSION_20,
        ..Default::default()
    };
    let result = unsafe {
        Tbsi_GetDeviceInfo(
            std::mem::size_of_val(&info) as u32,
            std::ptr::from_mut(&mut info).cast(),
        )
    };
    let availability = if result == 0 {
        "detected"
    } else if result == TBS_E_TPM_NOT_FOUND.0 as u32 {
        "not_detected"
    } else {
        "unknown"
    };
    let version = if result == 0 {
        match info.tpmVersion {
            1 => Some("1.2"),
            2 => Some("2.0"),
            _ => None,
        }
    } else {
        None
    };
    // The interface/revision fields are reserved in the public API: never infer hardware type.
    json!({
        "availability": availability,
        "version": version,
        "implementation": if availability == "not_detected" { "none" } else { "unknown" },
        "evidence": "windows_tbs",
    })
}

#[cfg(not(any(target_os = "linux", windows)))]
fn detect_tpm() -> Value {
    json!({"availability": "not_applicable", "version": null, "implementation": "not_applicable", "evidence": "none"})
}

/// The installers use this same report as CLI/MCP status; unknown is always displayed explicitly.
pub fn summary(report: &Value) -> String {
    let protection = &report["key_protection"];
    fn value(v: &Value) -> &str {
        v.as_str().unwrap_or("unknown")
    }
    let scheme = match value(&protection["scheme"]) {
        "secure_enclave" => "Secure Enclave (macOS)".into(),
        "windows_hello_tpm" => "Windows Hello + TPM".into(),
        "windows_hello_software" => "Windows Hello (software)".into(),
        "windows_hello_unconfirmed" => "Windows Hello (TPM unknown)".into(),
        "tpm2_ecdh" => "TPM 2.0 (ECDH)".into(),
        "software_key_file" => kv_i18n::t("软件密钥文件", "Software key file"),
        "legacy_key_file" => kv_i18n::t(
            "旧文件密钥（需要迁移）",
            "Legacy key file (migration required)",
        ),
        "uninitialized" => kv_i18n::t("尚未初始化", "Uninitialized"),
        _ => kv_i18n::t("保护方案未确认（unknown）", "Unknown protection scheme"),
    };
    let hardware = match value(&protection["hardware"]) {
        "hardware_backed" => kv_i18n::t(
            "硬件保护（Secure Enclave）",
            "Hardware protection (Secure Enclave)",
        ),
        "os_reported" => kv_i18n::t(
            "系统报告 TPM 保护（非独立验证）",
            "OS-reported TPM protection (not independently verified)",
        ),
        "software" => kv_i18n::t("仅软件保护", "SOFTWARE PROTECTION ONLY"),
        "not_configured" => kv_i18n::t("尚未配置", "NOT CONFIGURED"),
        _ => kv_i18n::t("未确认（unknown）", "UNCONFIRMED (unknown)"),
    };
    let authentication = match value(&protection["authentication"]) {
        "secure_enclave_user_presence" => {
            kv_i18n::t("Touch ID 或系统密码", "Touch ID or system password")
        }
        "windows_hello" => "Windows Hello (PIN / biometrics)".into(),
        "polkit" => kv_i18n::t("系统授权（polkit）", "OS authorization (polkit)"),
        "none" => kv_i18n::t("尚未配置", "Not configured"),
        _ => kv_i18n::t("授权方式未确认（unknown）", "Unknown authorization"),
    };
    let tpm = match value(&report["tpm"]["availability"]) {
        "detected" => kv_i18n::t(
            &format!(
                "已检测到 TPM {}；实现类型未确认",
                value(&report["tpm"]["version"])
            ),
            &format!(
                "TPM {} detected; implementation unconfirmed",
                value(&report["tpm"]["version"])
            ),
        ),
        "not_detected" => kv_i18n::t("未检测到 TPM 设备", "No TPM device detected"),
        "not_applicable" => kv_i18n::t(
            "不适用（macOS 使用 Secure Enclave）",
            "Not applicable (macOS uses Secure Enclave)",
        ),
        _ => kv_i18n::t("检测结果未知", "Detection unknown"),
    };
    format!(
        "\n========== {} ==========\n{}: {}\n{}: {}\n{}: {}\n{}: {}\n{}\n{}: {}\n{}\n========================================\n",
        kv_i18n::t("KeyValet 密钥保护状态", "KeyValet key protection status"),
        kv_i18n::t("保护方案", "Scheme"), scheme,
        kv_i18n::t("硬件保护", "Hardware protection"), hardware,
        kv_i18n::t("本机 TPM", "System TPM"), tpm,
        kv_i18n::t("使用授权", "Authorization"), authentication,
        value(&protection["summary"]),
        kv_i18n::t("恢复口令", "Recovery passphrase"),
        match report["recovery_configured"].as_bool() {
            Some(true) => kv_i18n::t("已配置（独立离线恢复途径）", "Configured (independent offline recovery path)"),
            Some(false) => kv_i18n::t("未配置", "Not configured"),
            None => kv_i18n::t("未确认（unknown）", "Unconfirmed (unknown)"),
        },
        kv_i18n::t("派生密钥和解密后的秘密仍会进入进程内存。", "Derived keys and decrypted secrets still enter process memory."),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn status_response_requires_a_complete_bounded_frame_and_matching_protocol() {
        let response = kv_ipc::Response::ok(
            0,
            json!({"protocol": kv_ipc::PROTOCOL_VERSION, "vault_protection": report("windows_hello", None)}),
        );
        let line = format!("{}\n", serde_json::to_string(&response).unwrap());
        let report = read_probe_response(line.as_bytes()).await.unwrap();
        assert_eq!(report["key_protection"]["hardware"], "unknown");
        assert!(read_probe_response(line.trim_end().as_bytes())
            .await
            .is_err());
        for bad in [
            json!({"ready": true, "protocol": kv_ipc::PROTOCOL_VERSION}),
            json!({"id": 1, "ok": true, "result": {"protocol": kv_ipc::PROTOCOL_VERSION, "vault_protection": {}}}),
            json!({"id": 0, "ok": true, "result": {"protocol": kv_ipc::PROTOCOL_VERSION + 1, "vault_protection": {}}}),
            json!({"id": 0, "ok": true, "result": {"protocol": kv_ipc::PROTOCOL_VERSION, "vault_protection": null}}),
            json!({"id": 0, "ok": false, "error": "metadata unavailable"}),
        ] {
            let bad = format!("{bad}\n");
            assert!(read_probe_response(bad.as_bytes()).await.is_err());
        }
        let oversized = vec![b' '; kv_ipc::MAX_LINE_BYTES + 1];
        assert!(read_probe_response(oversized.as_slice()).await.is_err());
    }

    fn report(provider: &'static str, tpm_backed: Option<bool>) -> Value {
        let metadata = protection(provider, tpm_backed);
        let mut report = serde_json::to_value(&metadata).unwrap();
        report["key_protection"] = describe(&metadata);
        report["tpm"] = json!({
            "availability": "detected", "version": "2.0",
            "implementation": "unknown", "evidence": "linux_sysfs",
        });
        report
    }

    fn response_line(report: Value) -> Vec<u8> {
        let mut line = serde_json::to_vec(&kv_ipc::Response::ok(
            0,
            json!({"protocol": kv_ipc::PROTOCOL_VERSION, "vault_protection": report}),
        ))
        .unwrap();
        line.push(b'\n');
        line
    }

    #[tokio::test]
    async fn incomplete_or_mistyped_reports_never_become_successful_status() {
        let valid = report("windows_hello", None);
        for (object, field) in [
            ("", "provider"),
            ("", "tpm_backed"),
            ("", "recovery_configured"),
            ("", "device_binding"),
            ("", "migration_backup_present"),
            ("", "legacy_key_present"),
            ("", "hardware_required"),
            ("key_protection", "scheme"),
            ("key_protection", "hardware"),
            ("key_protection", "evidence"),
            ("key_protection", "authentication"),
            ("key_protection", "summary"),
            ("tpm", "availability"),
            ("tpm", "version"),
            ("tpm", "implementation"),
            ("tpm", "evidence"),
        ] {
            let mut incomplete = valid.clone();
            let parent = if object.is_empty() {
                &mut incomplete
            } else {
                &mut incomplete[object]
            };
            parent.as_object_mut().unwrap().remove(field);
            let line = response_line(incomplete);
            assert!(
                read_probe_response(line.as_slice()).await.is_err(),
                "{object}.{field}"
            );
        }
        for (object, field, value) in [
            ("", "provider", json!(false)),
            ("", "tpm_backed", json!("unknown")),
            ("", "recovery_configured", Value::Null),
            ("key_protection", "hardware", json!(true)),
            ("key_protection", "summary", json!(" ")),
            ("tpm", "availability", json!("hardware_backed")),
            ("tpm", "version", json!(2)),
            ("tpm", "resource_manager_present", json!("no")),
        ] {
            let mut invalid = valid.clone();
            if object.is_empty() {
                invalid[field] = value;
            } else {
                invalid[object][field] = value;
            }
            let line = response_line(invalid);
            assert!(
                read_probe_response(line.as_slice()).await.is_err(),
                "{object}.{field}"
            );
        }
        // Same-version helpers from before the new report must not silently omit the evidence.
        let old = response_line(json!({"provider": "windows_hello", "tpm_backed": null}));
        assert!(read_probe_response(old.as_slice()).await.is_err());
    }

    #[tokio::test]
    async fn fragmented_status_preserves_unknown_and_does_not_return_following_secret_frames() {
        use tokio::io::AsyncWriteExt;
        let expected = report("windows_hello", None);
        let mut wire = response_line(expected.clone());
        wire.extend_from_slice(
            b"{\"id\":1,\"ok\":true,\"result\":{\"value\":\"private-secret\"}}\n",
        );
        let (mut writer, reader) = tokio::io::duplex(13);
        let sender = tokio::spawn(async move {
            for chunk in wire.chunks(7) {
                if writer.write_all(chunk).await.is_err() {
                    break; // The status reader closes after its one public response.
                }
                tokio::task::yield_now().await;
            }
        });
        let actual = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            read_probe_response(reader),
        )
        .await
        .unwrap()
        .unwrap();
        sender.await.unwrap();
        assert_eq!(actual, expected);
        assert!(actual["tpm_backed"].is_null());
        assert_eq!(actual["key_protection"]["hardware"], "unknown");
        assert!(!actual.to_string().contains("private-secret"));
    }

    #[tokio::test]
    async fn response_size_limit_includes_newline_and_invalid_bytes_fail_closed() {
        let valid = response_line(report("software_key", Some(false)));
        let mut boundary = valid[..valid.len() - 1].to_vec();
        boundary.resize(kv_ipc::MAX_LINE_BYTES - 1, b' ');
        boundary.push(b'\n');
        assert!(read_probe_response(boundary.as_slice()).await.is_ok());
        boundary.insert(boundary.len() - 1, b' ');
        assert!(read_probe_response(boundary.as_slice()).await.is_err());
        for bad in [
            b"".as_slice(),
            b"{invalid}\n",
            b"\xff\n",
            b"null\n",
            b"[]\n",
        ] {
            assert!(read_probe_response(bad).await.is_err());
        }
    }

    fn protection(provider: &'static str, tpm_backed: Option<bool>) -> ProtectionStatus {
        let configured = matches!(
            provider,
            "secure_enclave" | "windows_hello" | "tpm2" | "software_key"
        );
        ProtectionStatus {
            provider,
            tpm_backed,
            recovery_configured: configured,
            device_binding: configured,
            migration_backup_present: false,
            legacy_key_present: provider == "migration_required",
            hardware_required: !matches!(provider, "windows_hello" | "software_key"),
        }
    }

    #[test]
    fn key_protection_never_confuses_a_tpm_interface_with_hardware_evidence() {
        for (provider, backed, scheme, hardware, auth) in [
            (
                "secure_enclave",
                None,
                "secure_enclave",
                "hardware_backed",
                "secure_enclave_user_presence",
            ),
            (
                "windows_hello",
                Some(true),
                "windows_hello_tpm",
                "os_reported",
                "windows_hello",
            ),
            (
                "windows_hello",
                None,
                "windows_hello_unconfirmed",
                "unknown",
                "windows_hello",
            ),
            (
                "windows_hello",
                Some(false),
                "windows_hello_software",
                "software",
                "windows_hello",
            ),
            ("tpm2", None, "tpm2_ecdh", "unknown", "polkit"),
            (
                "software_key",
                Some(false),
                "software_key_file",
                "software",
                "polkit",
            ),
            (
                "migration_required",
                None,
                "legacy_key_file",
                "software",
                "none",
            ),
            (
                "uninitialized",
                None,
                "uninitialized",
                "not_configured",
                "none",
            ),
        ] {
            let report = describe(&protection(provider, backed));
            assert_eq!(report["scheme"], scheme);
            assert_eq!(report["hardware"], hardware);
            assert_eq!(report["authentication"], auth);
        }
    }

    #[test]
    fn linux_detection_reports_missing_unreadable_and_virtual_devices_without_hardware_claims() {
        let tmp = tempfile::tempdir().unwrap();
        let class = tmp.path().join("tpm");
        let node = tmp.path().join("tpmrm0");
        assert_eq!(linux_tpm(&class, &node)["availability"], "not_detected");
        std::fs::create_dir(&class).unwrap();
        assert_eq!(linux_tpm(&class, &node)["availability"], "not_detected");
        std::fs::create_dir(class.join("tpm0")).unwrap();
        let report = linux_tpm(&class, &node);
        assert_eq!(report["availability"], "detected");
        assert!(report["version"].is_null());
        std::fs::write(class.join("tpm0/tpm_version_major"), "2\n").unwrap();
        std::fs::write(&node, []).unwrap();
        let report = linux_tpm(&class, &node);
        assert_eq!(report["availability"], "detected");
        assert_eq!(report["version"], "2.0");
        assert_eq!(report["implementation"], "unknown");
        assert_eq!(report["resource_manager_present"], true);
        std::fs::write(class.join("tpm0/tpm_version_major"), "invalid").unwrap();
        let report = linux_tpm(&class, &node);
        assert_eq!(report["availability"], "detected");
        assert!(report["version"].is_null());
    }

    #[test]
    fn linux_detection_uses_registered_device_numbers_and_prefers_tpm0() {
        let tmp = tempfile::tempdir().unwrap();
        let class = tmp.path().join("tpm");
        let node = tmp.path().join("tpmrm0");
        std::fs::create_dir_all(class.join("not-a-tpm")).unwrap();
        assert_eq!(linux_tpm(&class, &node)["availability"], "not_detected");
        std::fs::create_dir(class.join("tpm1")).unwrap();
        std::fs::write(class.join("tpm1/tpm_version_major"), "1\n").unwrap();
        let report = linux_tpm(&class, &node);
        assert_eq!(report["availability"], "detected");
        assert_eq!(report["version"], "1.2");
        assert_eq!(report["implementation"], "unknown");
        std::fs::create_dir(class.join("tpm0")).unwrap();
        std::fs::write(class.join("tpm0/tpm_version_major"), "2\n").unwrap();
        assert_eq!(linux_tpm(&class, &node)["version"], "2.0");
    }

    #[test]
    fn linux_device_without_sysfs_is_unconfirmed_instead_of_absent() {
        let tmp = tempfile::tempdir().unwrap();
        let class = tmp.path().join("tpm");
        let node = tmp.path().join("tpmrm0");
        std::fs::write(&node, []).unwrap();
        for make_class in [false, true] {
            if make_class {
                std::fs::create_dir(&class).unwrap();
            }
            let report = linux_tpm(&class, &node);
            assert_eq!(report["availability"], "unknown");
            assert_eq!(report["implementation"], "unknown");
            assert_eq!(report["resource_manager_present"], true);
        }
    }

    #[cfg(unix)]
    #[test]
    fn filesystem_probe_errors_never_claim_a_tpm_device_is_absent() {
        let tmp = tempfile::tempdir().unwrap();
        let class = tmp.path().join("tpm");
        let node = tmp.path().join("tpmrm0");
        std::fs::create_dir(&class).unwrap();
        // A symlink loop produces a lookup error without depending on root or file permissions.
        std::os::unix::fs::symlink(&node, &node).unwrap();
        let report = linux_tpm(&class, &node);
        assert_eq!(report["availability"], "unknown");
        assert!(report["resource_manager_present"].is_null());
        std::fs::create_dir(class.join("tpm0")).unwrap();
        std::fs::write(class.join("tpm0/tpm_version_major"), "2\n").unwrap();
        let registered = linux_tpm(&class, &node);
        assert_eq!(registered["availability"], "detected");
        assert!(registered["resource_manager_present"].is_null());
        std::fs::remove_file(&node).unwrap();
        std::fs::remove_dir_all(&class).unwrap();
        std::os::unix::fs::symlink(&class, &class).unwrap();
        assert_eq!(linux_tpm(&class, &node)["availability"], "unknown");
    }

    #[test]
    fn installer_summaries_keep_scheme_hardware_and_host_tpm_as_separate_facts() {
        for (provider, backed, availability, expected_en, expected_zh) in [
            (
                "secure_enclave",
                None,
                "not_applicable",
                "Hardware protection (Secure Enclave)",
                "硬件保护（Secure Enclave）",
            ),
            (
                "windows_hello",
                Some(true),
                "detected",
                "OS-reported TPM protection (not independently verified)",
                "系统报告 TPM 保护（非独立验证）",
            ),
            (
                "windows_hello",
                Some(false),
                "not_detected",
                "SOFTWARE PROTECTION ONLY",
                "仅软件保护",
            ),
            (
                "windows_hello",
                None,
                "detected",
                "UNCONFIRMED (unknown)",
                "未确认（unknown）",
            ),
            (
                "tpm2",
                None,
                "unknown",
                "UNCONFIRMED (unknown)",
                "未确认（unknown）",
            ),
            (
                "software_key",
                Some(false),
                "detected",
                "SOFTWARE PROTECTION ONLY",
                "仅软件保护",
            ),
            (
                "migration_required",
                None,
                "not_detected",
                "SOFTWARE PROTECTION ONLY",
                "仅软件保护",
            ),
            (
                "uninitialized",
                None,
                "not_applicable",
                "NOT CONFIGURED",
                "尚未配置",
            ),
        ] {
            let mut report = report(provider, backed);
            report["tpm"]["availability"] = json!(availability);
            if availability != "detected" {
                report["tpm"]["version"] = Value::Null;
            }
            let summary = summary(&report);
            let hardware_line = summary
                .lines()
                .find(|line| {
                    line.starts_with("Hardware protection:") || line.starts_with("硬件保护:")
                })
                .unwrap();
            assert!(
                hardware_line.ends_with(expected_en) || hardware_line.ends_with(expected_zh),
                "{summary}"
            );
            if report["key_protection"]["scheme"] == "windows_hello_unconfirmed" {
                assert!(summary.contains("Windows Hello (TPM unknown)"));
                assert!(
                    !hardware_line.contains("OS-reported") && !hardware_line.contains("系统报告")
                );
            }
            assert!(summary.contains("========== KeyValet"));
            assert!(summary.contains("process memory") || summary.contains("进程内存"));
        }
    }

    #[test]
    fn summaries_do_not_label_missing_or_future_metadata_as_uninitialized() {
        let mut future = report("uninitialized", None);
        future["key_protection"]["scheme"] = json!("future_provider");
        future["key_protection"]["hardware"] = json!("unknown");
        future["key_protection"]["authentication"] = json!("future_auth");
        let summary = summary(&future);
        assert!(!summary.contains("Uninitialized") && !summary.contains("尚未初始化"));
        assert!(
            !summary.contains("Authorization: Not configured")
                && !summary.contains("使用授权: 尚未配置")
        );
        assert!(summary.contains("unknown") || summary.contains("Unknown"));
        let missing = super::summary(&json!({}));
        assert!(
            !missing.contains("Recovery passphrase: Not configured")
                && !missing.contains("恢复口令: 未配置")
        );
    }
}
