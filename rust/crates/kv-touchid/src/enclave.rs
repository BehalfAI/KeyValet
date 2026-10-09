use base64::{engine::general_purpose::STANDARD, Engine};
use kv_vault::{EnclaveMetadata, MasterKey};
use std::{
    ffi::CString,
    io::{IsTerminal, Read, Write},
};

extern "C" {
    fn kv_enclave_key(
        create: i32,
        blob: *const u8,
        blob_len: usize,
        peer: *const u8,
        peer_len: usize,
        reason: *const libc::c_char,
        cancel: *const libc::c_char,
        output_blob: *mut u8,
        output_blob_len: *mut usize,
        output_peer: *mut u8,
        output_key: *mut u8,
    ) -> i32;
}

pub fn run(operation: &str, reason: &str, cancel: &str) -> Result<(), String> {
    if std::io::stdout().is_terminal() {
        return Err(kv_i18n::t(
            "硬件密钥操作只能通过父进程管道调用",
            "Hardware key operations require a parent-process pipe",
        ));
    }
    let mut input = Vec::new();
    std::io::stdin()
        .take(8193)
        .read_to_end(&mut input)
        .map_err(|_| {
            kv_i18n::t(
                "读取硬件密钥请求失败",
                "Failed to read hardware key request",
            )
        })?;
    if input.len() > 8192 {
        return Err(kv_i18n::t(
            "硬件密钥请求过大",
            "Hardware key request is too large",
        ));
    }
    let (blob, peer) = match operation {
        "create" if input.is_empty() => (Vec::new(), Vec::new()),
        "derive" => serde_json::from_slice::<EnclaveMetadata>(&input)
            .map_err(|_| kv_i18n::t("硬件密钥元数据无效", "Invalid hardware key metadata"))?
            .decode()
            .map_err(|e| e.0)?,
        _ => {
            return Err(kv_i18n::t(
                "无效的硬件密钥操作",
                "Invalid hardware key operation",
            ))
        }
    };
    let reason = CString::new(reason)
        .map_err(|_| kv_i18n::t("认证目的无效", "Invalid authentication reason"))?;
    let cancel =
        CString::new(cancel).map_err(|_| kv_i18n::t("取消按钮文字无效", "Invalid cancel label"))?;
    let mut result_blob = vec![0u8; 4096];
    let mut length = result_blob.len();
    let mut result_peer = [0u8; 65];
    let mut key: MasterKey = Default::default();
    let status = unsafe {
        kv_enclave_key(
            i32::from(operation == "create"),
            blob.as_ptr(),
            blob.len(),
            peer.as_ptr(),
            peer.len(),
            reason.as_ptr(),
            cancel.as_ptr(),
            result_blob.as_mut_ptr(),
            &mut length,
            result_peer.as_mut_ptr(),
            key.as_mut_ptr(),
        )
    };
    if status != 0 {
        return Err(kv_i18n::t(&format!("Secure Enclave 操作失败（{status}）；请确认设备已解锁并完成系统认证"),
            &format!("Secure Enclave operation failed ({status}); unlock the device and complete system authentication")));
    }
    if length == 0 || length > result_blob.len() {
        return Err(kv_i18n::t(
            "硬件密钥响应无效",
            "Invalid hardware key response",
        ));
    }
    let metadata = EnclaveMetadata {
        version: 1,
        key_blob: STANDARD.encode(&result_blob[..length]),
        peer_public_key: STANDARD.encode(result_peer),
    };
    metadata.decode().map_err(|e| e.0)?;
    let encoded = serde_json::to_vec(&metadata).map_err(|_| {
        kv_i18n::t(
            "硬件密钥响应编码失败",
            "Failed to encode hardware key response",
        )
    })?;
    // Write straight to fd 1: `std::io::stdout()` would copy the key into its own heap buffer.
    let mut out = std::mem::ManuallyDrop::new(unsafe {
        <std::fs::File as std::os::fd::FromRawFd>::from_raw_fd(1)
    });
    out.write_all(key.as_ref())
        .and_then(|_| out.write_all(&encoded))
        .map_err(|_| {
            kv_i18n::t(
                "硬件密钥响应发送失败",
                "Failed to send hardware key response",
            )
        })?;
    Ok(())
}
