//! Interactive Windows dialogs and the elevated CLI's connection to the service's agent broker.
use kv_ipc::agent as wire;
use kv_vault::{EnclaveKey, EnclaveMetadata, MasterKey, MasterKeyProvider, Result, VaultError};
use serde_json::{json, Value};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use windows::core::{w, HRESULT, PCWSTR};
use windows::Win32::Foundation::{ERROR_SUCCESS, HWND, LPARAM, WPARAM};
use windows::Win32::UI::Controls::{
    TaskDialogIndirect, TASKDIALOGCONFIG, TASKDIALOG_BUTTON, TASKDIALOG_NOTIFICATIONS,
    TDF_ALLOW_DIALOG_CANCELLATION, TDF_CALLBACK_TIMER, TDM_CLICK_BUTTON, TDN_TIMER,
};
use windows::Win32::UI::WindowsAndMessaging::SendMessageW;

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

struct DialogTimer {
    stopped: Arc<AtomicBool>,
    timeout_ms: usize,
}

unsafe extern "system" fn timer(
    hwnd: HWND,
    msg: TASKDIALOG_NOTIFICATIONS,
    elapsed: WPARAM,
    _: LPARAM,
    data: isize,
) -> HRESULT {
    let state = &*(data as *const DialogTimer);
    if msg == TDN_TIMER && (elapsed.0 >= state.timeout_ms || state.stopped.load(Ordering::SeqCst)) {
        let _ = SendMessageW(hwnd, TDM_CLICK_BUTTON.0 as u32, Some(WPARAM(2)), None);
    }
    HRESULT(0)
}

fn dialog(message: &str, ok: &str, state: &DialogTimer) -> bool {
    let message = wide(message);
    let ok = wide(ok);
    let cancel = wide(&kv_i18n::t("取消", "Cancel"));
    let buttons = [
        TASKDIALOG_BUTTON {
            nButtonID: 1,
            pszButtonText: PCWSTR(ok.as_ptr()),
        },
        TASKDIALOG_BUTTON {
            nButtonID: 2,
            pszButtonText: PCWSTR(cancel.as_ptr()),
        },
    ];
    let config = TASKDIALOGCONFIG {
        cbSize: std::mem::size_of::<TASKDIALOGCONFIG>() as u32,
        dwFlags: TDF_ALLOW_DIALOG_CANCELLATION | TDF_CALLBACK_TIMER,
        pszWindowTitle: w!("KeyValet"),
        pszContent: PCWSTR(message.as_ptr()),
        cButtons: 2,
        pButtons: buttons.as_ptr(),
        nDefaultButton: 2,
        pfCallback: Some(timer),
        lpCallbackData: state as *const _ as isize,
        ..Default::default()
    };
    let mut pressed = 0;
    unsafe { TaskDialogIndirect(&config, Some(&mut pressed), None, None).is_ok() && pressed == 1 }
}

pub fn confirm(message: &str, ok: &str) -> bool {
    confirm_with_timeout(message, ok, std::time::Duration::from_secs(120))
}

pub fn confirm_with_timeout(message: &str, ok: &str, timeout: std::time::Duration) -> bool {
    dialog(
        message,
        ok,
        &DialogTimer {
            stopped: Arc::new(AtomicBool::new(false)),
            timeout_ms: timeout.as_millis().min(usize::MAX as u128) as usize,
        },
    )
}

pub struct Notice(Arc<AtomicBool>);
impl Drop for Notice {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

pub fn show_notice(message: &str, seconds: u64) -> Notice {
    let stop = Arc::new(AtomicBool::new(false));
    let state = DialogTimer {
        stopped: stop.clone(),
        timeout_ms: seconds.saturating_mul(1000).min(usize::MAX as u64) as usize,
    };
    let message = message.to_owned();
    std::thread::spawn(move || {
        dialog(&message, &kv_i18n::t("关闭", "Close"), &state);
    });
    Notice(stop)
}

/// Generic credential UI with persistence disabled. This collects an application secret,
/// never a Windows password or PIN; the OS authenticates Hello separately.
pub fn prompt_secret(message: &str) -> Option<zeroize::Zeroizing<String>> {
    use windows::Win32::Security::Credentials::{
        CredUIPromptForCredentialsW, CREDUI_FLAGS_ALWAYS_SHOW_UI, CREDUI_FLAGS_DO_NOT_PERSIST,
        CREDUI_FLAGS_GENERIC_CREDENTIALS, CREDUI_FLAGS_KEEP_USERNAME, CREDUI_INFOW,
    };
    let message = wide(&kv_i18n::t(
        &format!("{message}\n\n这里输入 KeyValet 的秘密或恢复口令。请勿输入 Windows 登录密码或 Hello PIN。"),
        &format!("{message}\n\nEnter a KeyValet secret or recovery passphrase. Do not enter your Windows login password or Hello PIN.")));
    let info = CREDUI_INFOW {
        cbSize: std::mem::size_of::<CREDUI_INFOW>() as u32,
        pszCaptionText: w!("KeyValet · Save Secret / Recovery"),
        pszMessageText: PCWSTR(message.as_ptr()),
        ..Default::default()
    };
    let mut username = wide("KeyValet");
    username.resize(514, 0);
    let mut password = zeroize::Zeroizing::new([0u16; 1025]);
    let code = unsafe {
        CredUIPromptForCredentialsW(
            Some(&info),
            w!("KeyValet application secret"),
            None,
            0,
            &mut username,
            &mut password[..],
            None,
            CREDUI_FLAGS_GENERIC_CREDENTIALS
                | CREDUI_FLAGS_ALWAYS_SHOW_UI
                | CREDUI_FLAGS_DO_NOT_PERSIST
                | CREDUI_FLAGS_KEEP_USERNAME,
        )
    };
    if code != ERROR_SUCCESS {
        return None;
    }
    let end = password.iter().position(|c| *c == 0)?;
    if end == 0 {
        return None;
    }
    Some(zeroize::Zeroizing::new(
        String::from_utf16(&password[..end]).ok()?,
    ))
}

pub async fn control_request(
    command: &str,
    request: Value,
) -> std::io::Result<(Value, Option<(wire::EnclavePayload, usize)>)> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    tokio::time::timeout(std::time::Duration::from_secs(140), async {
        let mut pipe = crate::pipe::connect_service(crate::paths::HELPER_PIPE).await?;
        pipe.write_all(&wire::encode_line(
            &json!({"op":"control", "command":command, "request":request}),
        ))
        .await?;
        let mut header = Vec::new();
        loop {
            let byte = pipe.read_u8().await?;
            if byte == b'\n' {
                break;
            }
            if header.len() >= wire::MAX_LINE_BYTES {
                return Err(std::io::Error::other("control reply too large"));
            }
            header.push(byte);
        }
        let header: Value = serde_json::from_slice(&header)?;
        let payload = if header.get("len").is_some() {
            let len = wire::enclave_len(&header).map_err(std::io::Error::other)?;
            let mut buf: wire::EnclavePayload =
                zeroize::Zeroizing::new([0u8; wire::MAX_ENCLAVE_PAYLOAD + 1]);
            pipe.read_exact(&mut buf[..len]).await?;
            Some((buf, len))
        } else {
            None
        };
        Ok((header, payload))
    })
    .await
    .map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "KeyValet control request timed out",
        )
    })?
}

pub struct HelloMasterKeyProvider;
impl HelloMasterKeyProvider {
    fn run(
        &self,
        operation: &str,
        metadata: Option<&EnclaveMetadata>,
        reason: &str,
    ) -> Result<EnclaveKey> {
        let request = wire::request(
            0,
            "enclave",
            &[
                ("operation", json!(operation)),
                ("metadata", json!(metadata)),
                ("reason", json!(reason)),
            ],
        );
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let (header, payload) = runtime.block_on(control_request("agent", request))?;
        let (buf, len) = payload.ok_or_else(|| {
            VaultError(
                header["error"]
                    .as_str()
                    .unwrap_or("Windows Hello failed")
                    .to_owned(),
            )
        })?;
        let result = crate::agent::decode_enclave_output(&buf[..len], metadata)?;
        result.metadata.hello()?;
        Ok(result)
    }
}
impl MasterKeyProvider for HelloMasterKeyProvider {
    fn create(&self, reason: &str) -> Result<EnclaveKey> {
        self.run("create", None, reason)
    }
    fn unlock(&self, metadata: &EnclaveMetadata, reason: &str) -> Result<MasterKey> {
        metadata.hello()?;
        Ok(self.run("derive", Some(metadata), reason)?.key)
    }
}
