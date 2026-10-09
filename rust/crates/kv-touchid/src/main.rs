//! Touch ID / device owner authentication (LocalAuthentication). Direct port of
//! src/native/touchid.swift.
//!
//! Invoked by the root helper after dropping privileges to the current user (fingerprints can't
//! reach the auth sheet as root).
//! Usage: kv-touchid <reason text> [cancel button text]
//! Exit codes: 0 approved, 1 not approved/cancelled, 2 unsupported on this machine.
//! Without a fingerprint enrolled, the system auth sheet falls back to the login password -- the
//! system verifies it, this program never sees it.

#[cfg(target_os = "macos")]
mod enclave;

#[cfg(target_os = "macos")]
fn main() {
    use objc2_foundation::NSString;
    use objc2_local_authentication::{LAContext, LAPolicy};
    use std::sync::mpsc;
    if unsafe { libc::getuid() } == 0
        || unsafe { libc::geteuid() } == 0
        || unsafe { libc::getgid() } == 0
        || unsafe { libc::getegid() } == 0
    {
        eprintln!(
            "{}",
            kv_i18n::t(
                "kv-touchid 不能以 root 用户或 wheel 组身份运行",
                "kv-touchid must not run with root user or wheel group identity"
            )
        );
        std::process::exit(1);
    }
    unsafe {
        libc::umask(0o077);
        let limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        libc::setrlimit(libc::RLIMIT_CORE, &limit);
    }
    let mut args = std::env::args().skip(1);
    let reason = args
        .next()
        .unwrap_or_else(|| kv_i18n::t("解锁凭证库", "unlock your credential vault"));
    if reason == "--enclave" {
        let operation = args.next().unwrap_or_default();
        let reason = args
            .next()
            .unwrap_or_else(|| kv_i18n::t("解锁凭证库", "unlock your credential vault"));
        let cancel = args.next().unwrap_or_else(|| kv_i18n::t("取消", "Cancel"));
        if let Err(error) = enclave::run(&operation, &reason, &cancel) {
            eprintln!("{error}");
            std::process::exit(1);
        }
        return;
    }
    let cancel = args.next().unwrap_or_else(|| kv_i18n::t("取消", "Cancel"));

    let ctx = unsafe { LAContext::new() };
    unsafe { ctx.setLocalizedCancelTitle(Some(&NSString::from_str(&cancel))) };

    let policy = LAPolicy::DeviceOwnerAuthentication;
    if unsafe { ctx.canEvaluatePolicy_error(policy) }.is_err() {
        std::process::exit(2);
    }

    let (tx, rx) = mpsc::channel::<bool>();
    let reply = block2::RcBlock::new(
        move |success: objc2::runtime::Bool, _error: *mut objc2_foundation::NSError| {
            let _ = tx.send(success.as_bool());
        },
    );
    let reason_ns = NSString::from_str(&reason);
    unsafe { ctx.evaluatePolicy_localizedReason_reply(policy, &reason_ns, &reply) };

    let approved = rx.recv().unwrap_or(false);
    std::process::exit(if approved { 0 } else { 1 });
}

#[cfg(not(target_os = "macos"))]
fn main() {
    std::process::exit(2);
}
