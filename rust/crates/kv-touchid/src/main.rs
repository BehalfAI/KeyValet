//! Touch ID / device owner authentication (LocalAuthentication). Direct port of
//! src/native/touchid.swift.
//!
//! Invoked by the root helper after dropping privileges to the current user (fingerprints can't
//! reach the auth sheet as root).
//! Usage: kv-touchid <reason text> [cancel button text]
//! Exit codes: 0 approved, 1 not approved/cancelled, 2 unsupported on this machine.
//! Without a fingerprint enrolled, the system auth sheet falls back to the login password -- the
//! system verifies it, this program never sees it.

use objc2_foundation::NSString;
use objc2_local_authentication::{LAContext, LAPolicy};
use std::sync::mpsc;

fn main() {
    let mut args = std::env::args().skip(1);
    let reason = args
        .next()
        .unwrap_or_else(|| "Unlock the vault".to_string());
    let cancel = args.next().unwrap_or_else(|| "Cancel".to_string());

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
