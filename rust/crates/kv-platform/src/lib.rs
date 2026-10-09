//! Platform interaction traits: the seams every other crate codes against, implemented per-OS
//! (macOS via objc2, eventually Windows via windows-rs -- see the rewrite plan's "kv-platform interface").
//! Also the fixed install paths and filesystem trust checks shared by every binary that runs with
//! root's authority.

#[cfg(target_os = "macos")]
pub mod enclave;
#[cfg(target_os = "macos")]
pub mod macos;
pub mod paths;
pub mod trust;
#[cfg(unix)]
pub mod user;

/// The thing that actually shows a biometric (or password-fallback) prompt to the user and reports
/// whether they approved it.
pub trait Authenticator {
    /// `reason` is shown to the user (the stated purpose); `deny_label` is the cancel button's text
    /// (passed through so it can be localized the same way the rest of the UI is).
    ///
    /// Spelled out as `-> impl Future + Send` rather than `async fn`: the real daemon runs on a
    /// multi-threaded tokio runtime, where a spawned future must be `Send`; `async fn` in a public
    /// trait can't express that bound (see the `async_fn_in_trait` lint).
    fn authenticate(
        &self,
        reason: &str,
        deny_label: &str,
    ) -> impl std::future::Future<Output = AuthOutcome> + Send;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthOutcome {
    Approved,
    Denied,
    /// This machine has no biometric/password fallback available (TS: child exit code 2).
    Unsupported,
    /// The authenticator couldn't even attempt the prompt (e.g. an installation-integrity check
    /// failed, or the invoking user couldn't be determined). `message` is already localized and
    /// specific enough to show directly to the user, bypassing the generic Denied/Unsupported text.
    Error(String),
}

/// A confirmation dialog raised by the root helper itself (dropping privileges to the user who
/// invoked sudo). Used for the most sensitive changes (overwriting/deleting a credential, loosening
/// the authorization mode, widening a proxy's exposure): even if someone bypasses the MCP server
/// and drives the helper directly, user confirmation is still required.
pub trait Confirmer {
    /// Spelled out as `-> impl Future + Send` for the same reason as `Authenticator::authenticate`.
    fn confirm(
        &self,
        message: &str,
        ok_label: &str,
    ) -> impl std::future::Future<Output = bool> + Send;
}
