//! Session authorization and request dispatch: the glue between kv-ipc's wire protocol and
//! kv-vault's storage. Direct port of src/helper/dispatch.ts, settings.ts, and auth-gate.ts.

pub mod auth_gate;
pub mod dispatch;
pub mod prompt;
pub mod settings;
pub mod summarize;

pub use auth_gate::{cooldown_remaining, touch_id_gate, GateResult};
pub use dispatch::{
    cred_key, dispatch, resolve_hint, set_static, AuthorizeGate, ClientContext, JsonMap,
    SessionAuth, TouchIdSessionGate,
};
pub use kv_platform::{AuthOutcome, Authenticator, Confirmer};
pub use settings::{
    is_loosening, parse_mode, read_settings, remember_active, remember_until, stricter,
    write_settings, GrantMode, Settings, GRANT_MODES,
};
