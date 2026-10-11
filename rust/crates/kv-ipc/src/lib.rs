//! JSON-lines protocol between the MCP server (runs as a regular user) and the root helper.
//! Direct port of src/shared/protocol.ts.
//!
//! Handshake: the server first sends one line, an `AuthMessage` (purpose, source, session ID) -> the
//! helper shows a Touch ID prompt -> on success it replies `{ready: true}`, otherwise
//! `{ready: false, error}` and exits. Only after that do normal requests begin.

use serde::{Deserialize, Serialize};

pub mod agent;
pub mod mcp_worker;
mod request;
pub use request::{operation_digest, request_digest};

pub const PROTOCOL_VERSION: u32 = 4;
pub const MAX_LINE_BYTES: usize = 1024 * 1024;
/// Maximum outstanding helper operations. Clients queue before sending beyond this bound.
pub const MAX_IN_FLIGHT_REQUESTS: usize = 8;

/// A separate, read-only startup exchange. It never authenticates or opens a credential session;
/// the helper replies with public protection metadata and then closes the connection.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", deny_unknown_fields)]
pub enum ProtectionProbe {
    #[serde(rename = "protection")]
    Status {
        protocol: u32,
        #[serde(skip_serializing_if = "Option::is_none")]
        lang: Option<String>,
    },
}

/// Prefix the helper returns for a "needs authorization" error, followed by type/name.
pub const GRANT_REQUIRED_PREFIX: &str = "[GRANT_REQUIRED] ";
/// Error marker the helper returns for "endpoint/client has changed, can't keep reusing the old
/// client secret" (independent of UI language).
pub const SECRET_REBIND_MARK: &str = "[SECRET_REBIND]";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Op {
    ListTypes,
    CreateType,
    DeleteType,
    List,
    Exists,
    /// Non-sensitive credential info (including protocol-credential config and status); excludes the value and secrets.
    Info,
    /// Returns the value for static credentials; protocol credentials only return info.
    Get,
    Set,
    Delete,
    /// Create/replace a protocol credential (oauth2, google_service_account, github_app, jwt, totp, aws).
    SetupProtocol,
    OauthExchange,
    OauthDeviceStart,
    OauthDevicePoll,
    AccessToken,
    Totp,
    Aws,
    /// Query the audit log.
    AuditQuery,
    /// Change the proxy-call configuration (the helper prompts for user confirmation when widening exposure).
    HttpConfigure,
    /// Proxy call: injects the credential, sends the HTTP request, and returns only the response.
    HttpRequest,
    /// Checks whether a credential works, using a verification request.
    HttpTest,
    /// Per-credential authorization: shows a Touch ID prompt to authorize this session to use a given credential.
    Grant,
    /// Read/modify vault settings (grant-scope mode).
    Settings,
    /// This session's authorization status.
    SessionInfo,
    /// Opens the local gateway endpoint (for the SDK / CLI, supports streaming responses).
    GatewayOpen,
}

pub const OPS: [Op; 24] = [
    Op::ListTypes,
    Op::CreateType,
    Op::DeleteType,
    Op::List,
    Op::Exists,
    Op::Info,
    Op::Get,
    Op::Set,
    Op::Delete,
    Op::SetupProtocol,
    Op::OauthExchange,
    Op::OauthDeviceStart,
    Op::OauthDevicePoll,
    Op::AccessToken,
    Op::Totp,
    Op::Aws,
    Op::AuditQuery,
    Op::HttpConfigure,
    Op::HttpRequest,
    Op::HttpTest,
    Op::Grant,
    Op::Settings,
    Op::SessionInfo,
    Op::GatewayOpen,
];

impl Op {
    /// Parses the wire string form (same spelling as the TS `Op` union), returning `None` for an
    /// unrecognized op -- mirrors `OPS.includes(req.op)` in dispatch.ts, which produces a specific
    /// "Unknown operation" error rather than a generic parse failure.
    pub fn parse(s: &str) -> Option<Op> {
        OPS.iter().find(|op| op.as_str() == s).copied()
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Op::ListTypes => "listTypes",
            Op::CreateType => "createType",
            Op::DeleteType => "deleteType",
            Op::List => "list",
            Op::Exists => "exists",
            Op::Info => "info",
            Op::Get => "get",
            Op::Set => "set",
            Op::Delete => "delete",
            Op::SetupProtocol => "setupProtocol",
            Op::OauthExchange => "oauthExchange",
            Op::OauthDeviceStart => "oauthDeviceStart",
            Op::OauthDevicePoll => "oauthDevicePoll",
            Op::AccessToken => "accessToken",
            Op::Totp => "totp",
            Op::Aws => "aws",
            Op::AuditQuery => "auditQuery",
            Op::HttpConfigure => "httpConfigure",
            Op::HttpRequest => "httpRequest",
            Op::HttpTest => "httpTest",
            Op::Grant => "grant",
            Op::Settings => "settings",
            Op::SessionInfo => "sessionInfo",
            Op::GatewayOpen => "gatewayOpen",
        }
    }

    /// Operations that require stating a purpose: reading a credential/deriving a token, modifying a credential.
    pub fn purpose_required(&self) -> bool {
        matches!(
            self,
            Op::CreateType
                | Op::DeleteType
                | Op::Get
                | Op::Set
                | Op::Delete
                | Op::SetupProtocol
                | Op::OauthExchange
                | Op::OauthDeviceStart
                | Op::AccessToken
                | Op::Totp
                | Op::Aws
                | Op::HttpConfigure
                | Op::HttpRequest
                | Op::HttpTest
                | Op::Grant
                | Op::GatewayOpen
        )
    }

    /// Operations that require the credential to already be authorized (in per_credential mode).
    pub fn grant_required(&self) -> bool {
        matches!(
            self,
            Op::Get
                | Op::AccessToken
                | Op::Totp
                | Op::Aws
                | Op::HttpRequest
                | Op::HttpTest
                | Op::HttpConfigure
                | Op::OauthExchange
                | Op::OauthDeviceStart
                | Op::OauthDevicePoll
                | Op::GatewayOpen
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    pub id: u64,
    pub op: String,
    #[serde(default)]
    pub params: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Response {
    Ok {
        id: u64,
        ok: True,
        result: serde_json::Value,
    },
    Err {
        id: u64,
        ok: False,
        error: String,
    },
}

/// Serde needs concrete unit-like types to emit/require the literal `true`/`false` JSON boolean for
/// the `ok` field (matching the TS discriminated union `{ok: true, ...} | {ok: false, ...}` exactly)
/// rather than a generic bool -- hence the hand-written impls below instead of `derive`, which would
/// serialize a unit struct as `null`.
#[derive(Debug, Clone, Copy)]
pub struct True;
#[derive(Debug, Clone, Copy)]
pub struct False;

impl Serialize for True {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_bool(true)
    }
}
impl Serialize for False {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_bool(false)
    }
}
impl<'de> Deserialize<'de> for True {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        if bool::deserialize(d)? {
            Ok(True)
        } else {
            Err(serde::de::Error::custom("expected `true`"))
        }
    }
}
impl<'de> Deserialize<'de> for False {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        if bool::deserialize(d)? {
            Err(serde::de::Error::custom("expected `false`"))
        } else {
            Ok(False)
        }
    }
}

impl Response {
    pub fn ok(id: u64, result: serde_json::Value) -> Self {
        Response::Ok {
            id,
            ok: True,
            result,
        }
    }
    pub fn err(id: u64, error: impl Into<String>) -> Self {
        Response::Err {
            id,
            ok: False,
            error: error.into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialHint {
    #[serde(default)]
    pub r#type: Option<String>,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthMessage {
    pub op: String, // always "auth"
    pub purpose: String,
    /// Authorization mode requested by the client (from KEYVALET_GRANT_MODE): can only be stricter than the global setting.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requested_mode: Option<String>,
    /// UI language (keeps the helper's prompts, dialogs, and error messages consistent with the MCP server).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lang: Option<String>,
    /// Credential the unlocking tool is about to use (in per_credential mode, this Touch ID also authorizes that credential).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential: Option<CredentialHint>,
    pub cwd: String,
    pub ppid: u32,
    pub session: String,
    pub client: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ReadyMessage {
    Ready {
        ready: True,
        protocol: u32,
    },
    NotReady {
        ready: False,
        protocol: u32,
        error: String,
    },
}

/// Invisible direction and format characters (bidi overrides and isolates, zero-width marks, BOM)
/// that can reorder or hide text in dialogs without being visible themselves.
pub fn is_invisible_format(c: char) -> bool {
    matches!(
        c,
        '\u{061c}' | '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2060}'..='\u{2069}' | '\u{feff}'
    )
}

/// Purpose text: strip control and invisible format characters, collapse whitespace, cap the
/// length. `None` if too short after cleaning (the TS version requires at least 2 characters).
pub fn clean_purpose(v: Option<&str>) -> Option<String> {
    let v = v?;
    let mut out = String::with_capacity(v.len());
    let mut last_was_space = false;
    for c in v.chars() {
        if is_invisible_format(c) {
            continue;
        }
        let is_space = c.is_control() || c.is_whitespace();
        if is_space {
            if !last_was_space {
                out.push(' ');
            }
            last_was_space = true;
        } else {
            out.push(c);
            last_was_space = false;
        }
    }
    let s = out.trim();
    // Matches JS string .length (UTF-16 code units), not bytes or Unicode scalars.
    if s.encode_utf16().count() < 2 {
        return None;
    }
    let units: Vec<u16> = s.encode_utf16().take(300).collect();
    Some(String::from_utf16_lossy(&units))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn purpose_drops_invisible_direction_and_c1_controls() {
        let cleaned = clean_purpose(Some(
            "Read\u{202e}gnp.exe\u{202c} file\u{2066}x\u{2069}\u{200b}\u{0085}now",
        ))
        .unwrap();
        assert_eq!(cleaned, "Readgnp.exe filex now");
        assert!(!cleaned
            .chars()
            .any(|c| c.is_control() || is_invisible_format(c)));
    }

    #[test]
    fn op_round_trips_through_its_wire_string() {
        for op in OPS {
            assert_eq!(Op::parse(op.as_str()), Some(op));
        }
        assert_eq!(Op::parse("rm -rf"), None);
    }

    #[test]
    fn purpose_required_and_grant_required_match_the_ts_sets() {
        assert!(Op::Get.purpose_required());
        assert!(Op::Get.grant_required());
        assert!(!Op::List.purpose_required());
        assert!(!Op::List.grant_required());
        assert!(Op::Set.purpose_required());
        assert!(!Op::Set.grant_required());
    }

    #[test]
    fn clean_purpose_strips_control_chars_collapses_whitespace_and_caps_length() {
        assert_eq!(
            clean_purpose(Some("  read\n\norder  #6\t")),
            Some("read order #6".to_string())
        );
        assert_eq!(clean_purpose(Some("a")), None, "too short after cleaning");
        assert_eq!(clean_purpose(Some(" ")), None);
        assert_eq!(clean_purpose(None), None);
        let long = "x".repeat(400);
        assert_eq!(clean_purpose(Some(&long)).unwrap().len(), 300);
    }
}
