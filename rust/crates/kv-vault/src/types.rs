use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use zeroize::Zeroize;

pub const KINDS: [Kind; 7] = [
    Kind::Static,
    Kind::Oauth2,
    Kind::GoogleServiceAccount,
    Kind::GithubApp,
    Kind::Jwt,
    Kind::Totp,
    Kind::Aws,
];

/// The kinds of protocol-based credentials; `Static` is just a plain "store whatever, retrieve whatever".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Static,
    Oauth2,
    GoogleServiceAccount,
    GithubApp,
    Jwt,
    Totp,
    Aws,
}

impl Kind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Kind::Static => "static",
            Kind::Oauth2 => "oauth2",
            Kind::GoogleServiceAccount => "google_service_account",
            Kind::GithubApp => "github_app",
            Kind::Jwt => "jwt",
            Kind::Totp => "totp",
            Kind::Aws => "aws",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypeRecord {
    pub description: String,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(rename = "updatedAt")]
    pub updated_at: String,
}

/// A rule for injecting a credential into an HTTP request (proxied calls).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct InjectRule {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub headers: Option<HashMap<String, String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query: Option<HashMap<String, String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub basic: Option<BasicAuth>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BasicAuth {
    pub username: String,
    pub password: String,
}

/// A request used to verify that a credential works.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TestRequest {
    pub method: String,
    pub url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub headers: Option<HashMap<String, String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query: Option<HashMap<String, String>>,
}

/// Proxy-call configuration (injection rule, allowed hosts, proxy-only flag, test request).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HttpConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inject: Option<InjectRule>,
    pub allowed_hosts: Vec<String>,
    pub proxy_only: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub test: Option<TestRequest>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CredentialRecord {
    /// Defaults to `Static` if absent (for compatibility with old data).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<Kind>,
    /// The value of a static credential; an empty string for protocol-based credentials.
    #[serde(default)]
    pub value: String,
    /// Non-sensitive configuration for a protocol-based credential (endpoint, client_id, scope, etc.).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config: Option<serde_json::Value>,
    /// Long-lived secrets of a protocol-based credential (refresh token, private key, seed, ...);
    /// never leaves the root process.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secrets: Option<HashMap<String, String>>,
    /// Protocol runtime state (cached short-lived token, expiry, etc.).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<serde_json::Value>,
    /// Random version generated on each setProtocol; checked before writing back an async
    /// operation's result, to avoid overwriting a configuration replaced in the meantime.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generation: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http: Option<HttpConfig>,
    /// The template ID used at creation time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template: Option<String>,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub attributes: HashMap<String, String>,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(rename = "updatedAt")]
    pub updated_at: String,
}

impl CredentialRecord {
    pub fn kind_or_static(&self) -> Kind {
        self.kind.unwrap_or(Kind::Static)
    }
}

/// Overwrites this record's secret bytes before the memory is freed, rather than leaving them for
/// whatever a future allocation happens to reuse that memory for to see. Covers both a record
/// still sitting inside a `VaultData` (dropping the map drops every value in it, which runs this)
/// and a record that's been extracted/cloned out to live on its own (e.g. `get_record`'s return
/// value) -- either way, whichever scope lets go of the last copy triggers this. Best-effort, not
/// a substitute for keeping secrets out of long-lived structures in the first place: cloning a
/// record before this runs (e.g. into a `serde_json::Value` for a response) still leaves that
/// copy's bytes wherever the clone's allocation landed, unscrubbed.
impl CredentialRecord {
    /// The actual scrubbing logic, factored out of `Drop::drop` so it can be exercised directly
    /// in a test: calling `drop()` for real also triggers the subsequent field-by-field
    /// deallocation, and on this platform `free()` writes its own free-list bookkeeping into the
    /// first bytes of whatever it just freed -- so reading through a pointer after a *real* drop
    /// mostly observes the allocator's metadata, not whether this function did its job.
    fn scrub_secrets(&mut self) {
        self.value.zeroize();
        if let Some(secrets) = self.secrets.as_mut() {
            for v in secrets.values_mut() {
                v.zeroize();
            }
        }
    }
}

impl Drop for CredentialRecord {
    fn drop(&mut self) {
        self.scrub_secrets();
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VaultData {
    pub version: u8,
    #[serde(default)]
    pub types: HashMap<String, TypeRecord>,
    #[serde(default)]
    pub credentials: HashMap<String, HashMap<String, CredentialRecord>>,
}

impl VaultData {
    pub fn empty() -> Self {
        Self {
            version: 1,
            types: HashMap::new(),
            credentials: HashMap::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedFile {
    pub v: u8,
    pub alg: String,
    pub iv: String,
    pub tag: String,
    pub ct: String,
}

#[cfg(test)]
mod drop_zeroize_tests {
    use super::*;

    fn record_with_secrets(marker: &str) -> CredentialRecord {
        CredentialRecord {
            kind: None,
            value: marker.to_string(),
            config: None,
            secrets: Some([("field".to_string(), marker.to_string())].into()),
            state: None,
            generation: None,
            http: None,
            template: None,
            description: String::new(),
            attributes: HashMap::new(),
            created_at: String::new(),
            updated_at: String::new(),
        }
    }

    /// Regression test for `CredentialRecord`'s `Drop` impl (`value`/`secrets` must be
    /// overwritten, not just dropped as-is). Checks the logical content directly rather than
    /// peeking at the freed memory through a raw pointer: on this platform, `free()` writes its
    /// own free-list bookkeeping into the first bytes of whatever it just freed, so a real
    /// `drop()` followed by reading through a stale pointer mostly observes the allocator's
    /// metadata, not whether this code did its job -- that's not a meaningful test of this
    /// function (the `zeroize` crate's own test suite already covers the memory-level guarantee
    /// for `String`/`Vec<u8>`; what's actually ours to get wrong is *calling* it on every secret
    /// field, which this does check).
    #[test]
    fn scrub_secrets_clears_the_value_and_every_secret_field() {
        let mut record = record_with_secrets("SENSITIVE_MARKER_VALUE_0123456789");
        record.scrub_secrets();
        assert_eq!(record.value, "");
        assert_eq!(record.secrets.as_ref().unwrap()["field"], "");
    }

    #[test]
    fn dropping_a_credential_record_does_not_panic() {
        // Sanity check that Drop is wired up at all and doesn't itself blow up (e.g. on a record
        // with no secrets set).
        drop(record_with_secrets("whatever"));
        drop(CredentialRecord::default());
    }
}
