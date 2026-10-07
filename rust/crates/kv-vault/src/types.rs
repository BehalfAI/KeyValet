use serde::{Deserialize, Serialize};
use std::collections::HashMap;

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
