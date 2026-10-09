//! Generic JWT signing: e.g. the App Store Connect API (ES256), and other services that require
//! self-signed JWTs. All claims are fixed at setup time; the agent can only get short-lived JWTs
//! signed from this template, never the private key. Direct port of src/helper/protocols/jwt-kind.ts.

use crate::check::{int, json_record, now_sec, one_of, opt_str, str_req};
use crate::jwt::{check_jwt_key, sign_jwt, JWT_ALGORITHMS};
use kv_vault::{Kind, Vault, VaultError};
use serde_json::{json, Map, Value};

const RESERVED: [&str; 7] = ["iss", "sub", "aud", "iat", "exp", "nbf", "jti"];

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct JwtConfig {
    pub algorithm: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audience: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    pub lifetime_seconds: i64,
    pub claims: Map<String, Value>,
    pub header: Map<String, Value>,
}

pub fn validate_jwt_setup(
    config: &Value,
    secrets: &Value,
) -> kv_vault::Result<(JwtConfig, std::collections::HashMap<String, String>)> {
    let algorithm = one_of(
        config.get("algorithm"),
        "algorithm",
        &JWT_ALGORITHMS,
        "ES256",
    )?
    .to_string();
    let audience = match config.get("audience") {
        Some(Value::Array(a)) => Some(Value::Array(
            a.iter()
                .enumerate()
                .map(|(i, v)| str_req(Some(v), &format!("audience[{i}]"), 300).map(Value::String))
                .collect::<kv_vault::Result<_>>()?,
        )),
        other => opt_str(other, "audience", 300)?.map(Value::String),
    };
    let claims = json_record(config.get("claims"), "claims", 8192)?;
    for k in RESERVED {
        if claims.contains_key(k) {
            return Err(VaultError::new(&format!("claims 不能包含保留字段 {k}，请使用对应的专用参数"), &format!("claims must not contain reserved field {k}; use the corresponding dedicated parameter instead")));
        }
    }
    let header = json_record(config.get("header"), "header", 2048)?;
    for k in ["alg", "typ", "kid"] {
        if header.contains_key(k) {
            return Err(VaultError::new(
                &format!("header 不能包含 {k}"),
                &format!("header must not contain {k}"),
            ));
        }
    }
    let cfg = JwtConfig {
        algorithm: algorithm.clone(),
        issuer: opt_str(config.get("issuer"), "issuer", 300)?,
        subject: opt_str(config.get("subject"), "subject", 300)?,
        audience,
        key_id: opt_str(config.get("key_id"), "key_id", 200)?,
        lifetime_seconds: int(
            config.get("lifetime_seconds"),
            "lifetime_seconds",
            30,
            86_400,
            1200,
        )?,
        claims,
        header,
    };
    let key = check_jwt_key(&algorithm, &str_req(secrets.get("key"), "key", 10_000)?)?;
    Ok((cfg, [("key".to_string(), key)].into()))
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct JwtTokenResult {
    pub access_token: String,
    pub token_type: &'static str,
    pub expires_at: String,
}

pub fn jwt_token(vault: &Vault, ty: &str, name: &str) -> kv_vault::Result<JwtTokenResult> {
    let (ty, name, record) = vault.get_record(ty, name)?;
    if record.kind_or_static() != Kind::Jwt {
        return Err(VaultError::new(
            &format!("\"{ty}/{name}\" 不是 JWT 签发凭证"),
            &format!("\"{ty}/{name}\" is not a JWT signing credential"),
        ));
    }
    let cfg: JwtConfig = serde_json::from_value(record.config.clone().unwrap_or_default())
        .map_err(|_| VaultError::new("JWT 配置已损坏", "JWT configuration is corrupted"))?;
    let iat = now_sec();
    let mut claims = cfg.claims.clone();
    claims.insert("iat".into(), json!(iat));
    claims.insert("exp".into(), json!(iat + cfg.lifetime_seconds));
    if let Some(i) = &cfg.issuer {
        claims.insert("iss".into(), json!(i));
    }
    if let Some(s) = &cfg.subject {
        claims.insert("sub".into(), json!(s));
    }
    if let Some(a) = &cfg.audience {
        claims.insert("aud".into(), a.clone());
    }
    let mut header = cfg.header.clone();
    if let Some(kid) = &cfg.key_id {
        header.insert("kid".into(), json!(kid));
    }
    let key = record
        .secrets
        .as_ref()
        .and_then(|s| s.get("key"))
        .cloned()
        .unwrap_or_default();
    Ok(JwtTokenResult {
        access_token: sign_jwt(&cfg.algorithm, &key, &claims, &header)?,
        token_type: "Bearer",
        expires_at: chrono::DateTime::<chrono::Utc>::from(
            std::time::UNIX_EPOCH
                + std::time::Duration::from_secs((iat + cfg.lifetime_seconds) as u64),
        )
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_reserved_claims_and_header_fields() {
        assert!(validate_jwt_setup(
            &json!({"claims": {"iss": "x"}}),
            &json!({"key": "a very long enough hmac secret key for HS256"})
        )
        .is_err());
        assert!(validate_jwt_setup(
            &json!({"header": {"kid": "x"}}),
            &json!({"key": "a very long enough hmac secret key for HS256"})
        )
        .is_err());
    }

    #[test]
    fn signs_a_token_with_fixed_claims_plus_lifetime() {
        let (_tmp, vault) = test_vault();
        let (cfg, secrets) = validate_jwt_setup(
            &json!({"algorithm": "HS256", "issuer": "me", "lifetime_seconds": 60, "claims": {"custom": "x"}}),
            &json!({"key": "a very long enough hmac secret key for HS256"}),
        )
        .unwrap();
        vault
            .set_protocol(kv_vault::SetProtocolParams {
                r#type: "jwt".into(),
                name: "appstore".into(),
                kind: Kind::Jwt,
                config: serde_json::to_value(&cfg).unwrap(),
                secrets,
                description: None,
                type_description: None,
                overwrite: false,
            })
            .unwrap();
        let out = jwt_token(&vault, "jwt", "appstore").unwrap();
        let payload = crate::jwt::decode_jwt_payload(&out.access_token).unwrap();
        assert_eq!(payload["iss"], "me");
        assert_eq!(payload["custom"], "x");
        assert!(payload.contains_key("exp"));
    }

    fn test_vault() -> (tempfile::TempDir, Vault) {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("vault");
        let vault = Vault::new(&dir);
        vault.prepare().unwrap();
        if !vault.dir.join("master.key").exists() {
            // Explicit legacy fixture: production code never creates this file.
            std::fs::write(vault.dir.join("master.key"), [7u8; 32]).unwrap();
            std::fs::set_permissions(
                vault.dir.join("master.key"),
                <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o600),
            )
            .unwrap();
        }
        vault.init_legacy().unwrap();
        (tmp, vault)
    }
}
