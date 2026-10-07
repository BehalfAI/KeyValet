//! TOTP (RFC 6238) two-factor codes. The agent can only get the current code, never the seed.
//! Direct port of src/helper/protocols/totp.ts.

use crate::check::{int, one_of, opt_str, str_req};
use hmac::{Hmac, Mac};
use kv_vault::{Kind, Vault, VaultError};
use serde_json::{json, Value};
use sha1::Sha1;
use sha2::{Sha256, Sha512};

const ALGS: [&str; 3] = ["SHA1", "SHA256", "SHA512"];

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TotpConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
    pub digits: u32,
    pub period: u64,
    pub algorithm: String,
}

pub fn base32_decode(input: &str) -> kv_vault::Result<Vec<u8>> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let clean: String = input
        .to_uppercase()
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .collect();
    let clean = clean.trim_end_matches('=');
    let mut bits = 0u32;
    let mut value = 0u32;
    let mut out = Vec::new();
    for ch in clean.chars() {
        let idx = ALPHABET.iter().position(|&a| a as char == ch);
        let Some(idx) = idx else {
            return Err(VaultError::new(
                "TOTP 密钥不是合法的 Base32",
                "TOTP secret is not valid Base32",
            ));
        };
        value = (value << 5) | idx as u32;
        bits += 5;
        if bits >= 8 {
            out.push(((value >> (bits - 8)) & 0xff) as u8);
            bits -= 8;
        }
    }
    Ok(out)
}

fn hotp<D: Mac>(mut mac: D, counter: u64, digits: u32) -> String {
    mac.update(&counter.to_be_bytes());
    let result = mac.finalize().into_bytes();
    let offset = (result[result.len() - 1] & 0x0f) as usize;
    let bin = (u32::from_be_bytes(result[offset..offset + 4].try_into().unwrap()) & 0x7fff_ffff)
        % 10u32.pow(digits);
    format!("{bin:0width$}", width = digits as usize)
}

pub fn totp_at(key: &[u8], unix_seconds: f64, digits: u32, period: u64, alg: &str) -> String {
    let counter = (unix_seconds / period as f64).floor() as u64;
    match alg {
        "SHA256" => hotp(
            <Hmac<Sha256>>::new_from_slice(key).expect("HMAC accepts keys of any length"),
            counter,
            digits,
        ),
        "SHA512" => hotp(
            <Hmac<Sha512>>::new_from_slice(key).expect("HMAC accepts keys of any length"),
            counter,
            digits,
        ),
        _ => hotp(
            <Hmac<Sha1>>::new_from_slice(key).expect("HMAC accepts keys of any length"),
            counter,
            digits,
        ),
    }
}

/// `secret` can be either a Base32 seed or an `otpauth://totp/...` URI from a QR code.
pub fn validate_totp_setup(
    config: &Value,
    secrets: &Value,
) -> kv_vault::Result<(TotpConfig, std::collections::HashMap<String, String>)> {
    let raw = str_req(
        secrets.get("secret"),
        &kv_i18n::t("TOTP 密钥", "TOTP secret"),
        2000,
    )?;
    let raw = raw.trim();
    let mut seed = raw.to_string();
    let mut from_uri: serde_json::Map<String, Value> = Default::default();
    if raw.to_lowercase().starts_with("otpauth://") {
        let u = url::Url::parse(raw)
            .map_err(|_| VaultError::new("otpauth URI 格式错误", "Malformed otpauth URI"))?;
        if u.host_str().unwrap_or_default().to_lowercase() != "totp" {
            return Err(VaultError::new(
                "只支持 otpauth://totp（不支持 hotp）",
                "Only otpauth://totp is supported (hotp is not)",
            ));
        }
        let qs: std::collections::HashMap<String, String> = u
            .query_pairs()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        seed = str_req(
            qs.get("secret").map(|s| Value::String(s.clone())).as_ref(),
            &kv_i18n::t("otpauth URI 中的 secret", "secret in the otpauth URI"),
            500,
        )?;
        let label = urlencoding_decode(u.path().trim_start_matches('/'));
        let (label_issuer, label_account) = match label.split_once(':') {
            Some((i, a)) => (Some(i.to_string()), a.to_string()),
            None => (None, label),
        };
        if let Some(i) = qs.get("issuer").cloned().or(label_issuer) {
            from_uri.insert("issuer".into(), json!(i));
        }
        from_uri.insert("account".into(), json!(label_account.trim()));
        if let Some(d) = qs.get("digits").and_then(|s| s.parse::<i64>().ok()) {
            from_uri.insert("digits".into(), json!(d));
        }
        if let Some(p) = qs.get("period").and_then(|s| s.parse::<i64>().ok()) {
            from_uri.insert("period".into(), json!(p));
        }
        if let Some(a) = qs.get("algorithm") {
            from_uri.insert("algorithm".into(), json!(a.to_uppercase()));
        }
    }
    let key = base32_decode(&seed)?;
    if key.len() < 10 {
        return Err(VaultError::new(
            "TOTP 密钥太短（至少 80 位）",
            "TOTP secret is too short (at least 80 bits)",
        ));
    }
    let pick = |field: &str| -> Option<Value> {
        config
            .get(field)
            .cloned()
            .filter(|v| !v.is_null())
            .or_else(|| from_uri.get(field).cloned())
    };
    let cfg = TotpConfig {
        issuer: opt_str(pick("issuer").as_ref(), "issuer", 200)?,
        account: opt_str(pick("account").as_ref(), "account", 200)?,
        digits: int(pick("digits").as_ref(), "digits", 6, 8, 6)? as u32,
        period: int(pick("period").as_ref(), "period", 15, 300, 30)? as u64,
        algorithm: one_of(pick("algorithm").as_ref(), "algorithm", &ALGS, "SHA1")?.to_string(),
    };
    let cleaned_seed: String = seed
        .to_uppercase()
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .collect();
    let cleaned_seed = cleaned_seed.trim_end_matches('=').to_string();
    Ok((cfg, [("secret".to_string(), cleaned_seed)].into()))
}

/// Minimal percent-decoding (RFC 3986), matching JS `decodeURIComponent` closely enough for a
/// label made of ASCII + percent-escapes.
fn urlencoding_decode(s: &str) -> String {
    percent_encoding::percent_decode_str(s)
        .decode_utf8_lossy()
        .to_string()
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct TotpCodeResult {
    pub code: String,
    pub remaining_seconds: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_code: Option<String>,
    pub issuer: Option<String>,
    pub account: Option<String>,
}

pub fn totp_code(vault: &Vault, ty: &str, name: &str) -> kv_vault::Result<TotpCodeResult> {
    let (ty, name, record) = vault.get_record(ty, name)?;
    if record.kind_or_static() != Kind::Totp {
        return Err(VaultError::new(
            &format!("\"{ty}/{name}\" 不是 TOTP 凭证"),
            &format!("\"{ty}/{name}\" is not a TOTP credential"),
        ));
    }
    let cfg: TotpConfig = serde_json::from_value(record.config.clone().unwrap_or_default())
        .map_err(|_| VaultError::new("TOTP 配置已损坏", "TOTP configuration is corrupted"))?;
    let key = base32_decode(
        record
            .secrets
            .as_ref()
            .and_then(|s| s.get("secret"))
            .map(String::as_str)
            .unwrap_or(""),
    )?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64();
    let remaining = cfg.period - (now.floor() as u64 % cfg.period);
    Ok(TotpCodeResult {
        code: totp_at(&key, now, cfg.digits, cfg.period, &cfg.algorithm),
        remaining_seconds: remaining,
        next_code: if remaining <= 5 {
            Some(totp_at(
                &key,
                now + cfg.period as f64,
                cfg.digits,
                cfg.period,
                &cfg.algorithm,
            ))
        } else {
            None
        },
        issuer: cfg.issuer,
        account: cfg.account,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc6238_known_test_vector() {
        // RFC 6238 Appendix B test vector: ASCII secret "12345678901234567890", SHA1, at T=59s -> "94287082".
        let key = b"12345678901234567890";
        assert_eq!(totp_at(key, 59.0, 8, 30, "SHA1"), "94287082");
    }

    #[test]
    fn base32_decodes_a_known_vector() {
        // Well-known RFC 4648 test vector: base32("hello") = "NBSWY3DP".
        assert_eq!(base32_decode("NBSWY3DP").unwrap(), b"hello");
        assert_eq!(
            base32_decode("nbswy3dp").unwrap(),
            b"hello",
            "case-insensitive"
        );
        assert!(base32_decode("not-base32-1!!").is_err());
    }

    #[test]
    fn otpauth_uri_is_parsed_into_config() {
        let uri =
            "otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&digits=6&period=30";
        let (cfg, secrets) = validate_totp_setup(&json!({}), &json!({"secret": uri})).unwrap();
        assert_eq!(cfg.issuer.as_deref(), Some("GitHub"));
        assert_eq!(cfg.account.as_deref(), Some("alice"));
        assert_eq!(cfg.digits, 6);
        assert_eq!(secrets["secret"], "JBSWY3DPEHPK3PXP");
    }

    #[test]
    fn too_short_secret_is_rejected() {
        assert!(validate_totp_setup(&json!({}), &json!({"secret": "AAAA"})).is_err());
    }
}
