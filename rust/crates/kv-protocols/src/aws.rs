//! AWS: exchange a long-term access key for temporary credentials via STS (GetSessionToken or
//! AssumeRole). The long-term secret key never leaves the root helper; the agent only gets
//! credentials valid for at most a few hours. Direct port of src/helper/protocols/aws.ts.

use crate::check::{int, opt_str, str_req};
use crate::expiry::{is_fresh, iso_millis};
use crate::http::{http_request, Method};
use crate::totp::totp_code;
use hmac::{Hmac, Mac};
use kv_vault::{Kind, Vault, VaultError};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::sync::LazyLock;
use zeroize::{Zeroize, Zeroizing};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MfaTotpRef {
    pub r#type: String,
    pub name: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AwsConfig {
    pub access_key_id: String,
    pub region: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role_arn: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,
    pub role_session_name: String,
    pub duration_seconds: i64,
    /// MFA device ARN; paired with `mfa_totp` to automatically generate the verification code.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mfa_serial: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mfa_totp: Option<MfaTotpRef>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct SessionCreds {
    access_key_id: String,
    secret_access_key: Zeroizing<String>,
    session_token: Zeroizing<String>,
    expiration: i64,
}

static STS_ENDPOINT_OVERRIDE: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);
/// Test-only: send STS requests to a local mock server instead.
pub fn set_sts_endpoint_for_tests(url: Option<&str>) {
    *STS_ENDPOINT_OVERRIDE.lock().unwrap() = url.map(str::to_string);
}

fn sha256_hex(s: &[u8]) -> String {
    hex(&Sha256::digest(s))
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
fn hmac_sha256(key: &[u8], s: &str) -> Vec<u8> {
    let mut mac = <Hmac<Sha256>>::new_from_slice(key).expect("HMAC accepts keys of any length");
    mac.update(s.as_bytes());
    mac.finalize().into_bytes().to_vec()
}

pub struct SigV4Input<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub query: &'a str,
    pub headers: &'a [(&'a str, &'a str)],
    pub body: &'a str,
    pub region: &'a str,
    pub service: &'a str,
    pub access_key_id: &'a str,
    pub secret_access_key: &'a str,
    pub amz_date: &'a str,
}

/// AWS Signature Version 4; returns the `Authorization` header value.
pub fn sigv4(p: &SigV4Input) -> String {
    let mut names: Vec<String> = p.headers.iter().map(|(k, _)| k.to_lowercase()).collect();
    names.sort();
    let lower: std::collections::HashMap<String, String> = p
        .headers
        .iter()
        .map(|(k, v)| (k.to_lowercase(), v.to_string()))
        .collect();
    // Collapse internal whitespace runs to a single space, matching JS's `.replace(/\s+/g, " ")`.
    let canonical_headers: String = names
        .iter()
        .map(|h| format!("{h}:{}\n", collapse_whitespace(lower[h].trim())))
        .collect();
    let signed_headers = names.join(";");
    let canonical_request = [
        p.method,
        p.path,
        p.query,
        &canonical_headers,
        &signed_headers,
        &sha256_hex(p.body.as_bytes()),
    ]
    .join("\n");
    let date = &p.amz_date[..8];
    let scope = format!("{date}/{}/{}/aws4_request", p.region, p.service);
    let string_to_sign = [
        "AWS4-HMAC-SHA256",
        p.amz_date,
        &scope,
        &sha256_hex(canonical_request.as_bytes()),
    ]
    .join("\n");
    let k_date = hmac_sha256(format!("AWS4{}", p.secret_access_key).as_bytes(), date);
    let k_region = hmac_sha256(&k_date, p.region);
    let k_service = hmac_sha256(&k_region, p.service);
    let k_signing = hmac_sha256(&k_service, "aws4_request");
    let signature = hex(&hmac_sha256(&k_signing, &string_to_sign));
    format!("AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed_headers}, Signature={signature}", p.access_key_id)
}

fn collapse_whitespace(s: &str) -> String {
    static RE: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(r"\s+").unwrap());
    RE.replace_all(s, " ").to_string()
}

pub fn validate_aws_setup(
    config: &Value,
    secrets: &Value,
) -> kv_vault::Result<(AwsConfig, std::collections::HashMap<String, String>)> {
    let akid = str_req(config.get("access_key_id"), "access_key_id", 128)?;
    if !regex_match(&akid, r"^AKIA[A-Z0-9]{12,124}$") {
        return Err(VaultError::new(
            "access_key_id 应为长期密钥（AKIA 开头）",
            "access_key_id must be a long-term key (starting with AKIA)",
        ));
    }
    let secret = str_req(secrets.get("secret_access_key"), "secret_access_key", 256)?;
    if !regex_match(&secret, r"^[A-Za-z0-9/+=]{20,256}$") {
        return Err(VaultError::new(
            "secret_access_key 格式不对",
            "secret_access_key has an invalid format",
        ));
    }
    let region = config
        .get("region")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .unwrap_or("us-east-1")
        .to_string();
    if !regex_match(&region, r"^[a-z]{2}(-gov)?-[a-z]+-\d$") {
        return Err(VaultError::new(
            &format!("非法或不支持的 region：{region}"),
            &format!("Invalid or unsupported region: {region}"),
        ));
    }
    let role_arn = opt_str(config.get("role_arn"), "role_arn", 2048)?;
    if let Some(r) = &role_arn {
        if !regex_match(r, r"^arn:aws[a-z-]*:iam::\d{12}:role/[\w+=,.@/-]+$") {
            return Err(VaultError::new(
                "role_arn 格式不对",
                "role_arn has an invalid format",
            ));
        }
    }
    let mfa_serial = opt_str(config.get("mfa_serial"), "mfa_serial", 256)?;
    if let Some(m) = &mfa_serial {
        if !(regex_match(m, r"^arn:aws[a-z-]*:iam::\d{12}:mfa/[\w+=,.@/-]+$")
            || regex_match(m, r"^GAHT[A-Z0-9]+$"))
        {
            return Err(VaultError::new(
                "mfa_serial 格式不对",
                "mfa_serial has an invalid format",
            ));
        }
    }
    let mfa_totp = match config.get("mfa_totp") {
        Some(Value::Object(m)) => {
            let r#ref = MfaTotpRef {
                r#type: str_req(m.get("type"), "mfa_totp.type", 64)?,
                name: str_req(m.get("name"), "mfa_totp.name", 128)?,
            };
            if mfa_serial.is_none() {
                return Err(VaultError::new(
                    "设置 mfa_totp 时必须同时设置 mfa_serial",
                    "mfa_serial must be set when mfa_totp is set",
                ));
            }
            Some(r#ref)
        }
        _ => None,
    };
    let session_name = config
        .get("role_session_name")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .unwrap_or("keyvalet")
        .to_string();
    if !regex_match(&session_name, r"^[\w+=,.@-]{2,64}$") {
        return Err(VaultError::new(
            "role_session_name 格式不对",
            "role_session_name has an invalid format",
        ));
    }
    let max_duration = if role_arn.is_some() { 43_200 } else { 129_600 };
    let cfg = AwsConfig {
        access_key_id: akid,
        region,
        role_arn,
        external_id: opt_str(config.get("external_id"), "external_id", 1224)?,
        role_session_name: session_name,
        duration_seconds: int(
            config.get("duration_seconds"),
            "duration_seconds",
            900,
            max_duration,
            3600,
        )?,
        mfa_serial,
        mfa_totp,
    };
    Ok((cfg, [("secret_access_key".to_string(), secret)].into()))
}

fn regex_match(s: &str, pattern: &str) -> bool {
    regex::Regex::new(pattern).unwrap().is_match(s)
}

/// An AWS error code such as `ExpiredToken` or `AccessDenied`; anything else is dropped.
fn sts_error_code(text: &str) -> Option<&str> {
    xml_tag(text, "Code").filter(|c| {
        !c.is_empty() && c.len() <= 64 && c.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.')
    })
}

fn xml_tag<'a>(xml: &'a str, tag: &str) -> Option<&'a str> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&close)? + start;
    Some(&xml[start..end])
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct AwsCredentialsOut {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: String,
    pub expiration: String,
    pub region: String,
    pub role_arn: Option<String>,
}

impl Drop for AwsCredentialsOut {
    fn drop(&mut self) {
        self.secret_access_key.zeroize();
        self.session_token.zeroize();
    }
}

pub async fn aws_credentials(
    vault: &Vault,
    ty: &str,
    name: &str,
    duration_seconds: Option<i64>,
    force: bool,
) -> kv_vault::Result<AwsCredentialsOut> {
    let (ty, name, record) = vault.get_record(ty, name)?;
    if record.kind_or_static() != Kind::Aws {
        return Err(VaultError::new(
            &format!("\"{ty}/{name}\" 不是 AWS 凭证"),
            &format!("\"{ty}/{name}\" is not an AWS credential"),
        ));
    }
    let cfg: AwsConfig = serde_json::from_value(record.config.clone().unwrap_or_default())
        .map_err(|_| VaultError::new("AWS 配置已损坏", "AWS configuration is corrupted"))?;
    let max_duration = if cfg.role_arn.is_some() {
        43_200
    } else {
        129_600
    };
    let duration = duration_seconds
        .map(|d| d.clamp(900, max_duration))
        .unwrap_or(cfg.duration_seconds);

    if let Some(cached) = record
        .state
        .as_ref()
        .and_then(|s| s.get("session"))
        .and_then(|v| <SessionCreds as serde::Deserialize>::deserialize(v).ok())
    {
        if !force && duration_seconds.is_none() && is_fresh(cached.expiration, 5 * 60_000) {
            return out(&cached, &cfg);
        }
    }

    let mut form: Vec<(String, String)> = vec![
        ("Version".into(), "2011-06-15".into()),
        ("DurationSeconds".into(), duration.to_string()),
    ];
    if let Some(role_arn) = &cfg.role_arn {
        form.push(("Action".into(), "AssumeRole".into()));
        form.push(("RoleArn".into(), role_arn.clone()));
        form.push(("RoleSessionName".into(), cfg.role_session_name.clone()));
        if let Some(eid) = &cfg.external_id {
            form.push(("ExternalId".into(), eid.clone()));
        }
    } else {
        form.push(("Action".into(), "GetSessionToken".into()));
    }
    let mut token_code: Option<String> = None;
    if let Some(mfa_serial) = &cfg.mfa_serial {
        let Some(mfa_totp) = &cfg.mfa_totp else {
            return Err(VaultError::new(
                "配置了 mfa_serial 但没有关联 TOTP 凭证（mfa_totp）",
                "mfa_serial is configured but no TOTP credential is linked (mfa_totp)",
            ));
        };
        form.push(("SerialNumber".into(), mfa_serial.clone()));
        let mut mfa = totp_code(vault, &mfa_totp.r#type, &mfa_totp.name)?;
        // AWS rejects reusing the same code, so if it matches the last one used, wait for the next period.
        let last = record
            .state
            .as_ref()
            .and_then(|s| s.get("last_mfa_code"))
            .and_then(Value::as_str);
        if Some(mfa.code.as_str()) == last {
            tokio::time::sleep(std::time::Duration::from_secs(mfa.remaining_seconds + 1)).await;
            mfa = totp_code(vault, &mfa_totp.r#type, &mfa_totp.name)?;
        }
        form.push(("TokenCode".into(), mfa.code.clone()));
        token_code = Some(mfa.code);
    }

    let host = format!(
        "sts.{}.amazonaws.com{}",
        cfg.region,
        if cfg.region.starts_with("cn-") {
            ".cn"
        } else {
            ""
        }
    );
    let body = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(form.iter().map(|(k, v)| (k.as_str(), v.as_str())))
        .finish();
    let amz_date = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let headers = [
        (
            "content-type",
            "application/x-www-form-urlencoded; charset=utf-8",
        ),
        ("host", host.as_str()),
        ("x-amz-date", amz_date.as_str()),
    ];
    let authorization = sigv4(&SigV4Input {
        method: "POST",
        path: "/",
        query: "",
        headers: &headers,
        body: &body,
        region: &cfg.region,
        service: "sts",
        access_key_id: &cfg.access_key_id,
        secret_access_key: record
            .secrets
            .as_ref()
            .and_then(|s| s.get("secret_access_key"))
            .map(String::as_str)
            .unwrap_or(""),
        amz_date: &amz_date,
    });
    let sts_url = STS_ENDPOINT_OVERRIDE
        .lock()
        .unwrap()
        .clone()
        .unwrap_or_else(|| format!("https://{host}/"));
    let send_headers = [
        ("content-type", headers[0].1),
        ("x-amz-date", amz_date.as_str()),
        ("Authorization", authorization.as_str()),
        ("Accept", "application/xml"),
    ];
    let r = http_request(&sts_url, Method::Post, &send_headers, Some(body)).await?;
    if r.status >= 300 {
        // Only the status and a well-formed error code: provider messages can echo request
        // details, and are never needed to act on the error.
        let code = sts_error_code(&r.text)
            .map(|c| format!("：{c}"))
            .unwrap_or_default();
        let code_en = sts_error_code(&r.text)
            .map(|c| format!(": {c}"))
            .unwrap_or_default();
        return Err(VaultError::new(
            &format!("AWS STS 返回错误（HTTP {}）{code}", r.status),
            &format!("AWS STS returned an error (HTTP {}){code_en}", r.status),
        ));
    }
    let creds = SessionCreds {
        access_key_id: xml_tag(&r.text, "AccessKeyId")
            .unwrap_or_default()
            .to_string(),
        secret_access_key: Zeroizing::new(
            xml_tag(&r.text, "SecretAccessKey")
                .unwrap_or_default()
                .to_string(),
        ),
        session_token: Zeroizing::new(
            xml_tag(&r.text, "SessionToken")
                .unwrap_or_default()
                .to_string(),
        ),
        expiration: xml_tag(&r.text, "Expiration")
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
            .map(|d| d.timestamp_millis())
            .unwrap_or(0),
    };
    if creds.access_key_id.is_empty()
        || creds.secret_access_key.is_empty()
        || creds.session_token.is_empty()
        || creds.expiration == 0
        || iso_millis(creds.expiration).is_none()
    {
        return Err(VaultError::new(
            "AWS STS 响应缺少凭证字段",
            "AWS STS response is missing credential fields",
        ));
    }
    let gen = record.generation.clone();
    vault.patch_record(&ty, &name, Kind::Aws, gen.as_deref(), |rec| {
        if duration_seconds.is_none() {
            rec.set_state_field("session", serde_json::to_value(&creds).unwrap());
        }
        if let Some(code) = &token_code {
            rec.set_state_field("last_mfa_code", json!(code));
        }
    })?;
    out(&creds, &cfg)
}

fn out(c: &SessionCreds, cfg: &AwsConfig) -> kv_vault::Result<AwsCredentialsOut> {
    let expiration = iso_millis(c.expiration).ok_or_else(|| {
        VaultError::new("AWS 凭证有效期无效", "AWS credential expiration is invalid")
    })?;
    Ok(AwsCredentialsOut {
        access_key_id: c.access_key_id.clone(),
        secret_access_key: c.secret_access_key.to_string(),
        session_token: c.session_token.to_string(),
        expiration,
        region: cfg.region.clone(),
        role_arn: cfg.role_arn.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sts_errors_keep_only_a_well_formed_code() {
        let body = "<ErrorResponse><Error><Code>SignatureDoesNotMatch</Code><Message>key AKIAEXAMPLE…</Message></Error></ErrorResponse>";
        assert_eq!(sts_error_code(body), Some("SignatureDoesNotMatch"));
        assert_eq!(sts_error_code("<Code>bad code; AKIA…</Code>"), None);
        // Multibyte text without a code must not panic (the old byte slice could).
        assert_eq!(sts_error_code(&"错误".repeat(150)), None);
    }

    #[test]
    fn validate_rejects_malformed_fields() {
        assert!(validate_aws_setup(
            &json!({"access_key_id": "not-akia"}),
            &json!({"secret_access_key": "x".repeat(25)})
        )
        .is_err());
        assert!(validate_aws_setup(
            &json!({"access_key_id": format!("AKIA{}", "A".repeat(16))}),
            &json!({"secret_access_key": "short"})
        )
        .is_err());
        assert!(validate_aws_setup(
            &json!({"access_key_id": format!("AKIA{}", "A".repeat(16)), "region": "not-a-region"}),
            &json!({"secret_access_key": "x".repeat(25)})
        )
        .is_err());
    }

    #[test]
    fn validate_accepts_a_well_formed_setup_and_defaults_region_and_duration() {
        let (cfg, secrets) = validate_aws_setup(
            &json!({"access_key_id": format!("AKIA{}", "A".repeat(16))}),
            &json!({"secret_access_key": "x".repeat(25)}),
        )
        .unwrap();
        assert_eq!(cfg.region, "us-east-1");
        assert_eq!(cfg.duration_seconds, 3600);
        assert_eq!(cfg.role_session_name, "keyvalet");
        assert_eq!(secrets["secret_access_key"], "x".repeat(25));
    }

    // AWS's own documented SigV4 test suite vector (GetCallerIdentity-style minimal canonical case)
    // is intricate to reproduce exactly; instead this checks the well-known structural properties:
    // deterministic for the same input, and sensitive to any input change.
    #[test]
    fn sigv4_is_deterministic_and_input_sensitive() {
        let base = SigV4Input {
            method: "POST",
            path: "/",
            query: "",
            headers: &[
                ("host", "sts.us-east-1.amazonaws.com"),
                ("x-amz-date", "20250101T000000Z"),
            ],
            body: "Action=GetSessionToken&Version=2011-06-15",
            region: "us-east-1",
            service: "sts",
            access_key_id: "AKIAEXAMPLE",
            secret_access_key: "secretkeyexample",
            amz_date: "20250101T000000Z",
        };
        let a = sigv4(&base);
        let b = sigv4(&base);
        assert_eq!(a, b);
        assert!(a.starts_with(
            "AWS4-HMAC-SHA256 Credential=AKIAEXAMPLE/20250101/us-east-1/sts/aws4_request"
        ));
        let changed = SigV4Input {
            body: "Action=GetSessionToken&Version=2011-06-16",
            ..base
        };
        assert_ne!(sigv4(&base), sigv4(&changed));
    }
}
