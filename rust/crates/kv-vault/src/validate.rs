use crate::error::{Result, VaultError};
use regex::Regex;
use std::collections::HashMap;
use std::sync::LazyLock;

static TYPE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-z0-9][a-z0-9_.\-]{0,63}$").unwrap());
static NAME_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-z0-9][a-z0-9_.@:\-]{0,127}$").unwrap());
static ATTR_KEY_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-zA-Z0-9_.\-]{1,64}$").unwrap());

pub const MAX_VALUE_LENGTH: usize = 64 * 1024;
const MAX_DESCRIPTION_LENGTH: usize = 500;
const MAX_ATTRIBUTES: usize = 20;
const MAX_ATTRIBUTE_LENGTH: usize = 1000;
pub const MAX_PROTOCOL_BYTES: usize = 128 * 1024;

/// JS string `.length` counts UTF-16 code units, not bytes or Unicode scalar values; match that
/// exactly so length limits behave identically to the TS implementation for all inputs.
fn utf16_len(s: &str) -> usize {
    s.encode_utf16().count()
}

pub fn normalize_type(input: &str) -> Result<String> {
    let ty = input.trim().to_lowercase();
    if !TYPE_RE.is_match(&ty) {
        return Err(VaultError::new(
            &format!("非法的凭证类型 \"{input}\"：只允许小写字母、数字、_ . -，以字母或数字开头，最长 64"),
            &format!("Invalid credential type \"{input}\": only lowercase letters, digits, _ . - are allowed, must start with a letter or digit, max 64 characters"),
        ));
    }
    Ok(ty)
}

pub fn normalize_name(input: &str) -> Result<String> {
    let n = input.trim().to_lowercase();
    if !NAME_RE.is_match(&n) {
        return Err(VaultError::new(
            &format!("非法的凭证名 \"{input}\"：只允许小写字母、数字、_ . @ : -，以字母或数字开头，最长 128"),
            &format!("Invalid credential name \"{input}\": only lowercase letters, digits, _ . @ : - are allowed, must start with a letter or digit, max 128 characters"),
        ));
    }
    Ok(n)
}

pub fn check_description(d: Option<&str>) -> Result<String> {
    let d = match d {
        None => return Ok(String::new()),
        Some(d) => d,
    };
    if utf16_len(d) > MAX_DESCRIPTION_LENGTH {
        return Err(VaultError::new(
            &format!("description 必须是不超过 {MAX_DESCRIPTION_LENGTH} 字符的字符串"),
            &format!("description must be a string of at most {MAX_DESCRIPTION_LENGTH} characters"),
        ));
    }
    Ok(d.to_string())
}

pub fn check_value(v: Option<&str>) -> Result<String> {
    let v = v.unwrap_or("");
    let len = utf16_len(v);
    if len == 0 || len > MAX_VALUE_LENGTH {
        return Err(VaultError::new(
            &format!("凭证值必须是 1~{MAX_VALUE_LENGTH} 字符的字符串"),
            &format!("Credential value must be a string of 1-{MAX_VALUE_LENGTH} characters"),
        ));
    }
    Ok(v.to_string())
}

pub fn check_attributes(a: Option<&HashMap<String, String>>) -> Result<HashMap<String, String>> {
    let a = match a {
        None => return Ok(HashMap::new()),
        Some(a) => a,
    };
    if a.len() > MAX_ATTRIBUTES {
        return Err(VaultError::new(
            &format!("attributes 最多 {MAX_ATTRIBUTES} 项"),
            &format!("attributes may have at most {MAX_ATTRIBUTES} entries"),
        ));
    }
    let mut out = HashMap::with_capacity(a.len());
    for (k, v) in a {
        if !ATTR_KEY_RE.is_match(k) {
            return Err(VaultError::new(
                &format!("非法的 attribute 名 \"{k}\""),
                &format!("Invalid attribute name \"{k}\""),
            ));
        }
        if utf16_len(v) > MAX_ATTRIBUTE_LENGTH {
            return Err(VaultError::new(
                &format!("attribute \"{k}\" 必须是不超过 {MAX_ATTRIBUTE_LENGTH} 字符的字符串"),
                &format!("attribute \"{k}\" must be a string of at most {MAX_ATTRIBUTE_LENGTH} characters"),
            ));
        }
        out.insert(k.clone(), v.clone());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_type_accepts_lowercase_and_rejects_the_rest() {
        assert_eq!(normalize_type("API_Key").unwrap(), "api_key");
        assert!(normalize_type("").is_err());
        assert!(normalize_type("_leading").is_err());
        assert!(normalize_type("has space").is_err());
    }

    #[test]
    fn normalize_name_allows_at_and_colon() {
        assert_eq!(
            normalize_name("support@EXAMPLE.com").unwrap(),
            "support@example.com"
        );
        assert_eq!(normalize_name("aws:prod").unwrap(), "aws:prod");
    }

    #[test]
    fn check_value_rejects_empty_and_oversized() {
        assert!(check_value(None).is_err());
        assert!(check_value(Some("")).is_err());
        assert_eq!(check_value(Some("ok")).unwrap(), "ok");
        let too_long = "x".repeat(MAX_VALUE_LENGTH + 1);
        assert!(check_value(Some(&too_long)).is_err());
    }

    #[test]
    fn check_attributes_enforces_key_pattern_and_limits() {
        let mut attrs = HashMap::new();
        attrs.insert("host".to_string(), "example.com".to_string());
        assert_eq!(check_attributes(Some(&attrs)).unwrap().len(), 1);

        let mut bad_key = HashMap::new();
        bad_key.insert("bad key!".to_string(), "x".to_string());
        assert!(check_attributes(Some(&bad_key)).is_err());

        let mut too_many = HashMap::new();
        for i in 0..21 {
            too_many.insert(format!("k{i}"), "v".to_string());
        }
        assert!(check_attributes(Some(&too_many)).is_err());
    }
}
