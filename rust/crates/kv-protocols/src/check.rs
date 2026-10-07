//! Field validation for protocol config. Input comes from the MCP server (indirectly from the
//! agent), so it is always treated as untrusted. Direct port of src/helper/protocols/check.ts.

use kv_vault::VaultError;
use serde_json::Value;

fn utf16_len(s: &str) -> usize {
    s.encode_utf16().count()
}

pub fn str_req(v: Option<&Value>, what: &str, max: usize) -> kv_vault::Result<String> {
    let s = v.and_then(Value::as_str);
    match s {
        Some(s) if !s.is_empty() && utf16_len(s) <= max => Ok(s.to_string()),
        _ => Err(VaultError::new(
            &format!("{what} 必须是 1~{max} 字符的字符串"),
            &format!("{what} must be a string of 1-{max} characters"),
        )),
    }
}

pub fn opt_str(v: Option<&Value>, what: &str, max: usize) -> kv_vault::Result<Option<String>> {
    match v {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) if s.is_empty() => Ok(None),
        other => str_req(other, what, max).map(Some),
    }
}

pub fn int(v: Option<&Value>, what: &str, min: i64, max: i64, dflt: i64) -> kv_vault::Result<i64> {
    match v {
        None | Some(Value::Null) => Ok(dflt),
        Some(Value::Number(n)) => {
            let i = n.as_i64().filter(|i| *i >= min && *i <= max);
            i.ok_or_else(|| {
                VaultError::new(
                    &format!("{what} 必须是 {min}~{max} 之间的整数"),
                    &format!("{what} must be an integer between {min} and {max}"),
                )
            })
        }
        _ => Err(VaultError::new(
            &format!("{what} 必须是 {min}~{max} 之间的整数"),
            &format!("{what} must be an integer between {min} and {max}"),
        )),
    }
}

pub fn one_of<'a>(
    v: Option<&Value>,
    what: &str,
    allowed: &[&'a str],
    dflt: &'a str,
) -> kv_vault::Result<&'a str> {
    match v {
        None | Some(Value::Null) => Ok(dflt),
        Some(Value::String(s)) => allowed
            .iter()
            .find(|a| **a == s)
            .copied()
            .ok_or_else(|| bad_one_of(what, allowed)),
        _ => Err(bad_one_of(what, allowed)),
    }
}

fn bad_one_of(what: &str, allowed: &[&str]) -> VaultError {
    let list = allowed.join(" / ");
    VaultError::new(
        &format!("{what} 必须是 {list} 之一"),
        &format!("{what} must be one of {list}"),
    )
}

pub fn str_list(v: Option<&Value>, what: &str, max_items: usize) -> kv_vault::Result<Vec<String>> {
    match v {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(a)) if a.len() <= max_items => a
            .iter()
            .enumerate()
            .map(|(i, x)| {
                let s = str_req(Some(x), &format!("{what}[{i}]"), 500)?;
                if s.chars().any(char::is_whitespace) {
                    return Err(VaultError::new(
                        &format!("{what}[{i}] 不能包含空白字符"),
                        &format!("{what}[{i}] must not contain whitespace"),
                    ));
                }
                Ok(s)
            })
            .collect(),
        _ => Err(VaultError::new(
            &format!("{what} 必须是最多 {max_items} 项的字符串数组"),
            &format!("{what} must be an array of at most {max_items} strings"),
        )),
    }
}

pub fn str_record(
    v: Option<&Value>,
    what: &str,
    max_items: usize,
) -> kv_vault::Result<std::collections::HashMap<String, String>> {
    let obj = match v {
        None | Some(Value::Null) => return Ok(Default::default()),
        Some(Value::Object(o)) => o,
        _ => {
            return Err(VaultError::new(
                &format!("{what} 必须是对象"),
                &format!("{what} must be an object"),
            ))
        }
    };
    if obj.len() > max_items {
        return Err(VaultError::new(
            &format!("{what} 最多 {max_items} 项"),
            &format!("{what} may have at most {max_items} entries"),
        ));
    }
    let mut out = std::collections::HashMap::new();
    for (k, x) in obj {
        if !key_ok(k) {
            return Err(VaultError::new(
                &format!("{what} 的键 \"{k}\" 非法"),
                &format!("{what} has an invalid key \"{k}\""),
            ));
        }
        out.insert(k.clone(), str_req(Some(x), &format!("{what}.{k}"), 1000)?);
    }
    Ok(out)
}

fn key_ok(k: &str) -> bool {
    !k.is_empty()
        && k.len() <= 64
        && k.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
}

pub fn json_record(
    v: Option<&Value>,
    what: &str,
    max_bytes: usize,
) -> kv_vault::Result<serde_json::Map<String, Value>> {
    let obj = match v {
        None | Some(Value::Null) => return Ok(Default::default()),
        Some(Value::Object(o)) => o,
        _ => {
            return Err(VaultError::new(
                &format!("{what} 必须是对象"),
                &format!("{what} must be an object"),
            ))
        }
    };
    if serde_json::to_string(obj)
        .map(|s| s.len())
        .unwrap_or(usize::MAX)
        > max_bytes
    {
        return Err(VaultError::new(
            &format!("{what} 过大"),
            &format!("{what} is too large"),
        ));
    }
    Ok(obj.clone())
}

pub fn now_sec() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
