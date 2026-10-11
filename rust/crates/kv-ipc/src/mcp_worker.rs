//! Public launch context for a service-created Windows MCP worker. No environment block,
//! executable, session identity or private input is accepted from the caller.
use serde::{Deserialize, Serialize};

pub const PROTOCOL: u32 = 1;
pub const CHANNEL_PREFIX: &str = r"\\.\pipe\keyvalet-mcp-worker-";

pub fn valid_channel(channel: &str) -> bool {
    channel
        .strip_prefix(CHANNEL_PREFIX)
        .is_some_and(|id| id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit()))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Context {
    pub cwd: String,
    pub ttl_minutes: u64,
    pub grant_mode: Option<String>,
    pub lang: String,
}
impl Context {
    pub fn valid(&self) -> bool {
        !self.cwd.is_empty()
            && self.cwd.len() <= 32_768
            && !self.cwd.contains('\0')
            // Zero disables expiry; finite sessions are bounded to a year so both duration
            // arithmetic and platform timestamps remain representable.
            && self.ttl_minutes <= 525_600
            && matches!(self.lang.as_str(), "en" | "zh")
            && self.grant_mode.as_deref().is_none_or(|mode| {
                matches!(
                    mode,
                    "per_use" | "per_credential" | "per_session" | "remember" | "all"
                )
            })
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Launch {
    pub op: String,
    pub protocol: u32,
    pub context: Context,
}
impl Launch {
    pub fn valid(&self) -> bool {
        self.op == "mcp-launch" && self.protocol == PROTOCOL && self.context.valid()
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerHello {
    pub op: String,
    pub protocol: u32,
}
impl WorkerHello {
    pub fn valid(&self) -> bool {
        self.op == "mcp-worker" && self.protocol == PROTOCOL
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Started {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ready {
    pub ok: bool,
    pub context: Context,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn launch_context_cannot_select_a_program_environment_or_session() {
        let value = json!({"op":"mcp-launch", "protocol":PROTOCOL,
            "context":{"cwd":"C:\\项目", "ttl_minutes":30, "grant_mode":"per_use", "lang":"zh"}});
        assert!(serde_json::from_value::<Launch>(value.clone())
            .unwrap()
            .valid());
        for (field, extra) in [
            ("environment", json!({"PATH":"evil"})),
            ("session_id", json!(99)),
            ("executable", json!("evil.exe")),
        ] {
            let mut altered = value.clone();
            altered[field] = extra;
            assert!(serde_json::from_value::<Launch>(altered).is_err());
        }
        for (field, bad) in [
            ("ttl_minutes", json!(u64::MAX)),
            ("cwd", json!("C:\\x\u{0000}")),
            ("grant_mode", json!("unchecked")),
            ("lang", json!("unknown")),
        ] {
            let mut altered = value.clone();
            altered["context"][field] = bad;
            assert!(!serde_json::from_value::<Launch>(altered).unwrap().valid());
        }
    }

    #[test]
    fn worker_channel_is_a_single_fixed_namespace() {
        let valid = format!("{CHANNEL_PREFIX}{}", "ab".repeat(16));
        assert!(valid_channel(&valid));
        for invalid in [
            r"\\.\pipe\keyvalet-helper",
            r"\\server\pipe\keyvalet-mcp-worker-0000",
            r"\\.\pipe\keyvalet-mcp-worker-extra-0123456789abcdef0123456789abcdef",
        ] {
            assert!(!valid_channel(invalid));
        }
        assert!(!valid_channel(&format!("{valid}\"")));
    }

    fn context() -> Context {
        Context {
            cwd: r"C:\project".into(),
            ttl_minutes: 0,
            grant_mode: None,
            lang: "en".into(),
        }
    }

    #[test]
    fn launch_context_accepts_only_the_documented_languages_and_grant_modes() {
        for lang in ["en", "zh"] {
            for mode in [
                None,
                Some("per_use"),
                Some("per_credential"),
                Some("per_session"),
                Some("remember"),
                Some("all"),
            ] {
                let mut context = context();
                context.lang = lang.into();
                context.grant_mode = mode.map(str::to_owned);
                assert!(context.valid());
            }
        }
        for mode in ["", "ALL", "per-use", " all", "all\0"] {
            let mut context = context();
            context.grant_mode = Some(mode.into());
            assert!(!context.valid());
        }
        for lang in ["", "EN", "zh-CN", " en", "en\0"] {
            let mut context = context();
            context.lang = lang.into();
            assert!(!context.valid());
        }
    }

    #[test]
    fn launch_context_bounds_are_exact_and_measured_in_utf8_bytes() {
        let mut context = context();
        for ttl in [0, 1, 525_600] {
            context.ttl_minutes = ttl;
            assert!(context.valid());
        }
        context.ttl_minutes = 525_601;
        assert!(!context.valid());
        context.ttl_minutes = 0;
        for cwd in ["x".repeat(32_768), "中".repeat(10_922) + "ab"] {
            assert_eq!(cwd.len(), 32_768);
            context.cwd = cwd;
            assert!(context.valid());
            context.cwd.push('x');
            assert!(!context.valid());
        }
        for cwd in ["", "\0", "C:\\x\0y"] {
            context.cwd = cwd.into();
            assert!(!context.valid());
        }
    }

    #[test]
    fn malformed_nested_context_cannot_bypass_launch_schema() {
        let valid = serde_json::to_value(Launch {
            op: "mcp-launch".into(),
            protocol: PROTOCOL,
            context: context(),
        })
        .unwrap();
        for field in ["cwd", "ttl_minutes", "lang"] {
            let mut missing = valid.clone();
            missing["context"].as_object_mut().unwrap().remove(field);
            assert!(serde_json::from_value::<Launch>(missing).is_err());
        }
        for (field, value) in [
            ("cwd", serde_json::Value::Null),
            ("ttl_minutes", json!(-1)),
            ("ttl_minutes", json!(1.5)),
            ("ttl_minutes", json!("30")),
            ("grant_mode", json!(false)),
            ("lang", json!(["en"])),
            ("environment", json!({"PATH":"evil"})),
            ("session_id", json!(1)),
        ] {
            let mut altered = valid.clone();
            altered["context"][field] = value;
            assert!(serde_json::from_value::<Launch>(altered).is_err());
        }
    }

    #[test]
    fn worker_channel_rejects_aliases_controls_and_non_ascii_identifiers() {
        let id = "0123456789abcdef0123456789abcdef";
        assert!(valid_channel(&format!(
            "{CHANNEL_PREFIX}{}",
            id.to_ascii_uppercase()
        )));
        for suffix in [
            id[..31].to_owned(),
            format!("{id}0"),
            format!("{}g", &id[..31]),
            "中".repeat(10) + "ab",
            format!("{}\0", &id[..31]),
            format!("{}\n", &id[..31]),
        ] {
            assert!(!valid_channel(&format!("{CHANNEL_PREFIX}{suffix}")));
        }
        for channel in [
            format!("{CHANNEL_PREFIX}{id}/child"),
            format!("{CHANNEL_PREFIX}{id} "),
            format!("{CHANNEL_PREFIX}{id}:stream"),
            format!("{}{}", CHANNEL_PREFIX.to_ascii_uppercase(), id),
            format!("\\\\localhost\\pipe\\keyvalet-mcp-worker-{id}"),
        ] {
            assert!(!valid_channel(&channel));
        }
    }

    #[test]
    fn replies_require_boolean_success_and_cannot_forward_private_or_role_fields() {
        for field in ["environment", "session_id", "executable", "key", "protocol"] {
            let mut started = json!({"ok":true});
            started[field] = json!("unexpected");
            assert!(serde_json::from_value::<Started>(started).is_err());
            let mut ready = json!({"ok":true, "context":context()});
            ready[field] = json!("unexpected");
            assert!(serde_json::from_value::<Ready>(ready).is_err());
        }
        for ok in [serde_json::Value::Null, json!(1), json!("true")] {
            assert!(serde_json::from_value::<Started>(json!({"ok":ok})).is_err());
            assert!(serde_json::from_value::<Ready>(json!({"ok":ok,"context":context()})).is_err());
        }
        assert!(serde_json::from_value::<Started>(json!({})).is_err());
        assert!(serde_json::from_value::<Ready>(json!({"ok":true})).is_err());
    }
}
