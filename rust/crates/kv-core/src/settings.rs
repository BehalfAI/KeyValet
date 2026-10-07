//! Vault settings (root-only, stored in the vault directory). The agent cannot modify them
//! directly; loosening permissions requires the user to confirm with Touch ID.
//! Direct port of src/helper/settings.ts.

use std::path::{Path, PathBuf};

/// Grant modes (strictest to loosest):
///   `PerUse`        Touch ID is required every time a credential is used
///   `PerCredential` Once per credential per session (default)
///   `PerSession`    Once per session, after which all credentials can be used
///   `Remember`      After one Touch ID, no authentication is required across sessions for
///                   `remember_hours` (0 = forever)
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantMode {
    PerUse,
    PerCredential,
    PerSession,
    Remember,
}

pub const GRANT_MODES: [GrantMode; 4] = [
    GrantMode::PerUse,
    GrantMode::PerCredential,
    GrantMode::PerSession,
    GrantMode::Remember,
];

impl GrantMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            GrantMode::PerUse => "per_use",
            GrantMode::PerCredential => "per_credential",
            GrantMode::PerSession => "per_session",
            GrantMode::Remember => "remember",
        }
    }

    fn strictness(&self) -> u8 {
        match self {
            GrantMode::PerUse => 3,
            GrantMode::PerCredential => 2,
            GrantMode::PerSession => 1,
            GrantMode::Remember => 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Settings {
    pub grant_mode: GrantMode,
    /// Duration of remember mode in hours; 0 means forever.
    pub remember_hours: f64,
    /// Timestamp (ms since epoch) until which this remember period stays active; `None` when not
    /// remembered or already cleared.
    pub remember_until: Option<f64>,
}

const DEFAULTS: Settings = Settings {
    grant_mode: GrantMode::PerCredential,
    remember_hours: 8.0,
    remember_until: None,
};

/// Backward compatibility for an old value: "all" -> per_session.
pub fn parse_mode(v: &str) -> Option<GrantMode> {
    if v == "all" {
        return Some(GrantMode::PerSession);
    }
    GRANT_MODES.into_iter().find(|m| m.as_str() == v)
}

/// The stricter of two modes (a client can only tighten the mode, never loosen it).
pub fn stricter(a: GrantMode, b: Option<GrantMode>) -> GrantMode {
    match b {
        None => a,
        Some(b) => {
            if b.strictness() > a.strictness() {
                b
            } else {
                a
            }
        }
    }
}

/// Whether `next` is looser than `cur` (requires user authentication).
pub fn is_loosening(cur: &Settings, next: &Settings) -> bool {
    if next.grant_mode.strictness() < cur.grant_mode.strictness() {
        return true;
    }
    if next.grant_mode == GrantMode::Remember && cur.grant_mode == GrantMode::Remember {
        if cur.remember_hours == 0.0 {
            return false;
        }
        return next.remember_hours == 0.0 || next.remember_hours > cur.remember_hours;
    }
    false
}

pub fn remember_active(s: &Settings, now_ms: f64) -> bool {
    s.grant_mode == GrantMode::Remember && s.remember_until.is_some_and(|u| now_ms < u)
}

/// JS's `Number.MAX_SAFE_INTEGER` -- used as "no expiry" so a forever-remembered window still
/// compares as "in the future" against any real timestamp, matching the TS implementation exactly.
pub const MAX_SAFE_INTEGER: f64 = 9_007_199_254_740_991.0;

pub fn remember_until(hours: f64, now_ms: f64) -> f64 {
    if hours == 0.0 {
        MAX_SAFE_INTEGER
    } else {
        now_ms + hours * 3_600_000.0
    }
}

fn file(vault_dir: &Path) -> PathBuf {
    vault_dir.join("settings.json")
}

#[derive(serde::Serialize, serde::Deserialize, Default)]
struct RawSettings {
    grant_mode: Option<serde_json::Value>,
    remember_hours: Option<serde_json::Value>,
    remember_until: Option<f64>,
}

pub fn read_settings(vault_dir: &Path) -> Settings {
    let Ok(raw) = std::fs::read_to_string(file(vault_dir)) else {
        return DEFAULTS;
    };
    let Ok(raw): Result<RawSettings, _> = serde_json::from_str(&raw) else {
        return DEFAULTS;
    };
    let grant_mode = raw
        .grant_mode
        .as_ref()
        .and_then(|v| v.as_str())
        .and_then(parse_mode)
        .unwrap_or(DEFAULTS.grant_mode);
    let hours = raw
        .remember_hours
        .as_ref()
        .and_then(serde_json::Value::as_f64);
    let remember_hours = hours
        .filter(|h| h.is_finite() && *h >= 0.0)
        .unwrap_or(DEFAULTS.remember_hours);
    Settings {
        grant_mode,
        remember_hours,
        remember_until: raw.remember_until,
    }
}

pub fn write_settings(vault_dir: &Path, s: &Settings) -> std::io::Result<()> {
    let raw = RawSettings {
        grant_mode: Some(serde_json::Value::String(s.grant_mode.as_str().to_string())),
        remember_hours: Some(serde_json::json!(s.remember_hours)),
        remember_until: s.remember_until,
    };
    let body = serde_json::to_string_pretty(&raw).unwrap() + "\n";
    let tmp = file(vault_dir).with_extension(format!("json.tmp-{}", std::process::id()));
    std::fs::write(&tmp, body)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
    }
    std::fs::rename(&tmp, file(vault_dir))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stricter_never_loosens() {
        assert_eq!(
            stricter(GrantMode::PerSession, Some(GrantMode::PerUse)),
            GrantMode::PerUse
        );
        assert_eq!(
            stricter(GrantMode::PerUse, Some(GrantMode::PerSession)),
            GrantMode::PerUse
        );
        assert_eq!(
            stricter(GrantMode::PerCredential, None),
            GrantMode::PerCredential
        );
    }

    #[test]
    fn loosening_detection() {
        let per_cred = Settings {
            grant_mode: GrantMode::PerCredential,
            remember_hours: 8.0,
            remember_until: None,
        };
        let per_use = Settings {
            grant_mode: GrantMode::PerUse,
            remember_hours: 8.0,
            remember_until: None,
        };
        assert!(!is_loosening(&per_cred, &per_use));
        assert!(is_loosening(&per_use, &per_cred));

        let remember_8 = Settings {
            grant_mode: GrantMode::Remember,
            remember_hours: 8.0,
            remember_until: None,
        };
        let remember_24 = Settings {
            grant_mode: GrantMode::Remember,
            remember_hours: 24.0,
            remember_until: None,
        };
        let remember_forever = Settings {
            grant_mode: GrantMode::Remember,
            remember_hours: 0.0,
            remember_until: None,
        };
        assert!(is_loosening(&remember_8, &remember_24));
        assert!(!is_loosening(&remember_24, &remember_8));
        assert!(is_loosening(&remember_8, &remember_forever));
        assert!(!is_loosening(&remember_forever, &remember_8), "already forever: a shorter duration isn't a loosening (it's a no-op until explicitly shortened)");
    }

    #[test]
    fn remember_until_forever_is_max_safe_integer() {
        assert_eq!(remember_until(0.0, 1000.0), MAX_SAFE_INTEGER);
        assert_eq!(remember_until(1.0, 1000.0), 1000.0 + 3_600_000.0);
    }

    #[test]
    fn settings_round_trip_through_disk() {
        let dir = tempfile::tempdir().unwrap();
        let s = Settings {
            grant_mode: GrantMode::Remember,
            remember_hours: 12.0,
            remember_until: Some(123456.0),
        };
        write_settings(dir.path(), &s).unwrap();
        assert_eq!(read_settings(dir.path()), s);
    }

    #[test]
    fn missing_or_corrupt_file_falls_back_to_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let s = read_settings(dir.path());
        assert_eq!(s.grant_mode, GrantMode::PerCredential);
        assert_eq!(s.remember_hours, 8.0);
        std::fs::write(dir.path().join("settings.json"), "not json").unwrap();
        assert_eq!(
            read_settings(dir.path()).grant_mode,
            GrantMode::PerCredential
        );
    }

    #[test]
    fn parse_mode_accepts_the_legacy_all_value() {
        assert_eq!(parse_mode("all"), Some(GrantMode::PerSession));
        assert_eq!(parse_mode("bogus"), None);
    }
}
