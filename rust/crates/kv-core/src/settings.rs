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

// Keep a stable inode: replacing/removing this file would let two processes hold different locks.
// The lock covers only the disk transaction, never a user prompt.
fn lock_settings(vault_dir: &Path) -> std::io::Result<std::fs::File> {
    let path = vault_dir.join(".settings.lock");
    let mut options = std::fs::OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(&path)?;
    kv_platform::fs::set_private_permissions(&path)?;
    #[cfg(target_os = "linux")]
    kv_platform::linux::inherit_private_owner(&path)?;
    file.lock()?;
    Ok(file)
}

pub fn write_settings(vault_dir: &Path, s: &Settings) -> std::io::Result<()> {
    let _lock = lock_settings(vault_dir)?;
    write_settings_locked(vault_dir, s)
}

/// Commit a proposal only if its settings snapshot is still current. Prompts must happen before
/// this call; a concurrent tightening or forget operation invalidates the old approval.
pub fn compare_and_write_settings(
    vault_dir: &Path,
    expected: &Settings,
    next: &Settings,
) -> std::io::Result<bool> {
    let _lock = lock_settings(vault_dir)?;
    if read_settings(vault_dir) != *expected {
        return Ok(false);
    }
    write_settings_locked(vault_dir, next)?;
    Ok(true)
}

fn write_settings_locked(vault_dir: &Path, s: &Settings) -> std::io::Result<()> {
    use std::io::Write;

    let raw = RawSettings {
        grant_mode: Some(serde_json::Value::String(s.grant_mode.as_str().to_string())),
        remember_hours: Some(serde_json::json!(s.remember_hours)),
        remember_until: s.remember_until,
    };
    let body = serde_json::to_string_pretty(&raw).unwrap() + "\n";
    // Multiple daemon sessions run in this process. A PID-only temporary name lets their
    // writes clobber one another, or makes one rename remove the other's pending file.
    let mut tmp = tempfile::Builder::new()
        .prefix("settings.json.tmp-")
        .tempfile_in(vault_dir)?;
    kv_platform::fs::set_private_permissions(tmp.path())?;
    #[cfg(target_os = "linux")]
    kv_platform::linux::inherit_private_owner(tmp.path())?;
    tmp.write_all(body.as_bytes())?;
    tmp.as_file().sync_all()?;
    tmp.persist(file(vault_dir)).map_err(|e| e.error)?;
    #[cfg(unix)]
    std::fs::File::open(vault_dir)?.sync_all()?;
    Ok(())
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
    fn concurrent_settings_writes_commit_whole_files_without_temp_collisions() {
        let dir = tempfile::tempdir().unwrap();
        let barrier = std::sync::Barrier::new(12);
        std::thread::scope(|threads| {
            for worker in 0..12 {
                let barrier = &barrier;
                let dir = dir.path();
                threads.spawn(move || {
                    let settings = Settings {
                        grant_mode: GRANT_MODES[worker % GRANT_MODES.len()],
                        remember_hours: worker as f64,
                        remember_until: None,
                    };
                    barrier.wait();
                    for _ in 0..8 {
                        write_settings(dir, &settings).unwrap();
                        let saved = read_settings(dir);
                        assert_eq!(
                            saved.grant_mode,
                            GRANT_MODES[saved.remember_hours as usize % GRANT_MODES.len()]
                        );
                    }
                });
            }
        });
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 2);
    }

    #[test]
    fn settings_writes_leave_preexisting_temp_paths_untouched_and_clean_up_failures() {
        let dir = tempfile::tempdir().unwrap();
        let old_temp = file(dir.path()).with_extension(format!("json.tmp-{}", std::process::id()));
        std::fs::write(&old_temp, "unrelated file").unwrap();
        write_settings(dir.path(), &DEFAULTS).unwrap();
        assert_eq!(
            std::fs::read_to_string(&old_temp).unwrap(),
            "unrelated file"
        );

        std::fs::remove_file(file(dir.path())).unwrap();
        std::fs::create_dir(file(dir.path())).unwrap();
        assert!(write_settings(dir.path(), &DEFAULTS).is_err());
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 3);
    }

    #[test]
    fn concurrent_settings_proposals_cannot_both_commit_the_same_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        write_settings(dir.path(), &DEFAULTS).unwrap();
        let barrier = std::sync::Barrier::new(8);
        let committed = std::sync::atomic::AtomicUsize::new(0);
        std::thread::scope(|threads| {
            for worker in 0..8 {
                let barrier = &barrier;
                let committed = &committed;
                let dir = dir.path();
                threads.spawn(move || {
                    let next = Settings {
                        grant_mode: GrantMode::PerUse,
                        remember_hours: worker as f64,
                        remember_until: None,
                    };
                    barrier.wait();
                    if compare_and_write_settings(dir, &DEFAULTS, &next).unwrap() {
                        committed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    }
                });
            }
        });
        assert_eq!(committed.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(read_settings(dir.path()).grant_mode, GrantMode::PerUse);
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
