//! Bilingual UI text (English / Simplified Chinese).
//!
//! Usage: `t("Chinese copy", "English text")` -- both variants live side by side at the call site.
//! Language resolution (first match wins):
//!   1. `set_lang()` -- the root helper receives the language from the MCP server in the handshake;
//!      the CLI receives it via --lang from its wrapper script
//!   2. `KEYVALET_LANG=en|zh`
//!   3. macOS UI language (AppleLanguages)
//!   4. `LC_ALL` / `LC_MESSAGES` / `LANG`
//!   5. English
//!
//! Direct Rust port of src/shared/i18n.ts -- kept behaviorally identical so the Rust and TS
//! helpers resolve the same language from the same environment (differential testing relies on this).

use std::process::Command;
use std::sync::Mutex;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lang {
    En,
    Zh,
}

impl Lang {
    pub fn as_str(&self) -> &'static str {
        match self {
            Lang::En => "en",
            Lang::Zh => "zh",
        }
    }
}

static CURRENT: Mutex<Option<Lang>> = Mutex::new(None);

fn from_string(v: Option<&str>) -> Option<Lang> {
    let v = v?.trim();
    if v.is_empty() {
        return None;
    }
    let lower = v.to_lowercase();
    if lower.starts_with("zh") {
        Some(Lang::Zh)
    } else if lower.starts_with("en") {
        Some(Lang::En)
    } else {
        None
    }
}

/// Reads the user's macOS UI language preference. Returns None off Darwin, as root (root reads
/// root's own preference, not the invoking user's), or if the lookup fails for any reason.
fn mac_language() -> Option<Lang> {
    if cfg!(not(target_os = "macos")) {
        return None;
    }
    if unsafe { libc::getuid() } == 0 {
        return None;
    }
    let output = Command::new("/usr/bin/defaults")
        .args(["read", "-g", "AppleLanguages"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let raw = String::from_utf8_lossy(&output.stdout);
    let cleaned: String = raw
        .chars()
        .map(|c| if "(),\n\r\t ".contains(c) { ' ' } else { c })
        .collect();
    let first = cleaned.split_whitespace().next()?.trim_matches('"');
    Some(from_string(Some(first)).unwrap_or(Lang::En))
}

pub fn detect_lang() -> Lang {
    from_string(std::env::var("KEYVALET_LANG").ok().as_deref())
        .or_else(mac_language)
        .or_else(|| from_string(std::env::var("LC_ALL").ok().as_deref()))
        .or_else(|| from_string(std::env::var("LC_MESSAGES").ok().as_deref()))
        .or_else(|| from_string(std::env::var("LANG").ok().as_deref()))
        .unwrap_or(Lang::En)
}

pub fn lang() -> Lang {
    let mut current = CURRENT.lock().unwrap();
    if current.is_none() {
        *current = Some(detect_lang());
    }
    current.unwrap()
}

pub fn set_lang(v: &str) {
    if let Some(l) = from_string(Some(v)) {
        *CURRENT.lock().unwrap() = Some(l);
    }
}

/// Pick the text for the current language.
pub fn t(zh: &str, en: &str) -> String {
    match lang() {
        Lang::Zh => zh.to_string(),
        Lang::En => en.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex as StdMutex;

    // Tests that touch process-global env vars/CURRENT must not run concurrently with each other.
    // `unwrap_or_else(PoisonError::into_inner)` recovers the lock if an earlier test in this module
    // panicked while holding it, so one failure doesn't cascade into spurious failures in the rest.
    static ENV_LOCK: StdMutex<()> = StdMutex::new(());

    fn reset() {
        *CURRENT.lock().unwrap() = None;
        std::env::remove_var("KEYVALET_LANG");
    }

    // Deliberately NOT tested here: falling through to LC_ALL/LC_MESSAGES/LANG/macOS AppleLanguages
    // when KEYVALET_LANG is unset. That path shells out to the real OS preference (see
    // `mac_language`), so its result depends on the machine running the test -- src/test/i18n.test.ts
    // avoids this for the same reason, testing only `set_lang`/`t()` directly and the KEYVALET_LANG
    // env var (which is checked first and short-circuits before any OS lookup).

    #[test]
    fn env_var_picks_the_language() {
        let _guard = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        reset();
        std::env::set_var("KEYVALET_LANG", "zh-CN");
        assert_eq!(detect_lang(), Lang::Zh);
        std::env::set_var("KEYVALET_LANG", "en-US");
        assert_eq!(detect_lang(), Lang::En);
        reset();
    }

    #[test]
    fn set_lang_overrides_and_sticks_until_reset() {
        let _guard = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        reset();
        set_lang("zh");
        assert_eq!(lang(), Lang::Zh);
        assert_eq!(t("中文", "English"), "中文");
        reset();
    }

    #[test]
    fn invalid_set_lang_is_ignored() {
        let _guard = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        reset();
        set_lang("zh");
        set_lang("fr"); // not "en" or "zh": ignored, the previously set language is kept
        assert_eq!(lang(), Lang::Zh);
        reset();
    }
}
