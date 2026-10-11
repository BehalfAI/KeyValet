//! Validate provider lifetimes before arithmetic or conversion to an RFC 3339 timestamp.

use kv_vault::{Result, VaultError};
use serde_json::Value;

// Last millisecond of year 9999: stay within both chrono and four-digit RFC 3339 dates.
const MAX_TIMESTAMP_MS: i64 = 253_402_300_799_999;

pub(crate) fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

pub(crate) fn expires_at(value: Option<&Value>, default: Option<u32>) -> Result<Option<i64>> {
    let seconds = match value {
        Some(value) => value.as_f64(),
        None => {
            return default
                .map(|seconds| expires_at(Some(&Value::from(seconds)), None))
                .unwrap_or(Ok(None))
        }
    };
    let now = now_ms();
    let expiry = seconds
        .filter(|seconds| seconds.is_finite() && *seconds > 0.0)
        .map(|seconds| seconds * 1000.0)
        .filter(|millis| millis.is_finite() && *millis <= (MAX_TIMESTAMP_MS - now) as f64)
        .and_then(|millis| now.checked_add(millis as i64))
        .filter(|expiry| valid_timestamp(*expiry));
    expiry.map(Some).ok_or_else(|| {
        VaultError::new(
            "token 响应的 expires_in 无效或超出支持范围",
            "Token response expires_in is invalid or outside the supported range",
        )
    })
}

fn valid_timestamp(ms: i64) -> bool {
    (0..=MAX_TIMESTAMP_MS).contains(&ms)
}

pub(crate) fn iso_millis(ms: i64) -> Option<String> {
    if !valid_timestamp(ms) {
        return None;
    }
    chrono::DateTime::<chrono::Utc>::from_timestamp_millis(ms)
        .map(|date| date.to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
}

pub(crate) fn is_fresh(ms: i64, margin_ms: i64) -> bool {
    valid_timestamp(ms)
        && ms
            .checked_sub(margin_ms)
            .is_some_and(|expiry| expiry > now_ms())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn rejects_untrusted_lifetimes_before_arithmetic() {
        for value in [
            json!(100_000_000_000_000u64),
            json!(1e300),
            json!(-1),
            json!(0),
            json!("3600"),
            Value::Null,
        ] {
            assert!(expires_at(Some(&value), None).is_err(), "{value}");
        }
        assert_eq!(expires_at(None, None).unwrap(), None);
        assert!(is_fresh(
            expires_at(None, Some(3600)).unwrap().unwrap(),
            60_000
        ));
        assert!(expires_at(Some(&json!(0.5)), None).unwrap().is_some());
    }

    #[test]
    fn corrupted_cached_dates_never_panic_or_count_as_fresh() {
        for ms in [i64::MIN, -1, MAX_TIMESTAMP_MS + 1, i64::MAX] {
            assert_eq!(iso_millis(ms), None);
            assert!(!is_fresh(ms, 60_000));
        }
        assert_eq!(iso_millis(0).as_deref(), Some("1970-01-01T00:00:00.000Z"));
        assert_eq!(
            iso_millis(MAX_TIMESTAMP_MS).as_deref(),
            Some("9999-12-31T23:59:59.999Z")
        );
    }
}
