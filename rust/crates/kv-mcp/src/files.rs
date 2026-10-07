//! Import secrets from a file (private keys, service account JSON, etc.); the content goes
//! straight to the root helper and never enters the AI's context. Direct port of src/server/files.ts.

const MAX_FILE_BYTES: u64 = 64 * 1024;

/// Resolve the path and check it (without reading the content): must be a regular file no larger
/// than 64KB.
pub fn resolve_secret_file(p: &str) -> Result<std::path::PathBuf, String> {
    let expanded = if let Some(rest) = p.strip_prefix("~/") {
        dirs_home().join(rest)
    } else {
        std::path::PathBuf::from(p)
    };
    let abs = std::path::absolute(&expanded).unwrap_or(expanded);
    let st = std::fs::metadata(&abs).map_err(|_| {
        kv_i18n::t(
            &format!("文件不存在：{}", abs.display()),
            &format!("File not found: {}", abs.display()),
        )
    })?;
    if !st.is_file() {
        return Err(kv_i18n::t(
            &format!("不是普通文件：{}", abs.display()),
            &format!("Not a regular file: {}", abs.display()),
        ));
    }
    if st.len() > MAX_FILE_BYTES {
        return Err(kv_i18n::t(
            &format!("文件过大（超过 64KB）：{}", abs.display()),
            &format!("File too large (over 64KB): {}", abs.display()),
        ));
    }
    Ok(abs)
}

pub fn read_secret_file(abs: &std::path::Path) -> Result<String, String> {
    let buf = std::fs::read(abs).map_err(|e| e.to_string())?;
    if buf.len() as u64 > MAX_FILE_BYTES {
        return Err(kv_i18n::t(
            &format!("文件过大（超过 64KB）：{}", abs.display()),
            &format!("File too large (over 64KB): {}", abs.display()),
        ));
    }
    Ok(String::from_utf8_lossy(&buf).to_string())
}

fn dirs_home() -> std::path::PathBuf {
    std::env::var("HOME")
        .map(std::path::PathBuf::from)
        .unwrap_or_default()
}
