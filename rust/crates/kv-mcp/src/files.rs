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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn resolves_a_small_existing_file_to_its_absolute_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.txt");
        std::fs::write(&path, b"hello").unwrap();
        let resolved = resolve_secret_file(path.to_str().unwrap()).unwrap();
        assert_eq!(resolved, std::path::absolute(&path).unwrap());
    }

    #[test]
    fn rejects_a_nonexistent_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("does-not-exist");
        let err = resolve_secret_file(path.to_str().unwrap()).unwrap_err();
        assert!(err.contains("not found") || err.contains("不存在"));
    }

    #[test]
    fn rejects_a_directory() {
        let dir = tempfile::tempdir().unwrap();
        let err = resolve_secret_file(dir.path().to_str().unwrap()).unwrap_err();
        assert!(err.contains("regular file") || err.contains("普通文件"));
    }

    #[test]
    fn rejects_a_file_over_64kb() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("big.bin");
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(&vec![0u8; 64 * 1024 + 1]).unwrap();
        let err = resolve_secret_file(path.to_str().unwrap()).unwrap_err();
        assert!(err.contains("too large") || err.contains("过大"));
    }

    #[test]
    fn accepts_a_file_exactly_at_the_64kb_limit() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("exactly.bin");
        std::fs::write(&path, vec![0u8; 64 * 1024]).unwrap();
        assert!(resolve_secret_file(path.to_str().unwrap()).is_ok());
    }

    #[test]
    fn tilde_prefix_expands_to_the_real_home_directory() {
        // Doesn't create or touch anything under $HOME -- a nonexistent path still proves
        // expansion happened, because the error message shows the expanded absolute path, not
        // a literal "~/...".
        let home = std::env::var("HOME").unwrap();
        let err = resolve_secret_file("~/kv-mcp-test-file-that-definitely-does-not-exist-xyz123")
            .unwrap_err();
        assert!(
            err.contains(&home),
            "expected the error to mention the expanded home dir {home}, got: {err}"
        );
    }

    #[test]
    fn read_secret_file_returns_the_content() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.txt");
        std::fs::write(&path, b"sekrit-value").unwrap();
        assert_eq!(read_secret_file(&path).unwrap(), "sekrit-value");
    }

    #[test]
    fn read_secret_file_on_a_missing_path_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        assert!(read_secret_file(&dir.path().join("nope")).is_err());
    }
}
