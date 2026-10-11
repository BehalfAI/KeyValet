//! Pure PowerShell rendering; private-file ACLs and cleanup stay in gateway_env_win.

use std::io;
use zeroize::Zeroizing;

pub fn quote(value: &str) -> String {
    let mut quoted = String::new();
    append_literal(&mut quoted, value);
    quoted
}

fn append_literal(output: &mut String, value: &str) {
    output.push('\'');
    for ch in value.chars() {
        // PowerShell treats U+2018..U+201B as single-quote delimiters too.
        // Duplicate the original character so its exact spelling survives evaluation.
        if matches!(ch, '\'' | '\u{2018}'..='\u{201b}') {
            output.push(ch);
        }
        output.push(ch);
    }
    output.push('\'');
}

pub fn render_env(env: &[(String, String)]) -> io::Result<Zeroizing<String>> {
    if env.iter().any(|(name, _)| {
        name.is_empty()
            || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
            || name.as_bytes()[0].is_ascii_digit()
    }) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid environment variable name",
        ));
    }
    if env.iter().any(|(_, value)| value.contains('\0')) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "environment variable value contains NUL",
        ));
    }
    // Windows PowerShell 5.1 uses the ANSI code page for scripts without a BOM.
    // Render directly into zeroizing storage, without temporary secret-bearing strings.
    let capacity = env
        .iter()
        .try_fold(3usize, |total, (name, value)| {
            let escaped_bytes: usize = value
                .chars()
                .filter(|ch| matches!(ch, '\'' | '\u{2018}'..='\u{201b}'))
                .map(char::len_utf8)
                .sum();
            total
                .checked_add(name.len())?
                .checked_add(value.len())?
                .checked_add(escaped_bytes)?
                .checked_add(12)
        })
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "environment script is too large",
            )
        })?;
    // Allocate before appending secret values, so growth cannot leave an old allocation behind.
    let mut body = Zeroizing::new(String::with_capacity(capacity));
    body.push('\u{feff}');
    for (name, value) in env {
        body.push_str("$env:");
        body.push_str(name);
        body.push_str(" = ");
        append_literal(&mut body, value);
        body.push_str("\r\n");
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(name: &str, value: &str) -> Vec<(String, String)> {
        vec![(name.into(), value.into())]
    }

    #[test]
    fn powershell_literals_do_not_interpolate() {
        assert_eq!(
            quote("it's $env:PATH `x $(throw 'bad')"),
            "'it''s $env:PATH `x $(throw ''bad'')'"
        );
    }

    #[test]
    fn all_powershell_smart_apostrophes_are_escaped() {
        assert_eq!(quote("a‘b’c‚d‛e"), "'a‘‘b’’c‚‚d‛‛e'");
    }

    #[test]
    fn scripts_use_utf8_bom_for_windows_powershell_51() {
        let body = render_env(&env("KEYVALET_TEST", "测试🗝é")).unwrap();
        assert!(body.as_bytes().starts_with(&[0xef, 0xbb, 0xbf]));
        assert_eq!(&body[3..], "$env:KEYVALET_TEST = '测试🗝é'\r\n");
    }

    #[test]
    fn invalid_environment_names_are_rejected_before_rendering() {
        for name in [
            "",
            "0TOKEN",
            "env:PATH",
            "${TOKEN}",
            "KEY;throw",
            "KEY\r\n",
            "KEY=VALUE",
            "KEY-VAL",
            "KEY VAL",
            "KEY\0VAL",
            "密钥",
            "KEY🗝",
        ] {
            assert_eq!(
                render_env(&env(name, "synthetic")).unwrap_err().kind(),
                io::ErrorKind::InvalidInput,
                "{name:?}"
            );
        }
    }

    #[test]
    fn valid_environment_names_keep_their_spelling_and_order() {
        let values = vec![
            ("_TOKEN".into(), "first".into()),
            ("ApiKey_09".into(), "second".into()),
        ];
        assert_eq!(
            &render_env(&values).unwrap()[3..],
            "$env:_TOKEN = 'first'\r\n$env:ApiKey_09 = 'second'\r\n"
        );
    }

    #[test]
    fn nul_in_environment_values_is_rejected_instead_of_truncated() {
        for value in ["\0", "before\0after"] {
            assert_eq!(
                render_env(&env("KEYVALET_TEST", value)).unwrap_err().kind(),
                io::ErrorKind::InvalidInput
            );
        }
    }

    #[test]
    fn multiline_values_and_shell_syntax_stay_inside_the_literal() {
        let value = "\r\n'; $env:KEYVALET_SCRIPT_RAN = 'yes'; #\n@'\n'@\n`$() \\";
        assert_eq!(
            &render_env(&env("KEYVALET_TEST", value)).unwrap()[3..],
            format!("$env:KEYVALET_TEST = {}\r\n", quote(value))
        );
    }

    #[test]
    fn unicode_double_quotes_are_literal_in_single_quoted_values() {
        assert_eq!(
            quote("“value” „value‟ \"value\""),
            "'“value” „value‟ \"value\"'"
        );
    }

    #[test]
    fn long_unicode_values_preserve_every_quote_and_byte() {
        let value = "测试‘x’‚y‛🗝'".repeat(4096);
        let expected = "测试‘‘x’’‚‚y‛‛🗝''".repeat(4096);
        assert_eq!(
            &render_env(&env("KEYVALET_TEST", &value)).unwrap()[3..],
            format!("$env:KEYVALET_TEST = '{expected}'\r\n")
        );
    }

    #[test]
    fn empty_values_are_explicit_and_empty_exports_are_valid_scripts() {
        assert_eq!(
            &render_env(&env("KEYVALET_TEST", "")).unwrap()[3..],
            "$env:KEYVALET_TEST = ''\r\n"
        );
        assert_eq!(&*render_env(&[]).unwrap(), "\u{feff}");
    }

    #[test]
    #[ignore = "Requires PowerShell: KEYVALET_TEST_POWERSHELL=pwsh cargo test -p kv-mcp windows_script::tests::powershell_executes_export_fixture -- --ignored --exact"]
    fn powershell_executes_export_fixture() {
        let engine = std::env::var_os("KEYVALET_TEST_POWERSHELL").unwrap_or_else(|| {
            if cfg!(windows) {
                "powershell.exe"
            } else {
                "pwsh"
            }
            .into()
        });
        let mut values = vec![
            (
                "KEYVALET_TEST_ASCII".into(),
                "it's $env:PATH `x $(throw 'bad')".into(),
            ),
            (
                "KEYVALET_TEST_UNICODE".into(),
                "测试🗝é “double” „quotes‟".into(),
            ),
            (
                "KEYVALET_TEST_MULTILINE".into(),
                "first\r\nsecond\n@'\n'@".into(),
            ),
            ("KEYVALET_TEST_EMPTY".into(), String::new()),
        ];
        for (i, delimiter) in ['\'', '‘', '’', '‚', '‛'].iter().enumerate() {
            values.push((
                format!("KEYVALET_TEST_INJECTION_{i}"),
                format!("{delimiter}; $env:KEYVALET_SCRIPT_RAN = 'yes'; #"),
            ));
        }
        let temp = tempfile::Builder::new()
            .prefix("keyvalet-'exports-")
            .tempdir()
            .unwrap();
        let script = temp.path().join("exports-测试.ps1");
        std::fs::write(&script, render_env(&values).unwrap().as_bytes()).unwrap();
        let wrapper = temp.path().join("verify.ps1");
        // The fixture contains only synthetic values; exported values are never command arguments.
        std::fs::write(
            &wrapper,
            br#"$ErrorActionPreference = 'Stop'
. $args[0]
$actual = [ordered]@{}
foreach ($name in $args[1..($args.Count - 1)]) {
    $actual[$name] = [string][Environment]::GetEnvironmentVariable($name)
}
$actual['KEYVALET_SCRIPT_RAN'] = $env:KEYVALET_SCRIPT_RAN
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
ConvertTo-Json -InputObject $actual -Compress
"#,
        )
        .unwrap();
        let output = std::process::Command::new(engine)
            .args([
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
            ])
            .arg(wrapper)
            .arg(script)
            .args(values.iter().map(|(name, _)| name))
            .env("KEYVALET_SCRIPT_RAN", "no")
            .output()
            .expect("PowerShell must be installed for this explicit integration test");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let actual: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(
            actual["KEYVALET_SCRIPT_RAN"], "no",
            "an exported value executed PowerShell code"
        );
        for (name, value) in &values {
            assert_eq!(actual[name], *value, "{name}");
        }
    }
}
