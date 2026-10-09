//! Terminal management tool, for the user's own use: keyvalet <command>
//! Launched by /usr/local/bin/keyvalet via `sudo -k`, reads and writes the credential vault
//! directly as root. Direct port of src/cli/main.ts.

use kv_core::settings::{parse_mode, read_settings, write_settings};
use kv_platform::paths::{CLI_BIN, VAULT_DIR};
use kv_platform::trust::verify_root_environment;
use kv_vault::{SetParams, Vault, MAX_VALUE_LENGTH};
use serde_json::{json, Map, Value};
use std::io::IsTerminal;

fn fatal(msg: &str) -> ! {
    eprintln!("keyvalet: {msg}");
    std::process::exit(1);
}

fn usage() -> String {
    kv_i18n::t(
        "用法：keyvalet <命令>\n\n\
        \u{20}\u{20}types                              列出凭证类型\n\
        \u{20}\u{20}list [type]                        列出凭证（不含值）\n\
        \u{20}\u{20}get <type> <name>                  输出凭证值（协议凭证输出完整配置和秘密）\n\
        \u{20}\u{20}set <type> <name> [选项]           保存凭证（值从隐藏输入或管道读取；类型不存在会先创建）\n\
        \u{20}\u{20}\u{20}\u{20}\u{20}\u{20}--desc <text>                  凭证说明\n\
        \u{20}\u{20}\u{20}\u{20}\u{20}\u{20}--type-desc <text>             新建类型时的类型说明\n\
        \u{20}\u{20}\u{20}\u{20}\u{20}\u{20}--attr key=value               非敏感属性，可重复\n\
        \u{20}\u{20}\u{20}\u{20}\u{20}\u{20}--overwrite                    覆盖已有凭证\n\
        \u{20}\u{20}delete <type> <name>               删除凭证\n\
        \u{20}\u{20}delete-type <type>                 删除空的凭证类型\n\
        \u{20}\u{20}audit [行数]                       查看审计日志（默认 50 行）\n\
        \u{20}\u{20}grant-mode [per-use|per-credential|per-session|remember [小时]|forget]\n\
        \u{20}\u{20}\u{20}\u{20}\u{20}\u{20}\u{20}\u{20}\u{20}\u{20}\u{20}\u{20}\u{20}\u{20}\u{20}\u{20}\u{20}\u{20}\u{20}\u{20}\u{20}\u{20}\u{20}\u{20}\u{20}\u{20}\u{20}\u{20}查看/设置授权模式：每次 / 每个凭证 / 每个会话按 Touch ID，或按一次后记住一段时间\n\
        \u{20}\u{20}scan                               在常见配置文件（.env、~/.claude.json 等）里找可能的密钥（只检测，不改动文件）",
        "Usage: keyvalet <command>\n\n\
        \u{20}\u{20}types                              List credential types\n\
        \u{20}\u{20}list [type]                        List credentials (without values)\n\
        \u{20}\u{20}get <type> <name>                  Print a credential value (protocol credentials print full config and secrets)\n\
        \u{20}\u{20}set <type> <name> [options]        Save a credential (value read from hidden input or a pipe; the type is created if missing)\n\
        \u{20}\u{20}\u{20}\u{20}\u{20}\u{20}--desc <text>                  Credential description\n\
        \u{20}\u{20}\u{20}\u{20}\u{20}\u{20}--type-desc <text>             Type description when creating a new type\n\
        \u{20}\u{20}\u{20}\u{20}\u{20}\u{20}--attr key=value               Non-secret attribute, repeatable\n\
        \u{20}\u{20}\u{20}\u{20}\u{20}\u{20}--overwrite                    Overwrite an existing credential\n\
        \u{20}\u{20}delete <type> <name>               Delete a credential\n\
        \u{20}\u{20}delete-type <type>                 Delete an empty credential type\n\
        \u{20}\u{20}audit [lines]                      Show the audit log (default 50 lines)\n\
        \u{20}\u{20}grant-mode [per-use|per-credential|per-session|remember [hours]|forget]\n\
        \u{20}\u{20}\u{20}\u{20}\u{20}\u{20}\u{20}\u{20}\u{20}\u{20}\u{20}\u{20}\u{20}\u{20}\u{20}\u{20}\u{20}\u{20}\u{20}\u{20}\u{20}\u{20}\u{20}\u{20}\u{20}\u{20}\u{20}Show/set grant mode: Touch ID per use / per credential / per session, or once and remember for a while\n\
        \u{20}\u{20}scan                               Look for possible secrets in common config files (.env, ~/.claude.json, ...); detects only, never changes a file",
    )
}

fn read_value(label: &str) -> String {
    if std::io::stdin().is_terminal() {
        let a = rpassword::prompt_password(kv_i18n::t(
            &format!("输入 {label} 的值（不回显）："),
            &format!("Enter the value for {label} (hidden): "),
        ))
        .unwrap_or_else(|_| fatal(&kv_i18n::t("读取输入失败", "Failed to read input")));
        let b = rpassword::prompt_password(kv_i18n::t(
            "再输入一次确认：",
            "Enter it again to confirm: ",
        ))
        .unwrap_or_else(|_| fatal(&kv_i18n::t("读取输入失败", "Failed to read input")));
        if a != b {
            fatal(&kv_i18n::t(
                "两次输入不一致",
                "The two entries do not match",
            ));
        }
        a
    } else {
        // Piped input: e.g. `pbpaste | keyvalet set api_key openai`.
        use std::io::Read;
        let mut buf = String::new();
        let _ = std::io::stdin().read_to_string(&mut buf);
        buf.trim_end_matches(['\n', '\r']).to_string()
    }
}

struct Options {
    desc: Option<String>,
    type_desc: Option<String>,
    attrs: std::collections::HashMap<String, String>,
    overwrite: bool,
    rest: Vec<String>,
}

fn parse_options(args: &[String]) -> Options {
    let mut opts = Options {
        desc: None,
        type_desc: None,
        attrs: Default::default(),
        overwrite: false,
        rest: Vec::new(),
    };
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        let mut next = || {
            i += 1;
            args.get(i).cloned().unwrap_or_else(|| {
                fatal(&kv_i18n::t(
                    &format!("{a} 缺少参数"),
                    &format!("{a} requires an argument"),
                ))
            })
        };
        match a.as_str() {
            "--desc" => opts.desc = Some(next()),
            "--type-desc" => opts.type_desc = Some(next()),
            "--overwrite" => opts.overwrite = true,
            "--attr" => {
                let kv = next();
                match kv.split_once('=') {
                    Some((k, v)) if !k.is_empty() => {
                        opts.attrs.insert(k.to_string(), v.to_string());
                    }
                    _ => fatal(&kv_i18n::t(
                        &format!("--attr 格式应为 key=value：{kv}"),
                        &format!("--attr must be key=value: {kv}"),
                    )),
                }
            }
            _ => opts.rest.push(a.clone()),
        }
        i += 1;
    }
    opts
}

fn audited<T>(
    vault: &Vault,
    op: &str,
    mut target: Map<String, Value>,
    client: &Value,
    f: impl FnOnce() -> kv_vault::Result<T>,
) -> T {
    match f() {
        Ok(r) => {
            target.insert("op".into(), json!(op));
            target.insert("ok".into(), json!(true));
            target.insert("client".into(), client.clone());
            let _ = vault.audit(target);
            r
        }
        Err(e) => {
            target.insert("op".into(), json!(op));
            target.insert("ok".into(), json!(false));
            target.insert("error".into(), json!(e.0));
            target.insert("client".into(), client.clone());
            let _ = vault.audit(target);
            fatal(&e.0);
        }
    }
}

fn main() {
    unsafe { libc::umask(0o077) };
    let self_path = std::env::current_exe().unwrap_or_default();
    if let Err(e) = verify_root_environment(&self_path, std::path::Path::new(CLI_BIN), &[]) {
        fatal(&e);
    }

    let mut argv: Vec<String> = std::env::args().skip(1).collect();
    // The wrapper script detects the language as the user and passes it in via --lang (root can't
    // read the user's language preference).
    if argv.first().map(String::as_str) == Some("--lang") {
        kv_i18n::set_lang(argv.get(1).map(String::as_str).unwrap_or(""));
        argv = argv.split_off(2.min(argv.len()));
    }

    let cmd = argv.first().cloned();
    let args = if argv.len() > 1 {
        argv[1..].to_vec()
    } else {
        Vec::new()
    };
    match cmd.as_deref() {
        None | Some("help") | Some("--help") | Some("-h") => {
            println!("{}", usage());
            return;
        }
        _ => {}
    }
    let cmd = cmd.unwrap();

    let vault = Vault::new(VAULT_DIR);
    if let Err(e) = vault.init() {
        fatal(&e.0);
    }
    let client = json!({"client": "keyvalet-cli", "user": std::env::var("SUDO_USER").ok()});

    match cmd.as_str() {
        "types" => {
            let types = audited(&vault, "listTypes", Map::new(), &client, || {
                Ok(vault.list_types())
            });
            if types.is_empty() {
                println!(
                    "{}",
                    kv_i18n::t("（暂无凭证类型）", "(no credential types)")
                );
            }
            for ty in types {
                println!(
                    "{}",
                    kv_i18n::t(
                        &format!("{}\t{} 个\t{}", ty.name, ty.count, ty.description),
                        &format!("{}\t{}\t{}", ty.name, ty.count, ty.description)
                    )
                );
            }
        }
        "list" => {
            let ty_filter = args.first().cloned();
            let mut target = Map::new();
            target.insert("type".into(), json!(ty_filter));
            let items = audited(&vault, "list", target, &client, || {
                vault.list(ty_filter.as_deref())
            });
            if items.is_empty() {
                println!("{}", kv_i18n::t("（暂无凭证）", "(no credentials)"));
            }
            for c in items {
                let attrs: String = {
                    let mut pairs: Vec<String> = c
                        .attributes
                        .iter()
                        .map(|(k, v)| format!("{k}={v}"))
                        .collect();
                    pairs.sort();
                    pairs.join(" ")
                };
                let kind = if matches!(c.kind, kv_vault::Kind::Static) {
                    String::new()
                } else {
                    format!(" [{}]", c.kind.as_str())
                };
                let attr_suffix = if attrs.is_empty() {
                    String::new()
                } else {
                    format!("\t{attrs}")
                };
                println!(
                    "{}/{}{}\t{}{}",
                    c.r#type, c.name, kind, c.description, attr_suffix
                );
            }
        }
        "get" => {
            let (Some(ty), Some(name)) = (args.first(), args.get(1)) else {
                fatal(&kv_i18n::t(
                    "用法：get <type> <name>",
                    "Usage: get <type> <name>",
                ));
            };
            let mut target = Map::new();
            target.insert("type".into(), json!(ty));
            target.insert("name".into(), json!(name));
            let (_, _, record) = audited(&vault, "get", target, &client, || {
                vault.get_record(ty, name)
            });
            if record.kind_or_static() == kv_vault::Kind::Static {
                if std::io::stdout().is_terminal() {
                    println!("{}", record.value);
                } else {
                    print!("{}", record.value);
                }
            } else {
                // Protocol credentials: print the full config and secrets (terminal-only, running
                // as root, for backup/migration).
                println!("{}", serde_json::to_string_pretty(&json!({"kind": record.kind_or_static().as_str(), "config": record.config, "secrets": record.secrets})).unwrap());
            }
        }
        "set" => {
            let opts = parse_options(&args);
            let (Some(ty), Some(name)) = (opts.rest.first().cloned(), opts.rest.get(1).cloned())
            else {
                fatal(&kv_i18n::t(
                    "用法：set <type> <name> [选项]",
                    "Usage: set <type> <name> [options]",
                ));
            };
            if !opts.overwrite && vault.exists(&ty, &name).unwrap_or(false) {
                fatal(&kv_i18n::t(
                    &format!("凭证 {ty}/{name} 已存在，如需替换请加 --overwrite"),
                    &format!(
                        "Credential {ty}/{name} already exists; add --overwrite to replace it"
                    ),
                ));
            }
            let value = read_value(&format!("{ty}/{name}"));
            if value.is_empty() {
                fatal(&kv_i18n::t("值不能为空", "Value must not be empty"));
            }
            if value.encode_utf16().count() > MAX_VALUE_LENGTH {
                fatal(&kv_i18n::t("值过长", "Value is too long"));
            }
            let mut target = Map::new();
            target.insert("type".into(), json!(ty));
            target.insert("name".into(), json!(name));
            let r = audited(&vault, "set", target, &client, || {
                vault.set(SetParams {
                    r#type: ty.clone(),
                    name: name.clone(),
                    value: Some(value.clone()),
                    description: opts.desc.clone(),
                    attributes: Some(opts.attrs.clone()),
                    type_description: opts.type_desc.clone(),
                    overwrite: opts.overwrite,
                    ..Default::default()
                })
            });
            if r.type_created {
                println!(
                    "{}",
                    kv_i18n::t(
                        &format!("凭证类型 \"{}\" 不存在，已先创建", r.r#type),
                        &format!(
                            "Credential type \"{}\" did not exist and was created",
                            r.r#type
                        )
                    )
                );
            }
            println!(
                "{}",
                if r.replaced {
                    kv_i18n::t(
                        &format!("已覆盖 {}/{}", r.r#type, r.name),
                        &format!("Overwrote {}/{}", r.r#type, r.name),
                    )
                } else {
                    kv_i18n::t(
                        &format!("已保存 {}/{}", r.r#type, r.name),
                        &format!("Saved {}/{}", r.r#type, r.name),
                    )
                }
            );
        }
        "delete" => {
            let (Some(ty), Some(name)) = (args.first(), args.get(1)) else {
                fatal(&kv_i18n::t(
                    "用法：delete <type> <name>",
                    "Usage: delete <type> <name>",
                ));
            };
            let mut target = Map::new();
            target.insert("type".into(), json!(ty));
            target.insert("name".into(), json!(name));
            let (ty, name) = audited(&vault, "delete", target, &client, || vault.delete(ty, name));
            println!(
                "{}",
                kv_i18n::t(
                    &format!("已删除 {ty}/{name}"),
                    &format!("Deleted {ty}/{name}")
                )
            );
        }
        "delete-type" => {
            let Some(ty) = args.first() else {
                fatal(&kv_i18n::t(
                    "用法：delete-type <type>",
                    "Usage: delete-type <type>",
                ));
            };
            let mut target = Map::new();
            target.insert("type".into(), json!(ty));
            let name = audited(&vault, "deleteType", target, &client, || {
                vault.delete_type(ty)
            });
            println!(
                "{}",
                kv_i18n::t(
                    &format!("已删除凭证类型 {name}"),
                    &format!("Deleted credential type {name}")
                )
            );
        }
        "grant-mode" => {
            let cur = read_settings(&vault.dir);
            let Some(m) = args.first() else {
                let suffix = if cur.grant_mode == kv_core::settings::GrantMode::Remember {
                    format!(
                        " ({})",
                        if cur.remember_hours == 0.0 {
                            "forever".to_string()
                        } else {
                            format!("{}h", cur.remember_hours)
                        }
                    )
                } else {
                    String::new()
                };
                println!("{}{suffix}", cur.grant_mode.as_str());
                return;
            };
            if m == "forget" {
                let next = kv_core::settings::Settings {
                    grant_mode: cur.grant_mode,
                    remember_hours: cur.remember_hours,
                    remember_until: None,
                };
                let _ = write_settings(&vault.dir, &next);
                let _ = vault.audit(Map::from_iter([
                    ("op".to_string(), json!("settings")),
                    ("forget".to_string(), json!(true)),
                    ("ok".to_string(), json!(true)),
                    ("client".to_string(), client.clone()),
                ]));
                println!(
                    "{}",
                    kv_i18n::t(
                        "已清除\u{201c}记住\u{201d}状态",
                        "Cleared the remembered authorization"
                    )
                );
                return;
            }
            let Some(mode) = parse_mode(&m.replace('-', "_")) else {
                fatal(&kv_i18n::t("用法：grant-mode [per-use|per-credential|per-session|remember [小时，0=永久]|forget]", "Usage: grant-mode [per-use|per-credential|per-session|remember [hours, 0=forever]|forget]"));
            };
            let hours = match args.get(1) {
                Some(h) => h.parse::<f64>().unwrap_or(f64::NAN),
                None => cur.remember_hours,
            };
            if !hours.is_finite() || !(0.0..=8760.0).contains(&hours) {
                fatal(&kv_i18n::t(
                    "小时数必须在 0~8760 之间",
                    "Hours must be between 0 and 8760",
                ));
            }
            // You're running this yourself in the terminal as root (password already entered), no
            // further confirmation needed; the remember window starts from the next Touch ID.
            let next = kv_core::settings::Settings {
                grant_mode: mode,
                remember_hours: hours,
                remember_until: None,
            };
            let _ = write_settings(&vault.dir, &next);
            let _ = vault.audit(Map::from_iter([
                ("op".to_string(), json!("settings")),
                ("grant_mode".to_string(), json!(mode.as_str())),
                ("remember_hours".to_string(), json!(hours)),
                ("ok".to_string(), json!(true)),
                ("client".to_string(), client.clone()),
            ]));
            println!(
                "{}",
                kv_i18n::t(
                    &format!("授权模式已设为 {}（新会话生效）", mode.as_str()),
                    &format!("Grant mode set to {} (new sessions)", mode.as_str())
                )
            );
        }
        "audit" => {
            let n: usize = args.first().and_then(|s| s.parse().ok()).unwrap_or(50);
            let lines = vault.read_audit_tail(4 * 1024 * 1024);
            let start = lines.len().saturating_sub(n);
            println!("{}", lines[start..].join("\n"));
        }
        "scan" => scan(),
        other => fatal(&kv_i18n::t(
            &format!("未知命令 {other}\n\n{}", usage()),
            &format!("Unknown command {other}\n\n{}", usage()),
        )),
    }
}

/// The invoking (non-root) user's home directory -- `$HOME` is reset to root's own under `sudo`
/// (no `-E` in the `keyvalet` wrapper), so dotfiles like `~/.claude.json` have to be found via
/// `SUDO_USER` instead. `dscl` is the authoritative source (handles a non-default home
/// directory); `/Users/<name>` is the fallback if that lookup fails, which is right for the
/// overwhelming majority of real Macs. Falls back to `$HOME` itself when there's no `SUDO_USER`
/// at all (e.g. invoking `kv-cli` directly as root for testing).
fn real_home() -> std::path::PathBuf {
    if let Some(user) = std::env::var("SUDO_USER").ok().filter(|u| !u.is_empty()) {
        if let Ok(out) = std::process::Command::new("dscl")
            .args([".", "-read", &format!("/Users/{user}"), "NFSHomeDirectory"])
            .output()
        {
            if let Some(dir) = std::str::from_utf8(&out.stdout)
                .ok()
                .and_then(|s| s.strip_prefix("NFSHomeDirectory:"))
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                return std::path::PathBuf::from(dir);
            }
        }
        return std::path::PathBuf::from(format!("/Users/{user}"));
    }
    std::env::var_os("HOME")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("/"))
}

/// The fixed list of places secrets commonly end up (action-plan 4.1), filtered down to the ones
/// that actually exist. `.env*`/`.cursor/mcp.json` are resolved against the current directory
/// (wherever the user ran `keyvalet scan` from -- `sudo` doesn't change cwd); the rest are
/// per-user dotfiles under `real_home()`.
fn scan_paths() -> Vec<std::path::PathBuf> {
    let home = real_home();
    let cwd = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
    let mut paths = vec![
        cwd.join(".env"),
        cwd.join(".env.local"),
        cwd.join(".env.development"),
        cwd.join(".env.production"),
        cwd.join(".cursor/mcp.json"),
        home.join(".claude.json"),
        home.join(".codex/config.toml"),
        home.join(".zshrc"),
        home.join(".bashrc"),
        home.join(".bash_profile"),
        home.join(".profile"),
    ];
    paths.retain(|p| p.is_file());
    paths
}

/// `keyvalet scan` (action-plan 4.1): a deliberately read-only first slice. Finds secret-shaped
/// strings in the usual places and prints where, with a suggested `keyvalet set` command for
/// each -- but does not import anything or touch any file. The full plan (native checkbox
/// dialog, import, placeholder rewrite, delete-the-plaintext-after-confirming) writes to the
/// user's real config files; that's a materially riskier feature than reporting what's there, so
/// it's left as a follow-up rather than shipped without a chance to review the rewrite logic
/// specifically. Reuses `kv_hook::detect` (the exact same engine the `tool`/`prompt` hooks use)
/// line by line, so results and recognized services match what the hooks would flag.
fn scan() {
    let (report, total) = scan_report(&scan_paths());
    print!("{report}");
    if total == 0 {
        println!(
            "{}",
            kv_i18n::t(
                "没有在常见位置发现明显的密钥。",
                "No obvious secrets found in the usual places."
            )
        );
    } else {
        println!();
        println!(
            "{}",
            kv_i18n::t(
                &format!("共 {total} 条可能的密钥。只是检测，没有改动任何文件：要收进 KeyValet，用上面建议的命令逐条 set，再手动从原文件删掉。"),
                &format!("{total} possible secret(s) total. This only detects, it didn't change any file: to store one in KeyValet, run the suggested `keyvalet set` command for it, then remove it from the original file by hand."),
            )
        );
    }
}

/// The pure part of `scan`: given a list of files (assumed to already exist -- `scan_paths`
/// filters for that; a test can skip straight to passing in tempdir paths), reads each, detects
/// line by line, and renders the per-file report. Returns the rendered text and the total hit
/// count so `scan` can decide which closing message to print without re-parsing its own output.
fn scan_report(paths: &[std::path::PathBuf]) -> (String, usize) {
    let mut out = String::new();
    let mut total = 0usize;
    for path in paths {
        let Ok(content) = std::fs::read_to_string(path) else {
            continue; // unreadable or not UTF-8 -- skip rather than fail the whole scan
        };
        let hits: Vec<(usize, kv_hook::Hit)> = content
            .lines()
            .enumerate()
            .flat_map(|(i, line)| {
                kv_hook::detect(line, false)
                    .into_iter()
                    .map(move |h| (i + 1, h))
            })
            .collect();
        if hits.is_empty() {
            continue;
        }
        total += hits.len();
        out.push_str(&format!("{}\n", path.display()));
        for (line_no, hit) in hits {
            // `tool` means the credential needs more than one secret field (e.g. AWS is a key
            // pair) -- `keyvalet set` only ever takes a single value, so it can't create one of
            // these correctly. Only an MCP-connected agent can run the dedicated setup tool
            // right now; `id` alone (no `tool`) is the common case `set` actually handles.
            let suggestion = match (&hit.tool, &hit.id) {
                (Some(tool), _) => kv_i18n::t(
                    &format!("需要多字段设置，`keyvalet set` 做不了：请让接入 KeyValet MCP 的 AI agent 调用 {tool}"),
                    &format!("needs multi-field setup that `keyvalet set` can't do: ask an AI agent connected to KeyValet's MCP server to run {tool}"),
                ),
                (None, Some(id)) => format!("keyvalet set {id} <name>"),
                (None, None) => "keyvalet set <type> <name>".to_string(),
            };
            out.push_str(&format!(
                "  :{line_no}\t{} ({})\t{suggestion}\n",
                hit.label, hit.preview
            ));
        }
    }
    (out, total)
}

#[cfg(test)]
mod scan_tests {
    use super::scan_report;
    use std::io::Write;

    fn write_tmp(name: &str, content: &str) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(name);
        std::fs::File::create(&path)
            .unwrap()
            .write_all(content.as_bytes())
            .unwrap();
        (dir, path)
    }

    #[test]
    fn reports_a_secret_with_its_line_number_and_a_set_suggestion() {
        let (_dir, path) = write_tmp(
            ".env",
            "APP_NAME=demo\nOPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyz0123456789\n",
        );
        let (report, total) = scan_report(std::slice::from_ref(&path));
        assert_eq!(total, 1);
        assert!(report.contains(&path.display().to_string()));
        assert!(report.contains(":2"));
        assert!(report.contains("keyvalet set openai <name>"));
        assert!(
            !report.contains("sk-proj-abcdefghijklmnopqrstuvwxyz0123456789"),
            "must only show the masked preview"
        );
    }

    #[test]
    fn an_ordinary_file_with_no_secrets_reports_nothing() {
        let (_dir, path) = write_tmp(".env", "APP_NAME=demo\nDEBUG=true\n");
        let (report, total) = scan_report(&[path]);
        assert_eq!(total, 0);
        assert_eq!(report, "");
    }

    #[test]
    fn a_missing_file_is_skipped_without_failing_the_rest_of_the_scan() {
        let (_dir, present) =
            write_tmp(".env", "KEY=sk-proj-abcdefghijklmnopqrstuvwxyz0123456789\n");
        let missing = present.parent().unwrap().join("does-not-exist");
        let (_report, total) = scan_report(&[missing, present]);
        assert_eq!(total, 1);
    }

    #[test]
    fn aws_keys_suggest_the_dedicated_setup_tool_not_a_plain_set() {
        // Not AWS's own well-known AKIA...EXAMPLE key -- `looks_random` filters out anything
        // matching "example" as an obvious placeholder, which would defeat this test.
        let (_dir, path) = write_tmp(".env", "AWS_ACCESS_KEY_ID=AKIAZQ3EXFAKE7NMKLPQ\n");
        let (report, _total) = scan_report(&[path]);
        assert!(report.contains("credential_setup_aws"));
    }
}
