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
        \u{20}\u{20}setup-enclave                      初始化或迁移到 macOS 必需的硬件保护\n\
        \u{20}\u{20}protection                         查看主密钥保护方式（无需 Touch ID）\n\
        \u{20}\u{20}enclave-test                       两次认证验证硬件密钥，不修改凭证库\n\
        \u{20}\u{20}migrate-to-enclave                 启用 Secure Enclave，设置独立恢复口令\n\
        \u{20}\u{20}recover-vault                      用恢复口令重新绑定本机硬件密钥\n\
        \u{20}\u{20}finish-enclave-migration           认证后清理中断迁移遗留的文件密钥\n\
        \u{20}\u{20}rotate-recovery                    更换凭证库密钥与恢复口令（并启用设备绑定）\n\
        \u{20}\u{20}recovery-check                     用恢复口令验证可解密（不用硬件、不修改、不输出值）\n\
        \u{20}\u{20}recovery-read <types|list|get> …   应急：Secure Enclave 不可用时用恢复口令只读访问\n\
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
        \u{20}\u{20}scan [--report-only]               在常见配置文件（.env、~/.claude.json 等）里找可能的密钥，弹窗勾选后导入并从原文件移除（备份在 <file>.bak-keyvalet）；命中模板的凭证按模板配置为仅代理；加 --report-only 只报告不改动\n\
        \u{20}\u{20}\u{20}\u{20}\u{20}\u{20}--report-only                  只扫描和报告，不弹窗、不导入、不改动任何文件",
        "Usage: keyvalet <command>\n\n\
        \u{20}\u{20}setup-enclave                      Initialize or migrate to required macOS hardware protection\n\
        \u{20}\u{20}protection                         Show master-key protection (no Touch ID)\n\
        \u{20}\u{20}enclave-test                       Verify hardware key with two prompts; vault unchanged\n\
        \u{20}\u{20}migrate-to-enclave                 Enable Secure Enclave and set a recovery passphrase\n\
        \u{20}\u{20}recover-vault                      Rebind the vault to this Mac with the recovery passphrase\n\
        \u{20}\u{20}finish-enclave-migration           Authenticate and remove a leftover file key\n\
        \u{20}\u{20}rotate-recovery                    Rotate the vault key and recovery passphrase (adds device binding)\n\
        \u{20}\u{20}recovery-check                     Verify the recovery passphrase decrypts (no hardware, no changes, no values)\n\
        \u{20}\u{20}recovery-read <types|list|get> …   Emergency read-only access with the recovery passphrase if Secure Enclave is unusable\n\
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
        \u{20}\u{20}scan [--report-only]               Look for possible secrets in common config files (.env, ~/.claude.json, ...); shows a checkbox dialog, imports what's picked (configured from the matching template as proxy-only when there is one), and removes it from the file (backup at <file>.bak-keyvalet); add --report-only to only report, never change anything\n\
        \u{20}\u{20}\u{20}\u{20}\u{20}\u{20}--report-only                  Only scan and report; no dialog, no import, no file changes",
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

/// What `keyvalet get` prints for a static credential. Template-imported credentials store their
/// secret under `secrets` with an empty `value` (mirroring the MCP set path), so a single secret
/// field prints as the value and several print as pretty JSON, same style as the protocol branch.
fn static_secret_to_print(record: &kv_vault::CredentialRecord) -> String {
    if !record.value.is_empty() {
        return record.value.clone();
    }
    match &record.secrets {
        Some(secrets) if secrets.len() == 1 => secrets.values().next().unwrap().clone(),
        Some(secrets) if !secrets.is_empty() => {
            serde_json::to_string_pretty(&json!({"fields": secrets})).unwrap()
        }
        _ => record.value.clone(),
    }
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
    #[cfg(unix)]
    unsafe {
        libc::umask(0o077);
        // No core dumps: a crash would dump every live secret to disk in one shot.
        let limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        libc::setrlimit(libc::RLIMIT_CORE, &limit);
    }
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
    let mut cmd = cmd.unwrap();
    let mut args = args;

    let vault = Vault::new(VAULT_DIR);
    // `recovery-read <cmd> ...` runs one read-only command after opening the vault with the
    // recovery passphrase instead of Secure Enclave; the vault rejects writes in that state.
    let recovery_read = cmd == "recovery-read";
    if recovery_read {
        if !matches!(
            args.first().map(String::as_str),
            Some("types" | "list" | "get")
        ) {
            fatal(&kv_i18n::t(
                "用法：recovery-read <types|list [type]|get <type> <name>>",
                "Usage: recovery-read <types|list [type]|get <type> <name>>",
            ));
        }
        cmd = args.remove(0);
    }
    let mut client = json!({"client": "keyvalet-cli", "user": std::env::var("SUDO_USER").ok()});
    if recovery_read {
        client["access"] = json!("recovery_passphrase_read_only");
        let password = enter_recovery_password();
        let count = audited(&vault, "recoveryUnlock", Map::new(), &client, || {
            vault.open_recovery_read_only(&password)
        });
        eprintln!(
            "{}",
            kv_i18n::t(
                &format!("已用恢复口令只读打开凭证库（{count} 条凭证）；不会修改凭证库"),
                &format!("Opened the vault read-only with the recovery passphrase ({count} credentials); no changes will be made")
            )
        );
    } else {
        if enclave_command(&cmd, &args, &vault, &client) {
            return;
        }
        #[cfg(target_os = "macos")]
        let initialized = vault.init_with_provider(
            &kv_platform::enclave::EnclaveMasterKeyProvider,
            &kv_core::prompt::terminal_unlock(&cmd),
        );
        #[cfg(not(target_os = "macos"))]
        let initialized = vault.init_legacy();
        if let Err(e) = initialized {
            fatal(&e.0);
        }
    }

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
                let out = static_secret_to_print(&record);
                if std::io::stdout().is_terminal() {
                    println!("{out}");
                } else {
                    print!("{out}");
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
        "scan" => scan(&args, &vault, &client),
        other => fatal(&kv_i18n::t(
            &format!("未知命令 {other}\n\n{}", usage()),
            &format!("Unknown command {other}\n\n{}", usage()),
        )),
    }
}

#[cfg(unix)]
fn recovery_password(confirm: bool) -> zeroize::Zeroizing<String> {
    let prompt = kv_i18n::t(
        "输入独立的恢复长口令（12–1024 字节，建议六个以上随机单词）。请离线保管；换机恢复需要它，持有口令与 vault 密文可绕过硬件解密：",
        "Enter a separate recovery passphrase (12–1024 bytes; preferably six or more random words). Keep it offline for device recovery; the passphrase and encrypted vault can decrypt without the hardware: ");
    let mut retry = String::new();
    loop {
        let password = read_recovery_secret(&format!("{retry}{prompt}"));
        if let Err(error) = kv_vault::WrappedMasterKey::validate_password(&password) {
            retry = format!("{}\n\n", error.0);
            continue;
        }
        if confirm {
            let again = read_recovery_secret(&kv_i18n::t(
                "再输入一次恢复口令确认：",
                "Enter the recovery passphrase again to confirm: ",
            ));
            if *password != *again {
                retry = format!(
                    "{}\n\n",
                    kv_i18n::t(
                        "两次输入不一致，请重新输入。",
                        "The entries do not match; please try again."
                    )
                );
                continue;
            }
        }
        return password;
    }
}

/// Opening an existing recovery wrapper: no strength rules or confirmation, a wrong passphrase
/// simply fails to decrypt.
fn enter_recovery_password() -> zeroize::Zeroizing<String> {
    read_recovery_secret(&kv_i18n::t(
        "输入凭证库的恢复口令：",
        "Enter the vault's recovery passphrase: ",
    ))
}

fn read_recovery_secret(prompt: &str) -> zeroize::Zeroizing<String> {
    let failed = || -> ! {
        fatal(&kv_i18n::t(
            "恢复口令输入已取消或失败",
            "Recovery passphrase entry cancelled or failed",
        ))
    };
    if std::io::stdin().is_terminal() {
        return zeroize::Zeroizing::new(
            rpassword::prompt_password(prompt).unwrap_or_else(|_| failed()),
        );
    }
    #[cfg(not(unix))]
    {
        // The hidden-answer dialog goes through the per-user agent on Windows (W3); a piped
        // passphrase is not accepted (it would sit in the caller's history/memory unzeroed).
        let _ = prompt;
        failed();
    }
    #[cfg(unix)]
    {
        // Only fixed, localized prompts reach this dialog. Passwords return directly to the root
        // CLI through a private pipe; never through an agent, argv, environment or temporary file.
        let (uid, gid) = kv_platform::user::invoking_user().unwrap_or_else(|| failed());
        use std::os::unix::process::CommandExt;
        let script = r#"on run argv
      set r to display dialog (item 1 of argv) with title "KeyValet · Recovery" default answer "" with hidden answer buttons {item 2 of argv, item 3 of argv} default button 2 cancel button 1 with icon caution giving up after 180
      if gave up of r then error number -128
      return text returned of r
    end run"#;
        let mut command = std::process::Command::new(kv_platform::paths::OSASCRIPT_BIN);
        command
            .args([
                "-e",
                script,
                "--",
                prompt,
                &kv_i18n::t("取消", "Cancel"),
                &kv_i18n::t("确认", "Confirm"),
            ])
            .current_dir("/")
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null());
        // Not `uid`/`gid`: on macOS that sequence leaves the child with effective gid 0 (wheel).
        unsafe {
            command.pre_exec(kv_platform::user::drop_to(uid, gid));
        }
        let mut child = command.spawn().unwrap_or_else(|_| failed());
        // A fixed zeroizing buffer, not `output()`: a growing Vec leaves unzeroed passphrase copies.
        let mut buf = zeroize::Zeroizing::new([0u8; 1027]);
        let mut len = 0;
        {
            use std::io::Read;
            let mut stdout = child.stdout.take().unwrap();
            while len < buf.len() {
                match stdout.read(&mut buf[len..]) {
                    Ok(0) => break,
                    Ok(n) => len += n,
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(_) => break,
                }
            }
        }
        let status = child.wait().unwrap_or_else(|_| failed());
        if !status.success() || len > 1026 {
            failed();
        }
        let text = std::str::from_utf8(&buf[..len]).unwrap_or_else(|_| failed());
        zeroize::Zeroizing::new(text.strip_suffix('\n').unwrap_or(text).to_owned())
    }
}

/// What the launchd daemon reports about live sessions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg(unix)]
enum DaemonState {
    /// No socket, or the socket exists but nothing is listening: the daemon isn't running and
    /// can't hold sessions.
    NotRunning,
    /// Connected and got a valid count.
    Sessions(usize),
    /// The socket answered but produced no valid reply before timing out: could be mid-restart
    /// or mid-session -- treated as busy (fail closed).
    Unknown,
}

#[cfg(unix)]
fn is_busy(state: DaemonState) -> bool {
    match state {
        DaemonState::NotRunning => false,
        DaemonState::Sessions(n) => n > 0,
        DaemonState::Unknown => true,
    }
}

#[cfg(unix)]
fn daemon_session_state() -> DaemonState {
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::fs::FileTypeExt;
    let path = std::path::Path::new(kv_platform::paths::HELPER_SOCKET);
    if !std::fs::symlink_metadata(path)
        .map(|m| m.file_type().is_socket())
        .unwrap_or(false)
    {
        return DaemonState::NotRunning;
    }
    let mut stream = match std::os::unix::net::UnixStream::connect(path) {
        // The socket file exists but nothing listens: stale file, daemon stopped.
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::NotFound
            ) =>
        {
            return DaemonState::NotRunning
        }
        Err(_) => return DaemonState::Unknown,
        Ok(s) => s,
    };
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(1)));
    let _ = stream.set_write_timeout(Some(std::time::Duration::from_secs(1)));
    if stream
        .write_all(b"{\"op\":\"control\",\"command\":\"sessions\"}\n")
        .is_err()
    {
        return DaemonState::Unknown;
    }
    let mut reply = String::new();
    if BufReader::new(&stream).read_line(&mut reply).is_err() {
        return DaemonState::Unknown;
    }
    match serde_json::from_str::<serde_json::Value>(&reply)
        .ok()
        .and_then(|v| v.get("sessions")?.as_u64())
    {
        Some(n) => DaemonState::Sessions(n as usize),
        None => DaemonState::Unknown,
    }
}

/// Legacy pre-daemon helpers: spawned as exactly `kv-helper` with no argv -- the daemon's
/// `kv-helper --daemon --uid ...` argv does NOT match this pattern, deliberately.
#[cfg(unix)]
fn legacy_helper_running() -> bool {
    matches!(
        std::process::Command::new("/usr/bin/pgrep")
            .args(["-f", "^/usr/local/lib/keyvalet/bin/kv-helper$"])
            .output(),
        Ok(output) if output.status.code() == Some(0)
    )
}

#[cfg(unix)]
fn require_no_helper_sessions() {
    // Older helper versions cannot detect a rotation. Never migrate while any helper is alive.
    // Helpers just asked to stop (e.g. by the installer) get a few seconds to exit.
    for attempt in 0..25 {
        // Fail closed: a live-but-unanswering daemon counts as busy; absent/stopped counts as 0.
        if !is_busy(daemon_session_state()) && !legacy_helper_running() {
            return;
        }
        if attempt < 24 {
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
    }
    fatal(&kv_i18n::t(
        "请先关闭所有 KeyValet / AI 会话，再迁移或恢复",
        "Close all KeyValet / AI sessions before migration or recovery",
    ))
}

/// Prints a warning when the device binding key's Time Machine exclusion can't be confirmed
/// (`tmutil isexcluded` failed, reported `[Included]`, or the file is missing).
#[cfg(unix)]
fn warn_if_binding_exclusion_unconfirmed(vault: &Vault) {
    if matches!(vault.binding_backup_exclusion(), Ok(Some(false))) {
        println!(
            "{}",
            kv_i18n::t(
                "警告：未能确认设备绑定密钥已排除在 Time Machine 备份之外；请用 sudo tmutil isexcluded 检查 /var/db/keyvalet 下的 device-binding-*.key。第三方备份工具不遵守这一排除。",
                "Warning: could not confirm the device binding key is excluded from Time Machine; check /var/db/keyvalet/device-binding-*.key with sudo tmutil isexcluded. Third-party backup tools do not honor this exclusion."
            )
        );
    }
}

fn enclave_command(cmd: &str, args: &[String], vault: &Vault, client: &Value) -> bool {
    if cmd == "protection" {
        let status = vault.protection().unwrap_or_else(|e| fatal(&e.0));
        let mut view = serde_json::to_value(&status).unwrap();
        view["binding_excluded_from_backups"] =
            json!(vault.binding_backup_exclusion().unwrap_or(None));
        println!("{}", serde_json::to_string_pretty(&view).unwrap());
        return true;
    }
    if cmd == "recovery-check" {
        if !args.is_empty() {
            fatal(&kv_i18n::t(
                "此命令不接受参数；口令不得放入命令行",
                "This command takes no arguments; never put passphrases on the command line",
            ));
        }
        let password = enter_recovery_password();
        let count = audited(vault, cmd, Map::new(), client, || {
            vault.open_recovery_read_only(&password)
        });
        println!(
            "{}",
            kv_i18n::t(
                &format!("恢复口令有效：可解密 {count} 条凭证；未使用硬件，未修改凭证库"),
                &format!("Recovery passphrase verified: {count} credentials decrypt; no hardware used, vault unchanged")
            )
        );
        return true;
    }
    if !matches!(
        cmd,
        "setup-enclave"
            | "enclave-test"
            | "migrate-to-enclave"
            | "recover-vault"
            | "rotate-recovery"
            | "finish-enclave-migration"
    ) {
        return false;
    }
    if !args.is_empty() {
        fatal(&kv_i18n::t(
            "此命令不接受参数；口令不得放入命令行",
            "This command takes no arguments; never put passphrases on the command line",
        ));
    }
    #[cfg(not(target_os = "macos"))]
    fatal(&kv_i18n::t(
        "Secure Enclave 仅支持 macOS",
        "Secure Enclave requires macOS",
    ));
    #[cfg(target_os = "macos")]
    {
        use kv_vault::MasterKeyProvider;
        let provider = kv_platform::enclave::EnclaveMasterKeyProvider;
        let reason = match cmd {
            "enclave-test" => kv_i18n::t("验证硬件保护（1/2）", "verify hardware protection (1/2)"),
            "recover-vault" => kv_i18n::t(
                "恢复凭证库并更换硬件保护密钥",
                "recover your credential vault with a new hardware key",
            ),
            "finish-enclave-migration" => kv_i18n::t(
                "完成凭证库迁移并移除旧文件密钥",
                "finish vault migration and remove the old file key",
            ),
            "rotate-recovery" => kv_i18n::t(
                "更换凭证库密钥与恢复口令",
                "rotate your vault key and recovery passphrase",
            ),
            _ => kv_i18n::t(
                "为凭证库启用硬件保护",
                "enable hardware protection for your credential vault",
            ),
        };
        match cmd {
            "enclave-test" => {
                let created = provider.create(&reason).unwrap_or_else(|e| fatal(&e.0));
                let restored = provider
                    .unlock(
                        &created.metadata,
                        &kv_i18n::t("验证硬件保护（2/2）", "verify hardware protection (2/2)"),
                    )
                    .unwrap_or_else(|e| fatal(&e.0));
                if *created.key != *restored {
                    fatal(&kv_i18n::t(
                        "硬件密钥验证失败",
                        "Hardware key verification failed",
                    ));
                }
                println!(
                    "{}",
                    kv_i18n::t(
                        "Secure Enclave 验证成功；未修改凭证库",
                        "Secure Enclave verification passed; vault unchanged"
                    )
                );
            }
            "setup-enclave" | "migrate-to-enclave" => {
                let status = vault.protection().unwrap_or_else(|e| fatal(&e.0));
                if status.provider == "secure_enclave" {
                    if status.legacy_key_present {
                        vault
                            .init_with_provider(
                                &provider,
                                &kv_i18n::t(
                                    "完成凭证库迁移并移除旧文件密钥",
                                    "finish vault migration and remove the old file key",
                                ),
                            )
                            .unwrap_or_else(|e| fatal(&e.0));
                        audited(
                            vault,
                            "finish-enclave-migration",
                            Map::new(),
                            client,
                            || vault.remove_legacy_key(),
                        );
                    }
                    println!(
                        "{}",
                        kv_i18n::t(
                            "Secure Enclave 已配置",
                            "Secure Enclave is already configured"
                        )
                    );
                    if !status.device_binding {
                        println!(
                            "{}",
                            kv_i18n::t(
                                "建议运行 keyvalet rotate-recovery：为凭证库加上设备绑定，使 vault 文件副本单靠一次系统认证无法解密，并同时更换恢复口令。",
                                "Recommended: run keyvalet rotate-recovery to add device binding (so a copy of the vault file can't be decrypted with one system prompt alone) and set a new recovery passphrase."
                            )
                        );
                    }
                    if status.migration_backup_present {
                        println!(
                            "{}",
                            kv_i18n::t(
                                "建议运行 keyvalet rotate-recovery：凭证库目录里还留着迁移时的加密快照 vault.migration-backup.enc，它仍可用迁移时的恢复口令解密；轮换后会删除它。",
                                "Recommended: run keyvalet rotate-recovery. The vault directory still holds the encrypted migration snapshot vault.migration-backup.enc, which still opens with the recovery passphrase used at migration; rotation removes it."
                            )
                        );
                    }
                    warn_if_binding_exclusion_unconfirmed(vault);
                    return true;
                }
                require_no_helper_sessions();
                // Find a missing or mismatched legacy key before asking for a passphrase.
                if status.provider != "uninitialized" {
                    vault.init_legacy().unwrap_or_else(|e| fatal(&e.0));
                }
                let password = recovery_password(true);
                require_no_helper_sessions();
                if status.provider == "uninitialized" {
                    audited(vault, cmd, Map::new(), client, || {
                        vault.initialize_enclave(&provider, &password, &reason)
                    });
                    println!(
                        "{}",
                        kv_i18n::t(
                            "Secure Enclave 凭证库初始化完成",
                            "Secure Enclave vault initialized"
                        )
                    );
                } else {
                    audited(vault, cmd, Map::new(), client, || {
                        vault.migrate_to_enclave(&provider, &password, &reason)
                    });
                    println!(
                        "{}",
                        kv_i18n::t("已迁移至 Secure Enclave", "Migrated to Secure Enclave")
                    );
                }
                warn_if_binding_exclusion_unconfirmed(vault);
            }
            "recover-vault" => {
                let status = vault.protection().unwrap_or_else(|e| fatal(&e.0));
                if status.provider != "secure_enclave" {
                    fatal(&kv_i18n::t(
                        "此凭证库没有硬件恢复信息；请先把备份的 vault.enc 放回凭证库目录",
                        "This vault has no hardware recovery information; restore the backed-up vault.enc to the vault directory first",
                    ));
                }
                require_no_helper_sessions();
                let password = enter_recovery_password();
                let message = kv_i18n::t("使用恢复口令恢复凭证库，并绑定本机新的 Secure Enclave 密钥？这会使原会话失效。",
                    "Recover the vault with your passphrase and bind it to a new Secure Enclave key on this Mac? Existing sessions will be invalidated.");
                if !confirm_yes_no(
                    &message,
                    &kv_i18n::t("恢复", "Recover"),
                    &kv_i18n::t("取消", "Cancel"),
                ) {
                    return true;
                }
                require_no_helper_sessions();
                audited(vault, cmd, Map::new(), client, || {
                    vault.recover_enclave(&provider, &password, &reason)
                });
                println!(
                    "{}",
                    kv_i18n::t(
                        "恢复成功，已绑定本机的新硬件密钥",
                        "Recovered and bound to a new hardware key on this Mac"
                    )
                );
                warn_if_binding_exclusion_unconfirmed(vault);
            }
            "rotate-recovery" => {
                let status = vault.protection().unwrap_or_else(|e| fatal(&e.0));
                if status.provider != "secure_enclave" {
                    fatal(&kv_i18n::t(
                        "尚未启用 Secure Enclave；请先运行 keyvalet setup-enclave",
                        "Secure Enclave is not enabled; run keyvalet setup-enclave first",
                    ));
                }
                require_no_helper_sessions();
                vault
                    .init_with_provider(
                        &provider,
                        &kv_i18n::t(
                            "解锁凭证库以更换密钥",
                            "unlock your vault to rotate its key",
                        ),
                    )
                    .unwrap_or_else(|e| fatal(&e.0));
                let password = recovery_password(true);
                require_no_helper_sessions();
                audited(vault, cmd, Map::new(), client, || {
                    vault.rotate_enclave(&provider, &password, &reason)
                });
                println!(
                    "{}",
                    kv_i18n::t(
                        "已更换硬件密钥、凭证库密钥和恢复口令，并启用设备绑定。旧口令不能再解密当前凭证库，但旧的 vault 备份仍可用旧口令解密。",
                        "Rotated the hardware key, vault key and recovery passphrase, with device binding. The old passphrase no longer decrypts the current vault; older vault backups still decrypt with it."
                    )
                );
                warn_if_binding_exclusion_unconfirmed(vault);
            }
            "finish-enclave-migration" => {
                vault
                    .init_with_provider(&provider, &reason)
                    .unwrap_or_else(|e| fatal(&e.0));
                audited(vault, cmd, Map::new(), client, || vault.remove_legacy_key());
                println!(
                    "{}",
                    kv_i18n::t("迁移清理完成", "Migration cleanup completed")
                );
            }
            _ => unreachable!(),
        }
        true
    }
}

/// The invoking (non-root) user's home directory -- `$HOME` is reset to root's own under `sudo`
/// (no `-E` in the `keyvalet` wrapper), so dotfiles like `~/.claude.json` have to be found via
/// `SUDO_USER` instead. `dscl` is the authoritative source (handles a non-default home
/// directory); `/Users/<name>` is the fallback if that lookup fails, which is right for the
/// overwhelming majority of real Macs. Falls back to `$HOME` itself when there's no `SUDO_USER`
/// at all (e.g. invoking `kv-cli` directly as root for testing).
#[cfg(unix)]
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

#[cfg(windows)]
fn real_home() -> std::path::PathBuf {
    std::env::var_os("USERPROFILE")
        .or_else(|| std::env::var_os("HOME"))
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from(r"C:\"))
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

struct ScanHit {
    path: std::path::PathBuf,
    line_no: usize,
    hit: kv_hook::Hit,
    /// The real, unmasked matched text -- needed to store the real value and to find/remove it
    /// from the file. Never printed; only `hit.preview` goes to the terminal or a dialog.
    raw: String,
}

/// The pure scanning step: given files (assumed to already exist -- `scan_paths` filters for
/// that; a test can pass tempdir paths directly), reads each as text and detects line by line.
/// Separated from path resolution and from the interactive/import steps below so each can be
/// tested on its own.
fn scan_hits(paths: &[std::path::PathBuf]) -> Vec<ScanHit> {
    let mut out = Vec::new();
    for path in paths {
        let Ok(content) = std::fs::read_to_string(path) else {
            continue; // unreadable or not UTF-8 -- skip rather than fail the whole scan
        };
        for (i, line) in content.lines().enumerate() {
            for (raw, hit) in kv_hook::detect_with_values(line, false) {
                out.push(ScanHit {
                    path: path.clone(),
                    line_no: i + 1,
                    hit,
                    raw,
                });
            }
        }
    }
    out
}

/// What to do about a hit: credentials needing more than one secret field (e.g. AWS's key pair,
/// flagged via `tool` rather than plain `id`) can't be created by `keyvalet set` -- it only ever
/// takes a single value -- so this points at the MCP setup tool instead. `id` alone is the
/// common case `set` actually handles; no `id` at all (an unrecognized generic secret) has no
/// concrete type to suggest. Also used to decide which hits the interactive import below offers.
fn suggestion(hit: &kv_hook::Hit) -> String {
    match (&hit.tool, &hit.id) {
        (Some(tool), _) => kv_i18n::t(
            &format!("需要多字段设置，`keyvalet set` 做不了：请让接入 KeyValet MCP 的 AI agent 调用 {tool}"),
            &format!("needs multi-field setup that `keyvalet set` can't do: ask an AI agent connected to KeyValet's MCP server to run {tool}"),
        ),
        (None, Some(id)) => format!("keyvalet set {id} <name>"),
        (None, None) => "keyvalet set <type> <name>".to_string(),
    }
}

/// The per-file, per-line report `scan` always prints first -- what a `--report-only` run, or a
/// run that finds nothing importable, stops at.
fn render_report(hits: &[ScanHit]) -> String {
    let mut out = String::new();
    let mut last: Option<&std::path::Path> = None;
    for h in hits {
        if last != Some(h.path.as_path()) {
            out.push_str(&format!("{}\n", h.path.display()));
            last = Some(h.path.as_path());
        }
        out.push_str(&format!(
            "  :{}\t{} ({})\t{}\n",
            h.line_no,
            h.hit.label,
            h.hit.preview,
            suggestion(&h.hit)
        ));
    }
    out
}

/// A dialog checkbox-list item label for one hit -- unique per (path, line, label, preview), so
/// the string the user picks can be matched straight back to its `ScanHit` with no separate ID
/// scheme. Never includes the real value, only the masked preview.
/// `idx` (the item's position in the dialog's item list) makes this unique even when two
/// different hits happen to render identically otherwise -- e.g. two distinct secrets on the
/// same line whose masked previews happen to come out the same (`mask` only reveals a few
/// prefix/suffix characters). Without that, matching the user's selection back by string equality
/// could silently pick up both when only one was checked.
fn dialog_label(idx: usize, h: &ScanHit) -> String {
    format!(
        "[{}] {} :{} -- {} ({})",
        idx + 1,
        h.path.display(),
        h.line_no,
        h.hit.label,
        h.hit.preview
    )
}

/// A deterministic default credential name from where it was found -- there's no further prompt
/// per item, so the name has to come from somewhere recognizable. `.env` -> "env", `.env.local`
/// -> "env-local", `.zshrc` -> "zshrc", `mcp.json` -> "mcp-json".
fn credential_name_from_path(path: &std::path::Path) -> String {
    let name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("secret");
    let cleaned: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();
    let cleaned = cleaned.trim_matches('-');
    if cleaned.is_empty() {
        "secret".to_string()
    } else {
        cleaned.to_string()
    }
}

/// Picks a name that doesn't collide with an existing credential of the same type (checked
/// against the real vault) or with another one picked earlier in this same run (`claimed`).
/// Never overwrites -- on a collision it appends `-2`, `-3`, ... until one is free, since there's
/// no reliable way to tell whether an existing same-type/same-name credential already holds this
/// exact value without decrypting it.
fn unique_name(
    vault: &Vault,
    ty: &str,
    base: &str,
    claimed: &mut std::collections::HashSet<String>,
) -> String {
    let mut candidate = base.to_string();
    let mut n = 2;
    while claimed.contains(&format!("{ty}/{candidate}"))
        || vault.exists(ty, &candidate).unwrap_or(false)
    {
        candidate = format!("{base}-{n}");
        n += 1;
    }
    claimed.insert(format!("{ty}/{candidate}"));
    candidate
}

/// What a removed secret's value is replaced with in the file -- deliberately not a working
/// substitute (there's no runtime that resolves a `${KEYVALET:...}`-style reference back into a
/// real value yet, see docs/runtimes.md), so inserting one would make the file look migrated
/// while silently breaking whatever reads it. An obviously-broken, loudly-named placeholder fails
/// immediately and visibly instead, and points at the one thing that does work today:
/// `keyvalet get` for manual rewiring.
fn placeholder_for(ty: &str, name: &str) -> String {
    format!("KEYVALET_MOVED_RUN_keyvalet_get_{ty}_{name}_TO_RETRIEVE")
}

/// Applies every `(line_no, real value -> placeholder)` replacement to `content`, scoped to the
/// specific line each hit was found on -- not a global substitution. A global replace would also
/// mangle an unselected secret elsewhere in the file if its exact text happened to appear as a
/// substring of a selected one (e.g. one token containing another as a prefix); scoping to the
/// line that `detect_with_values` actually matched on avoids that, and only has to touch the
/// lines that need it. `split_inclusive('\n')` keeps whatever line ending each line already had
/// (bare `\n` or `\r\n`) instead of normalizing them.
fn rewrite_content(content: &str, replacements: &[(usize, String, String)]) -> String {
    let mut by_line: std::collections::HashMap<usize, Vec<(&str, &str)>> = Default::default();
    for (line_no, raw, placeholder) in replacements {
        by_line
            .entry(*line_no)
            .or_default()
            .push((raw.as_str(), placeholder.as_str()));
    }
    let mut out = String::with_capacity(content.len());
    for (i, chunk) in content.split_inclusive('\n').enumerate() {
        match by_line.get(&(i + 1)) {
            None => out.push_str(chunk),
            Some(subs) => {
                let mut line = chunk.to_string();
                for (raw, placeholder) in subs {
                    line = line.replace(raw, placeholder);
                }
                out.push_str(&line);
            }
        }
    }
    out
}

#[cfg(unix)]
fn escape_applescript_string(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Runs an AppleScript with privileges dropped to the user who invoked `sudo` -- root can't reach
/// that user's GUI session directly. Mirrors what
/// `kv_platform::macos::RootUserDialogConfirmer` does for the helper daemon, duplicated here in
/// miniature: that version is async (tokio, for the helper's long-running event loop) and kv-cli
/// is a plain synchronous binary, so pulling in tokio for one dialog call wasn't worth it.
/// `None` means the dialog couldn't even be attempted (no `SUDO_UID`/`SUDO_GID` -- e.g. kv-cli
/// invoked as literal root, not via `sudo` -- or `osascript` itself failed to run).
#[cfg(unix)]
fn run_osascript_as_user(script: &str, args: &[&str]) -> Option<(i32, String)> {
    let (uid, gid) = kv_platform::user::invoking_user()?;
    use std::os::unix::process::CommandExt;
    let mut cmd = std::process::Command::new(kv_platform::paths::OSASCRIPT_BIN);
    cmd.arg("-e").arg(script).arg("--").args(args);
    cmd.current_dir("/")
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .stdin(std::process::Stdio::null());
    // Not `uid`/`gid`: on macOS that sequence leaves the child with effective gid 0 (wheel).
    unsafe {
        cmd.pre_exec(kv_platform::user::drop_to(uid, gid));
    }
    let out = cmd.output().ok()?;
    Some((
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).to_string(),
    ))
}

/// Shows a native multi-select checkbox-style list in the invoking user's GUI session
/// (AppleScript's `choose from list ... with multiple selections allowed`). `None` means the
/// dialog couldn't be shown at all (see `run_osascript_as_user`). `Some(vec![])` covers both
/// Cancel and "OK with nothing checked" -- the same outcome here (import nothing) -- so callers
/// don't need to tell them apart. Items are passed as actual argv list elements, not interpolated
/// into the script text, so arbitrary file paths/previews in them can't affect the AppleScript
/// itself.
#[cfg(unix)]
fn choose_from_list(prompt: &str, items: &[String]) -> Option<Vec<String>> {
    if items.is_empty() {
        return Some(Vec::new());
    }
    let script = format!(
        r#"on run argv
  try
    with timeout of 120 seconds
      set r to choose from list argv with title "KeyValet" with prompt "{}" with multiple selections allowed and empty selection allowed
    end timeout
  on error
    return ""
  end try
  if r is false then return ""
  set out to ""
  repeat with i in r
    set out to out & i & linefeed
  end repeat
  return out
end run"#,
        escape_applescript_string(prompt)
    );
    let item_refs: Vec<&str> = items.iter().map(String::as_str).collect();
    let (code, out) = run_osascript_as_user(&script, &item_refs)?;
    if code != 0 {
        return None;
    }
    Some(
        out.lines()
            .map(str::to_string)
            .filter(|s| !s.is_empty())
            .collect(),
    )
}

/// Shows a native two-button confirmation in the invoking user's GUI session. `false` on Cancel,
/// on a timeout, or if the dialog couldn't be shown at all -- "did nothing" is always the safe
/// default for this tool.
#[cfg(unix)]
fn confirm_yes_no(message: &str, yes_label: &str, no_label: &str) -> bool {
    let script = format!(
        r#"on run argv
  try
    with timeout of 120 seconds
      set r to display dialog "{}" with title "KeyValet" buttons {{"{}", "{}"}} default button "{}" cancel button "{}" with icon caution
    end timeout
  on error
    return "{}"
  end try
  return button returned of r
end run"#,
        escape_applescript_string(message),
        escape_applescript_string(no_label),
        escape_applescript_string(yes_label),
        escape_applescript_string(yes_label),
        escape_applescript_string(no_label),
        escape_applescript_string(no_label),
    );
    matches!(run_osascript_as_user(&script, &[]), Some((0, out)) if out.trim() == yes_label)
}

/// Checkbox dialogs belong to the per-user agent (W3); until then the import path is skipped
/// with an explicit message rather than silently pretending.
#[cfg(windows)]
fn choose_from_list(_prompt: &str, _items: &[String]) -> Option<Vec<String>> {
    None
}

#[cfg(windows)]
fn confirm_yes_no(_message: &str, _yes_label: &str, _no_label: &str) -> bool {
    false
}

/// The slice of `catalog.json` `keyvalet scan` needs to configure an imported credential for the
/// proxy. Deliberately minimal and local to kv-cli: kv-mcp's full template loader pulls in
/// rmcp/tokio, which a synchronous CLI doesn't want.
#[derive(serde::Deserialize)]
struct ScanTemplateField {
    name: String,
    #[serde(default)]
    secret: bool,
}

#[derive(serde::Deserialize)]
struct ScanTemplate {
    id: String,
    name: String,
    #[serde(default = "default_static_kind")]
    kind: String,
    fields: Vec<ScanTemplateField>,
    inject: Option<Value>,
    test: Option<Value>,
    #[serde(default)]
    hosts: Vec<String>,
}

fn default_static_kind() -> String {
    "static".to_string()
}

/// Reads `<dir>/catalog.json` and returns the template whose id matches `id`
/// (case-insensitively), or `None` when the file is missing, unparseable, or has no match.
/// Production passes `kv_platform::paths::TEMPLATES_DIR`; tests point at the repo's own
/// `templates/` via `env!("CARGO_MANIFEST_DIR")` so they don't depend on a KeyValet install.
fn catalog_template(dir: &std::path::Path, id: &str) -> Option<ScanTemplate> {
    #[derive(serde::Deserialize)]
    struct Catalog {
        templates: Vec<ScanTemplate>,
    }
    let text = std::fs::read_to_string(dir.join("catalog.json")).ok()?;
    let catalog: Catalog = serde_json::from_str(&text).ok()?;
    catalog
        .templates
        .into_iter()
        .find(|t| t.id.eq_ignore_ascii_case(id.trim()))
}

/// The `set_static` parameters for importing `raw` under template `tpl`, mirroring what
/// `kv-mcp`'s `set_from_template` sends to the root helper -- minus `value`, which template
/// credentials never set. `proxy_only: true` is deliberate: the point of moving a key out of
/// `.env` is that the AI can only use it through the proxy, while `keyvalet get` still works
/// for the human. `None` when the template can't carry a single raw secret (non-static kind,
/// zero or several secret fields, no injection rule, no allowed hosts).
fn template_import_params(
    tpl: &ScanTemplate,
    ty: &str,
    name: &str,
    raw: &str,
    description: &str,
) -> Option<Map<String, Value>> {
    let secret_fields: Vec<&ScanTemplateField> = tpl.fields.iter().filter(|f| f.secret).collect();
    if tpl.kind != "static"
        || secret_fields.len() != 1
        || tpl.inject.is_none()
        || tpl.hosts.is_empty()
    {
        return None;
    }
    let mut secrets = Map::new();
    secrets.insert(secret_fields[0].name.clone(), json!(raw));
    let mut p = Map::new();
    p.insert("type".into(), json!(ty));
    p.insert("name".into(), json!(name));
    p.insert("secrets".into(), Value::Object(secrets));
    p.insert(
        "http".into(),
        json!({
            "inject": tpl.inject,
            "allowed_hosts": tpl.hosts,
            "proxy_only": true,
            "test": tpl.test,
        }),
    );
    p.insert("template".into(), json!(tpl.id));
    p.insert("description".into(), json!(description));
    p.insert("type_description".into(), json!(tpl.name));
    Some(p)
}

/// `keyvalet scan` (action-plan 4.1). Scans the usual places, prints what it found, then -- the
/// `tool`-less, `id`-having hits only, since those are the only ones `keyvalet set` can create
/// correctly -- offers a native checkbox dialog to import some of them into the vault. A hit
/// whose type matches a `catalog.json` template is imported via `kv_core::set_static` with the
/// template's injection rule and allowed hosts as proxy-only, so the credential is proxyable
/// (and its value unreadable by agents) from the start; anything else falls back to a plain
/// `vault.set`. Anything imported gets removed from its source file (backed up first) and
/// replaced with an obviously-broken placeholder rather than a working substitute, since there's
/// no runtime yet that resolves a reference back into a real value (see `placeholder_for`). Ends
/// by asking,
/// in one more native dialog, whether to delete the just-made backups now or keep them -- that's
/// the "confirm, then delete the backup" step from the original plan: an explicit choice made
/// right here, not an automatic deletion with no way to verify anything still works first.
fn scan(args: &[String], vault: &Vault, client: &Value) {
    let report_only = args.iter().any(|a| a == "--report-only");
    let hits = scan_hits(&scan_paths());
    print!("{}", render_report(&hits));
    if hits.is_empty() {
        println!(
            "{}",
            kv_i18n::t(
                "没有在常见位置发现明显的密钥。",
                "No obvious secrets found in the usual places."
            )
        );
        return;
    }
    println!();
    println!(
        "{}",
        kv_i18n::t(
            &format!("共 {} 条可能的密钥。", hits.len()),
            &format!("{} possible secret(s) total.", hits.len())
        )
    );
    if report_only {
        println!(
            "{}",
            kv_i18n::t(
                "只是检测，没有改动任何文件：要收进 KeyValet，用上面建议的命令逐条处理。",
                "This only detects, it didn't change any file: handle each one with the suggested command above."
            )
        );
        return;
    }

    let importable: Vec<&ScanHit> = hits
        .iter()
        .filter(|h| h.hit.tool.is_none() && h.hit.id.is_some())
        .collect();
    if importable.is_empty() {
        println!(
            "{}",
            kv_i18n::t(
                "这些都需要按上面的建议手动处理，没有能直接导入的。",
                "All of these need manual handling per the suggestions above; none can be imported directly."
            )
        );
        return;
    }

    if cfg!(windows) {
        println!(
            "{}",
            kv_i18n::t(
                "检测到可导入的密钥，但图形导入对话框要到 W3（每用户 agent）才可用；现在请用上面的建议命令手动处理。",
                "Importable secrets were found, but the selection dialog needs the per-user agent (W3); for now handle them by hand with the suggested commands above."
            )
        );
        return;
    }
    let items: Vec<String> = importable
        .iter()
        .enumerate()
        .map(|(i, h)| dialog_label(i, h))
        .collect();
    let prompt = kv_i18n::t(
        &format!("KeyValet 在这些地方发现了 {} 个可能的密钥。勾选要收进 KeyValet 的，不勾选就不会动那一条。导入后 AI 只能通过代理使用这些凭证，看不到明文；终端里 keyvalet get 仍可读取。", importable.len()),
        &format!("KeyValet found {} possible secret(s) in these places. Check the ones to move into KeyValet; anything left unchecked is not touched. After import, AI agents can only use these through the proxy and never see the value; keyvalet get in a terminal can still read it.", importable.len()),
    );
    let Some(selected) = choose_from_list(&prompt, &items) else {
        println!(
            "{}",
            kv_i18n::t(
                "没能弹出选择窗口（没有通过 sudo 调用，或 osascript 失败），跳过导入；可以用上面建议的命令手动处理。",
                "Couldn't show the selection dialog (not invoked via sudo, or osascript failed); skipping import. Handle them by hand with the suggested commands above."
            )
        );
        return;
    };
    if selected.is_empty() {
        println!(
            "{}",
            kv_i18n::t(
                "没有勾选任何一条，没有做任何改动。",
                "Nothing was checked; no changes were made."
            )
        );
        return;
    }
    // Matched back by looking up the exact item string's position, not by re-deriving the label
    // from the hit: the `[N]` prefix in `dialog_label` only disambiguates two hits that would
    // otherwise render identically, so this has to go through the same strings the dialog showed.
    let chosen: Vec<&ScanHit> = selected
        .iter()
        .filter_map(|s| items.iter().position(|it| it == s))
        .map(|i| importable[i])
        .collect();

    let mut claimed_names = std::collections::HashSet::new();
    // The name actually assigned travels with each imported hit -- `unique_name` may have
    // disambiguated it (e.g. "env-2"), and the rewrite step below needs that exact name for the
    // placeholder, not whatever `credential_name_from_path` would recompute from scratch.
    let mut imported: Vec<(&ScanHit, String)> = Vec::new();
    for h in &chosen {
        let ty = h.hit.id.clone().unwrap();
        let base = credential_name_from_path(&h.path);
        let name = unique_name(vault, &ty, &base, &mut claimed_names);
        let mut target = Map::new();
        target.insert("type".into(), json!(ty));
        target.insert("name".into(), json!(name));
        target.insert("op".into(), json!("scanImport"));
        let description = kv_i18n::t(
            &format!("keyvalet scan 从 {}:{} 导入", h.path.display(), h.line_no),
            &format!(
                "Imported by keyvalet scan from {}:{}",
                h.path.display(),
                h.line_no
            ),
        );
        let tpl = catalog_template(std::path::Path::new(kv_platform::paths::TEMPLATES_DIR), &ty);
        let params = tpl
            .as_ref()
            .and_then(|t| template_import_params(t, &ty, &name, &h.raw, &description));
        let used_template = tpl
            .as_ref()
            .filter(|_| params.is_some())
            .map(|t| (t.id.clone(), t.hosts.clone()));
        let result: kv_vault::Result<()> = match &params {
            Some(p) => kv_core::set_static(vault, p).map(|_| ()),
            None => vault
                .set(SetParams {
                    r#type: ty.clone(),
                    name: name.clone(),
                    value: Some(h.raw.clone()),
                    description: Some(description),
                    type_description: Some(kv_i18n::t(
                        "keyvalet scan 自动创建",
                        "Auto-created by keyvalet scan",
                    )),
                    ..Default::default()
                })
                .map(|_| ()),
        };
        match result {
            Ok(_) => {
                if let Some((id, _)) = &used_template {
                    target.insert("template".into(), json!(id));
                }
                target.insert("ok".into(), json!(true));
                target.insert("client".into(), client.clone());
                let _ = vault.audit(target);
                println!(
                    "{}",
                    kv_i18n::t(
                        &format!(
                            "已导入 {ty}/{name}（来自 {}:{}）",
                            h.path.display(),
                            h.line_no
                        ),
                        &format!(
                            "Imported {ty}/{name} (from {}:{})",
                            h.path.display(),
                            h.line_no
                        )
                    )
                );
                if let Some((_, hosts)) = &used_template {
                    println!(
                        "{}",
                        kv_i18n::t(
                            &format!(
                                "  可通过代理调用（仅代理，AI 看不到明文）：{}",
                                hosts.join("、")
                            ),
                            &format!(
                                "  proxyable (proxy-only, value hidden from AI): {}",
                                hosts.join(", ")
                            )
                        )
                    );
                }
                imported.push((h, name.clone()));
            }
            Err(e) => {
                target.insert("ok".into(), json!(false));
                target.insert("error".into(), json!(e.0));
                target.insert("client".into(), client.clone());
                let _ = vault.audit(target);
                println!(
                    "{}",
                    kv_i18n::t(
                        &format!("导入 {ty}/{name} 失败：{}，跳过（原文件未改动）", e.0),
                        &format!(
                            "Failed to import {ty}/{name}: {}, skipping (original file untouched)",
                            e.0
                        )
                    )
                );
            }
        }
    }

    if imported.is_empty() {
        println!(
            "{}",
            kv_i18n::t(
                "没有成功导入的，原文件都没有改动。",
                "Nothing was imported successfully; no file was changed."
            )
        );
        return;
    }

    let mut by_path: std::collections::BTreeMap<std::path::PathBuf, Vec<(&ScanHit, &str)>> =
        Default::default();
    for (h, name) in &imported {
        by_path
            .entry(h.path.clone())
            .or_default()
            .push((h, name.as_str()));
    }
    let mut backups = Vec::new();
    for (path, hs) in &by_path {
        let Ok(content) = std::fs::read_to_string(path) else {
            continue; // changed/vanished since the scan -- leave it alone
        };
        // The exact name assigned at import time (which may be e.g. "env-2" if "env" was already
        // taken) -- not recomputed from the path, or two hits imported from the same file under
        // disambiguated names would both get a placeholder pointing at just the first one.
        let replacements: Vec<(usize, String, String)> = hs
            .iter()
            .map(|(h, name)| {
                (
                    h.line_no,
                    h.raw.clone(),
                    placeholder_for(&h.hit.id.clone().unwrap(), name),
                )
            })
            .collect();
        let mut backup = std::path::PathBuf::from(format!("{}.bak-keyvalet", path.display()));
        let mut n = 2;
        while backup.exists() {
            backup = std::path::PathBuf::from(format!("{}.bak-keyvalet-{n}", path.display()));
            n += 1;
        }
        if std::fs::copy(path, &backup).is_err() {
            println!(
                "{}",
                kv_i18n::t(
                    &format!("无法备份 {}，跳过改写这个文件（已导入的凭证仍然有效）", path.display()),
                    &format!("Couldn't back up {}, skipping the rewrite for this file (the already-imported credentials are still valid)", path.display())
                )
            );
            continue;
        }
        let new_content = rewrite_content(&content, &replacements);
        if let Err(e) = std::fs::write(path, new_content) {
            // `fs::write` truncates on open before writing, so a failure partway through can
            // leave the file already-truncated rather than genuinely untouched -- the backup is
            // the only way back at that point, so it must not be deleted here.
            println!(
                "{}",
                kv_i18n::t(
                    &format!("写入 {} 失败（{e}），文件内容可能已经被截断或损坏；备份保留在 {}，可以手动复制回去恢复", path.display(), backup.display()),
                    &format!("Failed to write {} ({e}); its contents may already be truncated or corrupted. The backup was kept at {} -- copy it back by hand to recover", path.display(), backup.display())
                )
            );
            continue;
        }
        println!(
            "{}",
            kv_i18n::t(
                &format!(
                    "已从 {} 移除 {} 条，备份在 {}",
                    path.display(),
                    hs.len(),
                    backup.display()
                ),
                &format!(
                    "Removed {} secret(s) from {}, backup at {}",
                    hs.len(),
                    path.display(),
                    backup.display()
                )
            )
        );
        backups.push(backup);
    }

    if backups.is_empty() {
        return;
    }
    let message = kv_i18n::t(
        &format!("已导入 {} 个凭证，改写了 {} 个文件。现在删除刚才的备份文件吗？如果还没确认改写后一切正常，建议先保留。", imported.len(), backups.len()),
        &format!("Imported {} credential(s) and rewrote {} file(s). Delete the backups made just now? If you haven't confirmed everything still works after the rewrite, it's safer to keep them for now.", imported.len(), backups.len()),
    );
    let delete_label = kv_i18n::t("删除备份", "Delete backups");
    let keep_label = kv_i18n::t("保留备份", "Keep backups");
    if confirm_yes_no(&message, &delete_label, &keep_label) {
        for b in &backups {
            let _ = std::fs::remove_file(b);
        }
        println!(
            "{}",
            kv_i18n::t("已删除备份文件。", "Backup files deleted.")
        );
    } else {
        println!(
            "{}",
            kv_i18n::t(
                "保留了备份文件，路径见上面的输出。",
                "Kept the backup files; see the paths printed above."
            )
        );
    }
}

#[cfg(test)]
mod scan_tests {
    use super::{
        catalog_template, credential_name_from_path, render_report, rewrite_content, scan_hits,
        static_secret_to_print, template_import_params, unique_name,
    };
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

    /// A `Vault` over a tempdir with a file key -- the same fixture `unique_name`'s test uses.
    /// The vault lives in a fresh subdirectory, not the tempdir root: `Vault::init` only chmods
    /// a directory it creates, and an existing one keeps its (too-open) OS permissions.
    fn test_vault() -> (tempfile::TempDir, kv_vault::Vault) {
        let dir = tempfile::tempdir().unwrap();
        let vault = kv_vault::Vault::new(dir.path().join("vault"));
        vault.prepare().unwrap();
        if !vault.dir.join("master.key").exists() {
            // Explicit legacy fixture: production code never creates this file.
            std::fs::write(vault.dir.join("master.key"), [7u8; 32]).unwrap();
            #[cfg(unix)]
            std::fs::set_permissions(
                vault.dir.join("master.key"),
                <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o600),
            )
            .unwrap();
        }
        vault.init_legacy().unwrap();
        (dir, vault)
    }

    /// The repo's `templates/` directory -- not the installed copy under
    /// `kv_platform::paths::TEMPLATES_DIR`, which doesn't exist on machines without KeyValet.
    fn repo_templates_dir() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../templates")
    }

    #[test]
    fn reports_a_secret_with_its_line_number_and_a_set_suggestion() {
        let (_dir, path) = write_tmp(
            ".env",
            "APP_NAME=demo\nOPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyz0123456789\n",
        );
        let hits = scan_hits(std::slice::from_ref(&path));
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].raw, "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789");
        let report = render_report(&hits);
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
        let hits = scan_hits(&[path]);
        assert!(hits.is_empty());
        assert_eq!(render_report(&hits), "");
    }

    #[test]
    fn a_missing_file_is_skipped_without_failing_the_rest_of_the_scan() {
        let (_dir, present) =
            write_tmp(".env", "KEY=sk-proj-abcdefghijklmnopqrstuvwxyz0123456789\n");
        let missing = present.parent().unwrap().join("does-not-exist");
        let hits = scan_hits(&[missing, present]);
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn aws_keys_suggest_the_dedicated_setup_tool_not_a_plain_set() {
        // Not AWS's own well-known AKIA...EXAMPLE key -- `looks_random` filters out anything
        // matching "example" as an obvious placeholder, which would defeat this test.
        let (_dir, path) = write_tmp(".env", "AWS_ACCESS_KEY_ID=AKIAZQ3EXFAKE7NMKLPQ\n");
        let hits = scan_hits(&[path]);
        assert!(hits[0].hit.tool.is_some());
        let report = render_report(&hits);
        assert!(report.contains("credential_setup_aws"));
    }

    #[test]
    fn credential_names_come_from_the_file_they_were_found_in() {
        assert_eq!(
            credential_name_from_path(std::path::Path::new(".env")),
            "env"
        );
        assert_eq!(
            credential_name_from_path(std::path::Path::new(".env.local")),
            "env-local"
        );
        assert_eq!(
            credential_name_from_path(std::path::Path::new(".zshrc")),
            "zshrc"
        );
        assert_eq!(
            credential_name_from_path(std::path::Path::new("/a/b/mcp.json")),
            "mcp-json"
        );
    }

    #[test]
    fn unique_name_avoids_both_vault_collisions_and_same_run_collisions() {
        let dir = tempfile::tempdir().unwrap();
        // A fresh subdirectory, not the tempdir root itself: `Vault::init` only chmods a
        // directory it creates -- an already-existing one (the tempdir root) keeps whatever
        // permissions the OS gave it and fails the "not group/world readable" check.
        let vault = kv_vault::Vault::new(dir.path().join("vault"));
        vault.prepare().unwrap();
        if !vault.dir.join("master.key").exists() {
            // Explicit legacy fixture: production code never creates this file.
            std::fs::write(vault.dir.join("master.key"), [7u8; 32]).unwrap();
            #[cfg(unix)]
            std::fs::set_permissions(
                vault.dir.join("master.key"),
                <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o600),
            )
            .unwrap();
        }
        vault.init_legacy().unwrap();
        vault
            .set(kv_vault::SetParams {
                r#type: "openai".into(),
                name: "env".into(),
                value: Some("sk-proj-abcdefghijklmnopqrstuvwxyz0123456789".into()),
                ..Default::default()
            })
            .unwrap();
        let mut claimed = std::collections::HashSet::new();
        // Collides with the credential that already exists in the vault.
        assert_eq!(unique_name(&vault, "openai", "env", &mut claimed), "env-2");
        // Collides with the name just claimed above, within this same run.
        assert_eq!(unique_name(&vault, "openai", "env", &mut claimed), "env-3");
        // A different type never collides with "openai/env".
        assert_eq!(unique_name(&vault, "anthropic", "env", &mut claimed), "env");
    }

    #[test]
    fn rewrite_removes_the_real_value_and_leaves_an_obviously_broken_placeholder() {
        let content =
            "APP_NAME=demo\nOPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyz0123456789\n";
        let out = rewrite_content(
            content,
            &[(
                2,
                "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789".to_string(),
                super::placeholder_for("openai", "env"),
            )],
        );
        assert!(!out.contains("sk-proj-abcdefghijklmnopqrstuvwxyz0123456789"));
        assert!(out.contains("KEYVALET_MOVED_RUN_keyvalet_get_openai_env_TO_RETRIEVE"));
        assert!(
            out.contains("APP_NAME=demo"),
            "untouched lines must survive as-is"
        );
    }

    #[test]
    fn rewrite_only_touches_the_specific_line_a_hit_was_found_on() {
        // "secret" (the selected, imported value) is also a literal substring of
        // "unrelated-secret-token" on another line, which was never selected. A global
        // find-and-replace across the whole file would mangle that unrelated line too; scoping
        // the replacement to line 1 must leave line 2 completely alone.
        let content = "KEY=secret\nOTHER=unrelated-secret-token\n";
        let out = rewrite_content(
            content,
            &[(1, "secret".to_string(), "PLACEHOLDER".to_string())],
        );
        assert_eq!(out, "KEY=PLACEHOLDER\nOTHER=unrelated-secret-token\n");
    }

    #[test]
    fn catalog_template_finds_templates_case_insensitively() {
        let dir = repo_templates_dir();
        let tpl = catalog_template(&dir, "openai").expect("openai template");
        assert_eq!(tpl.hosts, vec!["api.openai.com".to_string()]);
        let secrets: Vec<&str> = tpl
            .fields
            .iter()
            .filter(|f| f.secret)
            .map(|f| f.name.as_str())
            .collect();
        assert_eq!(secrets, ["apiKey"]);
        assert!(tpl.inject.is_some());
        assert!(tpl.test.is_some());
        assert!(catalog_template(&dir, "OpenAI").is_some());
        assert!(catalog_template(&dir, "nonexistent").is_none());

        let missing = tempfile::tempdir().unwrap();
        assert!(catalog_template(missing.path(), "openai").is_none());
    }

    #[test]
    fn template_import_params_build_a_proxy_only_set_static_request() {
        let tpl = catalog_template(&repo_templates_dir(), "openai").unwrap();
        let p = template_import_params(&tpl, "openai", "env", "sk-raw", "desc").unwrap();
        assert_eq!(p["secrets"], serde_json::json!({"apiKey": "sk-raw"}));
        assert_eq!(
            p["http"]["allowed_hosts"],
            serde_json::json!(["api.openai.com"])
        );
        assert_eq!(p["http"]["proxy_only"], serde_json::json!(true));
        assert_eq!(p["template"], serde_json::json!("openai"));
        assert!(!p.contains_key("value"));
    }

    #[test]
    fn template_import_params_rejects_templates_a_single_raw_value_cannot_fill() {
        let dir = repo_templates_dir();
        // datadog needs two secret fields (apiKey + appKey); jira has no allowed hosts.
        let datadog = catalog_template(&dir, "datadog").unwrap();
        assert!(template_import_params(&datadog, "datadog", "env", "x", "d").is_none());
        let jira = catalog_template(&dir, "jira").unwrap();
        assert!(template_import_params(&jira, "jira", "env", "x", "d").is_none());
    }

    #[test]
    fn set_static_from_template_params_stores_a_proxy_only_credential() {
        let (_dir, vault) = test_vault();
        let tpl = catalog_template(&repo_templates_dir(), "openai").unwrap();
        let p = template_import_params(&tpl, "openai", "env", "sk-raw", "desc").unwrap();
        kv_core::set_static(&vault, &p).unwrap();
        let (_, _, record) = vault.get_record("openai", "env").unwrap();
        let http = record.http.as_ref().unwrap();
        assert!(http.proxy_only);
        assert_eq!(http.allowed_hosts, vec!["api.openai.com".to_string()]);
        assert_eq!(record.template.as_deref(), Some("openai"));
        assert_eq!(
            record
                .secrets
                .as_ref()
                .unwrap()
                .get("apiKey")
                .map(String::as_str),
            Some("sk-raw")
        );
        // The agent-facing read path refuses proxy-only credentials outright.
        assert!(vault.get("openai", "env").is_err());
    }

    #[test]
    fn static_secret_to_print_prefers_value_then_falls_back_to_secrets() {
        let mut record = kv_vault::CredentialRecord::default();
        record.value = "plain".to_string();
        assert_eq!(static_secret_to_print(&record), "plain");

        let mut record = kv_vault::CredentialRecord::default();
        record.secrets = Some([("apiKey".to_string(), "sk-raw".to_string())].into());
        assert_eq!(static_secret_to_print(&record), "sk-raw");

        let mut record = kv_vault::CredentialRecord::default();
        record.secrets = Some(
            [
                ("apiKey".to_string(), "a".to_string()),
                ("appKey".to_string(), "b".to_string()),
            ]
            .into(),
        );
        let out = static_secret_to_print(&record);
        assert!(out.contains("apiKey") && out.contains("appKey"));
        assert!(out.contains("\"fields\""));
    }

    #[test]
    fn dialog_labels_stay_distinct_even_when_two_hits_render_identically_otherwise() {
        let (_dir, path) = write_tmp(
            ".env",
            "A=sk-proj-abcdefghijklmnopqrstuvwxyz0123456789\nB=sk-proj-abcdefghijklmnopqrstuvwxyz0123456789\n",
        );
        let hits = scan_hits(&[path]);
        assert_eq!(hits.len(), 2);
        // Same file, different lines -- dialog_label must still differ, driven by the `[N]`
        // index rather than anything derived from the hit itself.
        let a = super::dialog_label(0, &hits[0]);
        let b = super::dialog_label(1, &hits[1]);
        assert_ne!(a, b);
        assert!(a.starts_with("[1]"));
        assert!(b.starts_with("[2]"));
    }
}

#[cfg(all(test, unix))]
mod daemon_state_tests {
    use super::*;

    #[test]
    fn busy_only_when_sessions_exist_or_the_daemon_wont_answer() {
        assert!(!is_busy(DaemonState::NotRunning));
        assert!(!is_busy(DaemonState::Sessions(0)));
        assert!(is_busy(DaemonState::Sessions(1)));
        assert!(is_busy(DaemonState::Unknown));
    }
}
