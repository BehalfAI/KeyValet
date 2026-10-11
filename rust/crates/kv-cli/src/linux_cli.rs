//! Linux terminal management UI. Interactive input always uses the controlling
//! terminal; system dependencies are explicit so approval policy is testable.
use std::io::{self, BufRead, Read, Write};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

type UserLookup = unsafe extern "C" fn(
    libc::uid_t,
    *mut libc::passwd,
    *mut libc::c_char,
    usize,
    *mut *mut libc::passwd,
) -> libc::c_int;
trait TerminalIo: Read + Write {}
impl<T: Read + Write> TerminalIo for T {}
type TerminalOpener = Box<dyn Fn(&Path) -> io::Result<Box<dyn TerminalIo>>>;

pub struct Environment {
    cli_path: PathBuf,
    agent_path: PathBuf,
    proc_path: PathBuf,
    tty_path: PathBuf,
    current_exe: fn() -> io::Result<PathBuf>,
    uid: unsafe extern "C" fn() -> libc::uid_t,
    args: Vec<String>,
    invoking_user: fn() -> Option<(u32, u32)>,
    lookup: UserLookup,
    start_time: fn(u32) -> io::Result<u64>,
    trust: fn(&Path) -> Option<String>,
    exec: fn(Command) -> io::Error,
    open_terminal: TerminalOpener,
}

impl Environment {
    pub fn system() -> Self {
        Self {
            cli_path: kv_platform::paths::CLI_BIN.into(),
            agent_path: "/usr/bin/pkttyagent".into(),
            proc_path: "/proc".into(),
            tty_path: "/dev/tty".into(),
            current_exe: std::env::current_exe,
            uid: libc::getuid,
            args: std::env::args().collect(),
            invoking_user: kv_platform::user::invoking_user,
            lookup: libc::getpwuid_r,
            start_time: kv_platform::peer::process_start_time,
            trust: kv_platform::trust::untrusted_reason,
            exec: exec_agent,
            open_terminal: Box::new(open_terminal),
        }
    }
}

fn open_terminal(path: &Path) -> io::Result<Box<dyn TerminalIo>> {
    Ok(Box::new(
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)?,
    ))
}
fn exec_agent(mut command: Command) -> io::Error {
    command.exec()
}

pub fn approve(env: &Environment) -> Result<(), String> {
    if (env.current_exe)().unwrap_or_default() != env.cli_path {
        return Err("run the installed keyvalet approve <kv-mcp-pid>".into());
    }
    let uid = unsafe { (env.uid)() };
    if uid == 0 {
        return Err("run approve as the regular user, without sudo".into());
    }
    let pid: u32 = env
        .args
        .get(2)
        .and_then(|s| s.parse().ok())
        .filter(|_| env.args.len() == 3)
        .ok_or("usage: keyvalet approve <kv-mcp-pid>")?;
    let status = std::fs::read_to_string(env.proc_path.join(pid.to_string()).join("status"))
        .map_err(|e| e.to_string())?;
    if !approval_target_owned_by(&status, uid) {
        return Err("approval target must belong to your user".into());
    }
    let start = (env.start_time)(pid).map_err(|e| e.to_string())?;
    (env.open_terminal)(&env.tty_path).map_err(|_| "approve requires your interactive terminal")?;
    eprintln!("KeyValet polkit agent for process {pid}. Leave this terminal open; Ctrl-C stops the agent.");
    run_agent(env, pid, start)
}

fn run_agent(env: &Environment, pid: u32, start: u64) -> Result<(), String> {
    // Installed executable trust belongs to the real runner, after the target
    // policy has been checked. No user-controlled executable is selected.
    for path in [&env.cli_path, &env.agent_path] {
        if let Some(reason) = (env.trust)(path) {
            return Err(reason);
        }
    }
    let mut command = Command::new(&env.agent_path);
    command
        .args(["--fallback", "--process", &format!("{pid},{start}")])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LANG", "C.UTF-8");
    Err((env.exec)(command).to_string())
}

fn approval_target_owned_by(status: &str, uid: u32) -> bool {
    let mut rows = status.lines().filter_map(|line| line.strip_prefix("Uid:"));
    let Some(row) = rows.next() else {
        return false;
    };
    let ids: Result<Vec<u32>, _> = row.split_whitespace().map(str::parse).collect();
    uid != 0
        && rows.next().is_none()
        && ids.is_ok_and(|ids| ids.len() == 4 && ids.iter().all(|id| *id == uid))
}

pub fn real_home(env: &Environment) -> Result<PathBuf, String> {
    let uid = match (env.invoking_user)() {
        Some((uid, _)) => uid,
        None => unsafe { (env.uid)() },
    };
    let mut record: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result = std::ptr::null_mut();
    let mut buffer = vec![0u8; 16384];
    let rc = unsafe {
        (env.lookup)(
            uid,
            &mut record,
            buffer.as_mut_ptr() as *mut _,
            buffer.len(),
            &mut result,
        )
    };
    if rc != 0 || result.is_null() || record.pw_dir.is_null() {
        return Err("cannot determine the invoking user's home directory".into());
    }
    Ok(PathBuf::from(
        unsafe { std::ffi::CStr::from_ptr(record.pw_dir) }
            .to_string_lossy()
            .into_owned(),
    ))
}

fn terminal_prompt(prompt: &str) -> String {
    // Do not interpret terminal control sequences carried by a filename or preview.
    prompt
        .chars()
        .map(|c| {
            if c.is_control() && c != '\n' && c != '\t' {
                '?'
            } else {
                c
            }
        })
        .collect()
}

fn tty_response(env: &Environment, prompt: &str) -> Option<String> {
    terminal_response((env.open_terminal)(&env.tty_path).ok()?, prompt)
}

fn terminal_response(mut tty: impl Read + Write, prompt: &str) -> Option<String> {
    let shown = terminal_prompt(prompt);
    write!(tty, "{shown}").ok()?;
    tty.flush().ok()?;
    let mut answer = String::new();
    let bytes = std::io::BufReader::new(tty)
        .take(4097)
        .read_line(&mut answer)
        .ok()?;
    if bytes == 0 || bytes > 4096 {
        return None;
    }
    Some(answer.trim().to_owned())
}

pub fn confirm_yes_no(env: &Environment, message: &str, yes_label: &str, _no_label: &str) -> bool {
    tty_response(
        env,
        &format!("{message}\n{yes_label}: type yes to approve [default: cancel]: "),
    )
    .as_deref()
        == Some("yes")
}

pub fn choose_from_list(env: &Environment, prompt: &str, items: &[String]) -> Option<Vec<String>> {
    if items.is_empty() {
        return Some(Vec::new());
    }
    let labels = items
        .iter()
        .enumerate()
        .map(|(i, item)| format!("{}: {item}", i + 1))
        .collect::<Vec<_>>()
        .join("\n");
    let answer = tty_response(
        env,
        &format!("{prompt}\n{labels}\nEnter item numbers separated by spaces (empty cancels): "),
    )?;
    selected_items(&answer, items)
}

fn selected_items(answer: &str, items: &[String]) -> Option<Vec<String>> {
    if answer.trim().is_empty() {
        return None;
    }
    let mut selected = Vec::new();
    for index in answer.split_whitespace() {
        let item = items.get(index.parse::<usize>().ok()?.checked_sub(1)?)?;
        if !selected.contains(item) {
            selected.push(item.clone());
        }
    }
    Some(selected)
}

#[cfg(test)]
mod tests;
