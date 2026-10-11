use super::*;

unsafe extern "C" fn root_uid() -> libc::uid_t {
    0
}
unsafe extern "C" fn user_uid() -> libc::uid_t {
    1000
}
fn fixture_exe() -> io::Result<PathBuf> {
    Ok("/fixture/keyvalet".into())
}
fn missing_exe() -> io::Result<PathBuf> {
    Err(io::Error::other("fixture exe error"))
}
fn fixture_start(pid: u32) -> io::Result<u64> {
    assert_eq!(pid, 123);
    Ok(456)
}
fn failed_start(_: u32) -> io::Result<u64> {
    Err(io::Error::other("fixture process disappeared"))
}
fn fixture_trust(_: &Path) -> Option<String> {
    None
}
fn rejected_trust(_: &Path) -> Option<String> {
    Some("fixture trust failure".into())
}
fn capture_exec(command: Command) -> io::Error {
    assert_eq!(command.get_program(), "/fixture/pkttyagent");
    assert_eq!(
        command.get_args().collect::<Vec<_>>(),
        ["--fallback", "--process", "123,456"]
    );
    let vars = command.get_envs().collect::<Vec<_>>();
    assert_eq!(vars.len(), 2);
    io::Error::other("fixture exec failure")
}

fn environment(temp: &Path) -> Environment {
    let mut env = Environment::system();
    env.cli_path = "/fixture/keyvalet".into();
    env.agent_path = "/fixture/pkttyagent".into();
    env.current_exe = fixture_exe;
    env.uid = user_uid;
    env.proc_path = temp.into();
    env.tty_path = temp.join("tty");
    env.args = vec!["keyvalet".into(), "approve".into(), "123".into()];
    env.start_time = fixture_start;
    env.trust = fixture_trust;
    env.exec = capture_exec;
    env.open_terminal = Box::new(|_| Ok(Box::new(Terminal::default())));
    std::fs::create_dir_all(temp.join("123")).unwrap();
    std::fs::write(temp.join("123/status"), "Uid: 1000 1000 1000 1000\n").unwrap();
    env
}

#[test]
fn approval_checks_its_binary_user_arguments_target_and_terminal_before_exec() {
    let temp = tempfile::tempdir().unwrap();
    let mut env = environment(temp.path());
    assert_eq!(approve(&env).unwrap_err(), "fixture exec failure");
    env.current_exe = missing_exe;
    assert!(approve(&env).unwrap_err().contains("installed"));
    env.current_exe = fixture_exe;
    env.uid = root_uid;
    assert!(approve(&env).unwrap_err().contains("without sudo"));
    env.uid = user_uid;
    for args in [
        vec!["keyvalet", "approve"],
        vec!["keyvalet", "approve", "invalid"],
        vec!["keyvalet", "approve", "123", "extra"],
    ] {
        env.args = args.into_iter().map(str::to_owned).collect();
        assert!(approve(&env).unwrap_err().contains("usage:"));
    }
    env.args = vec!["keyvalet".into(), "approve".into(), "123".into()];
    std::fs::write(temp.path().join("123/status"), "Uid: 1001 1001 1001 1001\n").unwrap();
    assert!(approve(&env).unwrap_err().contains("belong to your user"));
    std::fs::write(temp.path().join("123/status"), "Uid: 1000 1000 1000 1000\n").unwrap();
    env.start_time = failed_start;
    assert!(approve(&env).unwrap_err().contains("disappeared"));
    env.start_time = fixture_start;
    env.open_terminal = Box::new(|_| Err(io::Error::other("fixture no terminal")));
    assert!(approve(&env).unwrap_err().contains("interactive terminal"));
    std::fs::remove_file(temp.path().join("123/status")).unwrap();
    assert!(approve(&env).is_err());
}

#[test]
fn agent_runner_rejects_untrusted_code_and_reports_exec_failure() {
    let temp = tempfile::tempdir().unwrap();
    let mut env = environment(temp.path());
    env.trust = rejected_trust;
    assert_eq!(
        run_agent(&env, 123, 456).unwrap_err(),
        "fixture trust failure"
    );
    env.trust = fixture_trust;
    assert_eq!(
        run_agent(&env, 123, 456).unwrap_err(),
        "fixture exec failure"
    );
}

#[test]
fn real_exec_failure_is_checked_in_an_isolated_process() {
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "linux_cli::tests::exec_failure_fixture",
            "--ignored",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
#[ignore = "Subprocess fixture, invoked by real_exec_failure_is_checked_in_an_isolated_process"]
fn exec_failure_fixture() {
    let temp = tempfile::tempdir().unwrap();
    let command = Command::new(temp.path().join("missing-agent"));
    assert_eq!(exec_agent(command).kind(), io::ErrorKind::NotFound);
}

fn no_invoker() -> Option<(u32, u32)> {
    None
}
fn fixture_invoker() -> Option<(u32, u32)> {
    Some((1000, 1000))
}
unsafe extern "C" fn fixture_home(
    uid: libc::uid_t,
    entry: *mut libc::passwd,
    _: *mut libc::c_char,
    _: usize,
    result: *mut *mut libc::passwd,
) -> libc::c_int {
    assert_eq!(uid, 1000);
    unsafe {
        (*entry).pw_dir = c"/fixture/home".as_ptr().cast_mut();
        *result = entry;
    }
    0
}
unsafe extern "C" fn missing_home(
    _: libc::uid_t,
    _: *mut libc::passwd,
    _: *mut libc::c_char,
    _: usize,
    result: *mut *mut libc::passwd,
) -> libc::c_int {
    unsafe {
        *result = std::ptr::null_mut();
    }
    0
}
unsafe extern "C" fn null_home(
    _: libc::uid_t,
    entry: *mut libc::passwd,
    _: *mut libc::c_char,
    _: usize,
    result: *mut *mut libc::passwd,
) -> libc::c_int {
    unsafe {
        (*entry).pw_dir = std::ptr::null_mut();
        *result = entry;
    }
    0
}
unsafe extern "C" fn failed_home(
    _: libc::uid_t,
    _: *mut libc::passwd,
    _: *mut libc::c_char,
    _: usize,
    _: *mut *mut libc::passwd,
) -> libc::c_int {
    libc::EIO
}

#[test]
fn home_lookup_uses_the_invoker_and_handles_nss_errors_and_missing_records() {
    let mut env = Environment::system();
    env.invoking_user = no_invoker;
    env.uid = user_uid;
    env.lookup = fixture_home;
    assert_eq!(real_home(&env).unwrap(), Path::new("/fixture/home"));
    env.invoking_user = fixture_invoker;
    env.uid = root_uid;
    assert_eq!(real_home(&env).unwrap(), Path::new("/fixture/home"));
    for lookup in [missing_home as UserLookup, null_home, failed_home] {
        env.lookup = lookup;
        assert!(real_home(&env).is_err());
    }
    env.invoking_user = no_invoker;
    env.uid = libc::getuid;
    env.lookup = libc::getpwuid_r;
    assert!(real_home(&env).unwrap().is_absolute());
}

#[test]
fn real_terminal_opener_handles_files_and_open_errors() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("tty");
    std::fs::write(&path, []).unwrap();
    let mut tty = open_terminal(&path).unwrap();
    tty.write_all(b"fixture").unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), b"fixture");
    assert!(open_terminal(&temp.path().join("missing")).is_err());
}

fn answering(answer: &[u8]) -> Environment {
    let mut env = Environment::system();
    let answer = answer.to_vec();
    env.open_terminal = Box::new(move |path| {
        assert_eq!(path, Path::new("/dev/tty"));
        Ok(Box::new(Terminal {
            input: std::io::Cursor::new(answer.clone()),
            ..Default::default()
        }))
    });
    env
}

#[test]
fn confirmation_and_list_selection_use_their_terminal_and_cancel_on_failure() {
    assert!(confirm_yes_no(
        &answering(b"yes\n"),
        "test",
        "allow",
        "deny"
    ));
    for answer in [b"no\n".as_slice(), b"\n", b"YES\n", b""] {
        assert!(!confirm_yes_no(&answering(answer), "test", "allow", "deny"));
    }
    let items = vec!["one".into(), "two".into()];
    assert_eq!(
        choose_from_list(&answering(b"2 1\n"), "test", &items),
        Some(vec!["two".into(), "one".into()])
    );
    assert_eq!(choose_from_list(&answering(b"\n"), "test", &items), None);
    let mut env = answering(b"yes\n");
    env.open_terminal = Box::new(|_| Err(io::Error::other("fixture terminal unavailable")));
    assert!(!confirm_yes_no(&env, "test", "allow", "deny"));
    assert_eq!(choose_from_list(&env, "test", &items), None);
}

#[derive(Default)]
struct Terminal {
    input: std::io::Cursor<Vec<u8>>,
    shown: Vec<u8>,
    fail_read: bool,
    fail_write: bool,
    fail_flush: bool,
}
impl Read for Terminal {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        if self.fail_read {
            return Err(std::io::Error::other("fixture read error"));
        }
        self.input.read(buffer)
    }
}
impl Write for Terminal {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        if self.fail_write {
            return Err(std::io::Error::other("fixture write error"));
        }
        self.shown.write(buffer)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        if self.fail_flush {
            return Err(std::io::Error::other("fixture flush error"));
        }
        Ok(())
    }
}

#[test]
fn terminal_response_uses_its_terminal_and_sanitizes_the_prompt() {
    let mut tty = Terminal {
        input: std::io::Cursor::new(b"  yes\t\nno\n".to_vec()),
        ..Default::default()
    };
    assert_eq!(
        terminal_response(&mut tty, "approve\x1b[2J: "),
        Some("yes".into())
    );
    assert_eq!(tty.shown, b"approve?[2J: ");
}

#[test]
fn terminal_response_rejects_eof_invalid_utf8_and_oversized_input() {
    for input in [Vec::new(), vec![0xff, b'\n'], vec![b'x'; 4097]] {
        let tty = Terminal {
            input: std::io::Cursor::new(input),
            ..Default::default()
        };
        assert_eq!(terminal_response(tty, "test"), None);
    }
    let tty = Terminal {
        input: std::io::Cursor::new(vec![b'x'; 4096]),
        ..Default::default()
    };
    assert_eq!(terminal_response(tty, "test").unwrap().len(), 4096);
}

#[test]
fn terminal_io_errors_cancel_the_response() {
    for failure in 0..3 {
        let tty = Terminal {
            input: std::io::Cursor::new(b"yes\n".to_vec()),
            fail_read: failure == 0,
            fail_write: failure == 1,
            fail_flush: failure == 2,
            ..Default::default()
        };
        assert_eq!(terminal_response(tty, "test"), None);
    }
}

#[test]
fn approval_target_requires_all_four_kernel_uids_to_match() {
    assert!(approval_target_owned_by(
        "Name:\tkv-mcp\nUid:\t1000 1000 1000 1000\nGid:\t1000\n",
        1000
    ));
    for row in [
        "0 1000 1000 1000",
        "1000 0 1000 1000",
        "1000 1000 0 1000",
        "1000 1000 1000 0",
    ] {
        assert!(!approval_target_owned_by(&format!("Uid:\t{row}\n"), 1000));
    }
    assert!(!approval_target_owned_by("Uid: 0 0 0 0\n", 0));
}

#[test]
fn approval_target_rejects_missing_duplicate_and_malformed_uid_fields() {
    for status in [
        "Name: kv-mcp\n",
        "Uid: 1000 1000 1000\n",
        "Uid: 1000 1000 1000 1000 1000\n",
        "Uid: 1000 invalid 1000 1000 1000\n",
        "Uid: 1000 1000 1000 4294967296\n",
        "Uid: -1 -1 -1 -1\n",
        "Uid: 1000 1000 1000 1000\nUid: 1000 1000 1000 1000\n",
    ] {
        assert!(!approval_target_owned_by(status, 1000), "{status:?}");
    }
}

#[test]
fn terminal_prompts_neutralize_control_sequences_and_preserve_readable_text() {
    assert_eq!(
        terminal_prompt("密钥\n\tAPI\x1b[2J\r\x07\x08\x00\x7f"),
        "密钥\n\tAPI?[2J?????"
    );
    assert_eq!(terminal_prompt("normal prompt 😀"), "normal prompt 😀");
}

#[test]
fn list_selection_preserves_order_and_deduplicates_items() {
    let items = vec!["one".into(), "two".into(), "three".into()];
    assert_eq!(
        selected_items("3 1 3\t2", &items),
        Some(vec!["three".into(), "one".into(), "two".into()])
    );
}

#[test]
fn canceled_or_invalid_list_selection_never_returns_a_partial_result() {
    let items = vec!["one".into(), "two".into()];
    for answer in [
        "",
        " \t ",
        "0",
        "3",
        "-1",
        "1 invalid",
        "1 3",
        "999999999999999999999999999999999",
    ] {
        assert_eq!(selected_items(answer, &items), None, "{answer:?}");
    }
    assert_eq!(
        choose_from_list(&Environment::system(), "test", &[]),
        Some(Vec::new())
    );
}
