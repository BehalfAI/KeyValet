use super::*;
use std::os::unix::process::ExitStatusExt;
use std::sync::Mutex;

unsafe extern "C" fn root_uid() -> libc::uid_t {
    0
}
unsafe extern "C" fn user_uid() -> libc::uid_t {
    1000
}
fn trust_fixture(_: &Path) -> Option<String> {
    None
}
fn reject_fixture(_: &Path) -> Option<String> {
    Some("fixture trust failure".into())
}

unsafe extern "C" fn fixture_passwd(
    _: *const libc::c_char,
    entry: *mut libc::passwd,
    _: *mut libc::c_char,
    _: usize,
    result: *mut *mut libc::passwd,
) -> libc::c_int {
    unsafe {
        (*entry).pw_uid = libc::getuid().max(1000);
        (*entry).pw_gid = 1000;
        *result = entry;
    }
    0
}
unsafe extern "C" fn missing_passwd(
    _: *const libc::c_char,
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
unsafe extern "C" fn failed_passwd(
    _: *const libc::c_char,
    _: *mut libc::passwd,
    _: *mut libc::c_char,
    _: usize,
    _: *mut *mut libc::passwd,
) -> libc::c_int {
    libc::EIO
}
unsafe extern "C" fn root_passwd(
    name: *const libc::c_char,
    entry: *mut libc::passwd,
    buffer: *mut libc::c_char,
    size: usize,
    result: *mut *mut libc::passwd,
) -> libc::c_int {
    unsafe {
        fixture_passwd(name, entry, buffer, size, result);
        (*entry).pw_uid = 0;
    }
    0
}
unsafe extern "C" fn root_group_passwd(
    name: *const libc::c_char,
    entry: *mut libc::passwd,
    buffer: *mut libc::c_char,
    size: usize,
    result: *mut *mut libc::passwd,
) -> libc::c_int {
    unsafe {
        fixture_passwd(name, entry, buffer, size, result);
        (*entry).pw_gid = 0;
    }
    0
}
unsafe extern "C" fn failed_chown(_: libc::c_int, _: libc::uid_t, _: libc::gid_t) -> libc::c_int {
    unsafe {
        *libc::__errno_location() = libc::EPERM;
    }
    -1
}

fn host_fixture(directory: &Path) -> LinuxHost {
    let mut host = LinuxHost::system();
    host.vault_directory = directory.into();
    host.owner_file = directory.join("owner.uid");
    host.passwd_lookup = fixture_passwd;
    host.check_trust = trust_fixture;
    host.uid = root_uid;
    std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    if unsafe { libc::getuid() } == 0 {
        let path = std::ffi::CString::new(directory.as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::chown(path.as_ptr(), 1000, u32::MAX) }, 0);
    }
    host
}

#[test]
fn service_identity_handles_nss_success_missing_errors_and_root_records() {
    let mut host = LinuxHost::system();
    host.passwd_lookup = fixture_passwd;
    assert_eq!(
        host.service_identity().unwrap(),
        (unsafe { libc::getuid() }.max(1000), 1000)
    );
    for lookup in [
        missing_passwd as PasswdLookup,
        root_passwd,
        root_group_passwd,
    ] {
        host.passwd_lookup = lookup;
        assert_eq!(
            host.service_identity().unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
    }
    host.passwd_lookup = failed_passwd;
    assert_eq!(
        host.service_identity().unwrap_err().raw_os_error(),
        Some(libc::EIO)
    );
    host.passwd_lookup = libc::getpwnam_r;
    host.service_user = std::ffi::CString::new("root").unwrap();
    assert_eq!(
        host.service_identity().unwrap_err().kind(),
        io::ErrorKind::NotFound
    );
}

#[test]
fn owner_uid_loader_checks_trust_io_identity_and_user_policy() {
    let temp = tempfile::tempdir().unwrap();
    let mut host = host_fixture(temp.path());
    let owner = unsafe { libc::getuid() }.max(1000) + 1;
    std::fs::write(&host.owner_file, format!("{owner}\n")).unwrap();
    assert_eq!(host.owner_uid().unwrap(), owner);
    host.check_trust = reject_fixture;
    assert_eq!(host.owner_uid().unwrap_err(), "fixture trust failure");
    host.check_trust = trust_fixture;
    host.passwd_lookup = failed_passwd;
    assert!(host.owner_uid().is_err());
    host.passwd_lookup = fixture_passwd;
    std::fs::write(&host.owner_file, "0").unwrap();
    assert!(host.owner_uid().is_err());
    std::fs::remove_file(&host.owner_file).unwrap();
    assert!(host.owner_uid().is_err());
}

#[test]
fn vault_owner_validation_checks_identity_directory_permissions_and_parent_trust() {
    let temp = tempfile::tempdir().unwrap();
    let mut host = host_fixture(temp.path());
    assert_eq!(
        host.verify_vault_owner().unwrap(),
        unsafe { libc::getuid() }.max(1000)
    );
    host.check_trust = reject_fixture;
    assert_eq!(
        host.verify_vault_owner().unwrap_err(),
        "fixture trust failure"
    );
    host.check_trust = trust_fixture;
    host.passwd_lookup = failed_passwd;
    assert!(host.verify_vault_owner().is_err());
    host.passwd_lookup = fixture_passwd;
    std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(host.verify_vault_owner().is_err());
}

#[test]
fn root_management_uses_a_verified_vault_and_refuses_unprivileged_callers() {
    let temp = tempfile::tempdir().unwrap();
    let mut host = host_fixture(temp.path());
    for mode in [KeyMode::Tpm2, KeyMode::Software] {
        let p = LinuxMasterKeyProvider::for_root_cli_with(mode, &host).unwrap();
        assert_eq!(p.directory, temp.path());
        assert_eq!(p.mode, mode);
        assert!(p.approval.is_none());
    }
    host.uid = user_uid;
    assert!(LinuxMasterKeyProvider::for_root_cli_with(KeyMode::Software, &host).is_err());
    if unsafe { libc::getuid() } != 0 {
        assert!(LinuxMasterKeyProvider::for_root_cli(KeyMode::Tpm2).is_err());
    }
    host.uid = root_uid;
    host.passwd_lookup = failed_passwd;
    assert!(LinuxMasterKeyProvider::for_root_cli_with(KeyMode::Tpm2, &host).is_err());
}

#[test]
fn inherited_ownership_uses_a_descriptor_and_reports_parent_or_chown_failures() {
    let temp = tempfile::tempdir().unwrap();
    let mut host = LinuxHost::system();
    host.uid = root_uid;
    std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let file = temp.path().join("key");
    write_private(&file, b"unchanged", unsafe { libc::getuid() }).unwrap();
    host.inherit_private_owner(&file).unwrap();
    assert_eq!(std::fs::metadata(&file).unwrap().uid(), unsafe {
        libc::getuid()
    });
    host.chown = failed_chown;
    assert_eq!(
        host.inherit_private_owner(&file)
            .unwrap_err()
            .raw_os_error(),
        Some(libc::EPERM)
    );
    std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(host.inherit_private_owner(&file).is_err());
    assert!(host.inherit_private_owner(Path::new("/")).is_err());
    assert!(host
        .inherit_private_owner(&temp.path().join("missing/key"))
        .is_err());
    std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let link = temp.path().join("link");
    std::os::unix::fs::symlink(&file, &link).unwrap();
    assert!(host.inherit_private_owner(&link).is_err());
    host.uid = user_uid;
    host.inherit_private_owner(&link).unwrap();
    inherit_private_owner(&file).unwrap();
    assert_eq!(std::fs::read(file).unwrap(), b"unchanged");
}

#[test]
fn private_writes_report_ownership_failures_before_writing_key_material() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("key");
    let owner = unsafe { libc::getuid() };
    assert_eq!(
        write_private_with(&path, b"key", owner, 0, failed_chown)
            .unwrap_err()
            .raw_os_error(),
        Some(libc::EPERM)
    );
    assert!(std::fs::read(&path).unwrap().is_empty());
    std::fs::remove_file(&path).unwrap();
    write_private_with(&path, b"key", owner, 0, libc::fchown).unwrap();
    assert_eq!(std::fs::read(path).unwrap(), b"key");
}

#[test]
fn trusted_commands_reject_untrusted_paths_and_start_with_a_clean_environment() {
    let temp = tempfile::tempdir().unwrap();
    assert!(trusted_command(temp.path().join("missing").to_str().unwrap()).is_err());
    let command = trusted_command("/bin/true").unwrap();
    let env = command
        .get_envs()
        .map(|(key, value)| {
            (
                key.to_string_lossy().into_owned(),
                value.unwrap().to_string_lossy().into_owned(),
            )
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    assert_eq!(env.len(), 2);
    assert_eq!(env["PATH"], "/usr/bin:/bin");
    assert_eq!(env["LANG"], "C.UTF-8");
    assert!(wait_command(command, Duration::from_secs(5), None)
        .unwrap()
        .success());
}

fn panic_wait(
    _: Command,
    _: Duration,
    _: Option<&std::sync::atomic::AtomicBool>,
) -> io::Result<std::process::ExitStatus> {
    panic!("fixture runner panic")
}
fn failed_wait(
    _: Command,
    _: Duration,
    _: Option<&std::sync::atomic::AtomicBool>,
) -> io::Result<std::process::ExitStatus> {
    Err(io::Error::other("fixture wait failure"))
}

#[tokio::test]
async fn polkit_real_command_path_reports_approval_io_errors_and_worker_panics() {
    let mut p = subject();
    p.executable = "/bin/true".into();
    assert_eq!(
        p.authenticate("test", "cancel").await,
        AuthOutcome::Approved
    );
    assert!(p.confirm("test", "approve").await);
    p.wait = failed_wait;
    assert!(matches!(
        p.authenticate("test", "cancel").await,
        AuthOutcome::Error(_)
    ));
    p.wait = panic_wait;
    assert!(matches!(
        p.authenticate("test", "cancel").await,
        AuthOutcome::Error(_)
    ));
}

#[test]
fn failure_to_poll_a_child_still_attempts_kill_and_reap() {
    #[derive(Default)]
    struct FailedChild {
        killed: bool,
        reaped: bool,
    }
    impl ChildProcess for FailedChild {
        fn try_wait(&mut self) -> io::Result<Option<std::process::ExitStatus>> {
            Err(io::Error::from_raw_os_error(libc::ECHILD))
        }
        fn kill(&mut self) -> io::Result<()> {
            self.killed = true;
            Err(io::Error::other("already gone"))
        }
        fn wait(&mut self) -> io::Result<std::process::ExitStatus> {
            self.reaped = true;
            Err(io::Error::from_raw_os_error(libc::ECHILD))
        }
    }
    let mut child = FailedChild::default();
    assert_eq!(
        wait_child(&mut child, Duration::from_secs(5), None)
            .unwrap_err()
            .raw_os_error(),
        Some(libc::ECHILD)
    );
    assert!(child.killed && child.reaped);
}

fn tpm_echo(_: &str) -> std::result::Result<Command, String> {
    let mut c = Command::new("/bin/sh");
    c.args(["-c", "printf fixture"]);
    Ok(c)
}
fn tpm_failure(_: &str) -> std::result::Result<Command, String> {
    Ok(Command::new("/bin/false"))
}
fn tpm_sleep(_: &str) -> std::result::Result<Command, String> {
    let mut c = Command::new("/bin/sh");
    c.args(["-c", "exec /bin/sleep 30"]);
    Ok(c)
}
fn tpm_missing(_: &str) -> std::result::Result<Command, String> {
    Ok(Command::new("/keyvalet-fixture-missing-executable"))
}
fn tpm_untrusted(_: &str) -> std::result::Result<Command, String> {
    Err("fixture untrusted tool".into())
}

#[test]
fn tpm_detection_requires_version_two_and_a_resource_manager() {
    let temp = tempfile::tempdir().unwrap();
    let mut device = TpmDevice::system();
    device.version_file = temp.path().join("version");
    device.resource_manager = temp.path().join("device");
    assert!(!device.available());
    for version in ["1", "invalid", "2"] {
        std::fs::write(&device.version_file, version).unwrap();
        assert!(!device.available());
    }
    std::fs::write(&device.resource_manager, []).unwrap();
    assert!(device.available());
    std::fs::write(&device.version_file, "2\n").unwrap();
    assert!(device.available());
}

#[test]
fn tpm_process_runner_handles_output_nonzero_spawn_trust_timeout_and_revocation() {
    let temp = tempfile::tempdir().unwrap();
    let mut p = provider(temp.path());
    p.device.version_file = temp.path().join("version");
    p.device.resource_manager = temp.path().join("device");
    p.command = tpm_echo;
    assert!(p.tpm("fixture", &[], temp.path()).is_err());
    std::fs::write(&p.device.version_file, "2").unwrap();
    std::fs::write(&p.device.resource_manager, []).unwrap();
    assert_eq!(
        p.tpm("fixture", &[], temp.path()).unwrap().as_slice(),
        b"fixture"
    );
    for factory in [
        tpm_failure as fn(&str) -> std::result::Result<Command, String>,
        tpm_missing,
        tpm_untrusted,
    ] {
        p.command = factory;
        assert!(p.tpm("fixture", &[], temp.path()).is_err());
    }
    p.command = tpm_sleep;
    p.tpm_timeout = Duration::ZERO;
    assert!(p.tpm("fixture", &[], temp.path()).is_err());
    p.tpm_timeout = Duration::from_secs(5);
    let approval = subject();
    approval.cancel();
    p.approval = Some(approval);
    assert!(p.tpm("fixture", &[], temp.path()).is_err());
}

#[test]
fn service_provider_creation_and_metadata_selected_unlock_use_the_expected_backends() {
    let approval = subject();
    let p = LinuxMasterKeyProvider::for_service(approval);
    assert_eq!(p.mode, KeyMode::Tpm2);
    assert_eq!(p.directory, Path::new(VAULT_DIR));
    let temp = tempfile::tempdir().unwrap();
    let mut p = provider(temp.path());
    assert!(p.authorize("test").is_err() || unsafe { libc::getuid() } == 0);
    p.uid = root_uid;
    let software = p.create("test").unwrap();
    assert_eq!(
        *software.key,
        *p.unlock(&software.metadata, "test").unwrap()
    );
    p.mode = KeyMode::Tpm2;
    p.runner = Some(std::sync::Arc::new(FixtureTpm::default()));
    let hardware = p.create("test").unwrap();
    assert_eq!(
        *hardware.key,
        *p.unlock(&hardware.metadata, "test").unwrap()
    );
    assert_eq!(
        *software.key,
        *p.unlock(&software.metadata, "test").unwrap()
    );
    std::fs::remove_file(p.software_path(&software.metadata.decode().unwrap().0)).unwrap();
    assert!(p
        .unlock(&software.metadata, "test")
        .unwrap_err()
        .0
        .contains("software key is missing"));
    p.runner = None;
    p.device.version_file = temp.path().join("missing-tpm");
    assert!(p.run("fixture", &[], temp.path()).is_err());
}

#[test]
fn revocation_after_hardware_unlock_discards_the_returned_key() {
    struct Revoke {
        approval: Polkit,
        tpm: FixtureTpm,
    }
    impl TpmRunner for Revoke {
        fn run(&self, name: &str, args: &[&str], directory: &Path) -> Result<Zeroizing<Vec<u8>>> {
            let output = self.tpm.run(name, args, directory)?;
            if name == "ecdhzgen" {
                self.approval.cancel();
            }
            Ok(output)
        }
    }
    let temp = tempfile::tempdir().unwrap();
    let mut p = provider(temp.path());
    let metadata = p.create_tpm_with(&FixtureTpm::default()).unwrap().metadata;
    let mut approval = subject();
    approval.executable = "/bin/true".into();
    p.runner = Some(std::sync::Arc::new(Revoke {
        approval: approval.clone(),
        tpm: FixtureTpm::default(),
    }));
    p.approval = Some(approval);
    assert!(p
        .unlock(&metadata, "test")
        .unwrap_err()
        .0
        .contains("revoked"));
    assert_no_tpm_workspace(temp.path());
}

fn provider(dir: &Path) -> LinuxMasterKeyProvider {
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    LinuxMasterKeyProvider::new(
        dir.into(),
        unsafe { libc::getuid() },
        KeyMode::Software,
        None,
    )
}

fn subject() -> Polkit {
    Polkit::for_peer(crate::peer::PeerCredentials {
        uid: 1000,
        gid: 1000,
        pid: std::process::id(),
    })
    .unwrap()
}

fn point() -> Vec<u8> {
    let mut point = vec![5; 70];
    point[..4].copy_from_slice(&[0, 0x44, 0, 0x20]);
    point[4..36].copy_from_slice(&(0..32).collect::<Vec<_>>());
    point[36..38].copy_from_slice(&[0, 0x20]);
    point
}

fn public_blob() -> Vec<u8> {
    let mut public = vec![0; 90];
    public[..10].copy_from_slice(&[0, 88, 0, 0x23, 0, 0x0b, 0, 2, 4, 0x72]);
    public[10..24].copy_from_slice(&[0, 0, 0, 0x10, 0, 0x19, 0, 0x0b, 0, 3, 0, 0x10, 0, 0x20]);
    public[56..58].copy_from_slice(&[0, 0x20]);
    public
}

#[derive(Default)]
struct FixtureTpm {
    fail_at: Option<usize>,
    invalid_secret: bool,
    calls: Mutex<Vec<String>>,
}

impl TpmRunner for FixtureTpm {
    fn run(&self, name: &str, args: &[&str], directory: &Path) -> Result<Zeroizing<Vec<u8>>> {
        self.calls.lock().unwrap().push(name.into());
        private_path(directory, unsafe { libc::getuid() }, true).unwrap();
        if self.fail_at == Some(self.calls.lock().unwrap().len()) {
            return Err(error("fixture TPM failure"));
        }
        match name {
            "createprimary" => {}
            "create" => {
                assert!(args.contains(
                    &"fixedtpm|fixedparent|sensitivedataorigin|userwithauth|decrypt|noda"
                ));
                std::fs::write(directory.join("key.pub"), public_blob())?;
                std::fs::write(directory.join("key.priv"), [0, 1, 42])?;
            }
            "load" => {
                assert_eq!(std::fs::read(directory.join("key.pub"))?, public_blob());
                assert_eq!(std::fs::read(directory.join("key.priv"))?, [0, 1, 42]);
            }
            "ecdhkeygen" | "ecdhzgen" => {
                assert!(args.windows(2).any(|a| a == ["-o", "/dev/stdout"]));
                if name == "ecdhkeygen" {
                    std::fs::write(directory.join("peer.point"), point())?;
                } else {
                    assert_eq!(std::fs::read(directory.join("peer.point"))?, point());
                    for file in ["key.pub", "key.priv", "peer.point"] {
                        private_path(&directory.join(file), unsafe { libc::getuid() }, false)
                            .unwrap();
                    }
                }
                return Ok(Zeroizing::new(if self.invalid_secret {
                    vec![0; 70]
                } else {
                    point()
                }));
            }
            _ => panic!("unexpected TPM command: {name}"),
        }
        Ok(Zeroizing::new(Vec::new()))
    }
}

fn assert_no_tpm_workspace(directory: &Path) {
    assert!(std::fs::read_dir(directory).unwrap().all(|entry| !entry
        .unwrap()
        .file_name()
        .to_string_lossy()
        .starts_with(".tpm-")));
}

#[test]
fn owner_config_rejects_root_service_malformed_and_oversized_uids() {
    assert_eq!(parse_owner_uid(" 1000\n", 123).unwrap(), 1000);
    for raw in ["", "0", "123", "-1", "1000 1001", "4294967296", "uid=1000"] {
        assert!(parse_owner_uid(raw, 123).is_err(), "{raw:?}");
    }
    assert!(parse_owner_uid(&format!("{}1000", " ".repeat(33)), 123).is_err());
}

#[test]
fn private_paths_reject_public_permissions_wrong_owners_and_file_types() {
    let temp = tempfile::tempdir().unwrap();
    let p = provider(temp.path());
    let file = temp.path().join("key");
    write_private(&file, &[7; 32], p.owner).unwrap();
    assert!(private_path(temp.path(), p.owner, true).is_ok());
    assert!(private_path(&file, p.owner, false).is_ok());
    for mode in [0o604, 0o620, 0o601] {
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(mode)).unwrap();
        assert_eq!(
            private_path(&file, p.owner, false).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
    }
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(private_path(&file, p.owner.wrapping_add(1), false).is_err());
    assert!(private_path(&file, p.owner, true).is_err());
    assert!(private_path(temp.path(), p.owner, false).is_err());
    let link = temp.path().join("link");
    std::os::unix::fs::symlink(temp.path(), &link).unwrap();
    assert!(private_path(&link, p.owner, true).is_err());
    let socket = temp.path().join("socket");
    let _listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
    assert!(private_path(&socket, p.owner, false).is_err());
    assert_eq!(
        private_path(&temp.path().join("missing"), p.owner, false)
            .unwrap_err()
            .kind(),
        io::ErrorKind::NotFound
    );
}

#[test]
fn private_writes_are_exclusive_and_never_follow_symlinks() {
    let temp = tempfile::tempdir().unwrap();
    let p = provider(temp.path());
    let file = temp.path().join("key");
    write_private(&file, b"original", p.owner).unwrap();
    assert_eq!(std::fs::metadata(&file).unwrap().mode() & 0o777, 0o600);
    assert!(write_private(&file, b"replacement", p.owner).is_err());
    let link = temp.path().join("link");
    std::os::unix::fs::symlink(&file, &link).unwrap();
    assert!(write_private(&link, b"replacement", p.owner).is_err());
    assert_eq!(std::fs::read(&file).unwrap(), b"original");
}

#[test]
fn polkit_subjects_reject_root_and_missing_processes() {
    assert!(Polkit::for_peer(crate::peer::PeerCredentials {
        uid: 0,
        gid: 0,
        pid: std::process::id(),
    })
    .is_err());
    assert!(Polkit::for_peer(crate::peer::PeerCredentials {
        uid: 1000,
        gid: 1000,
        pid: u32::MAX,
    })
    .is_err());
    assert_eq!(subject().peer_identity(), Some((1000, std::process::id())));
}

#[test]
fn polkit_binds_approval_to_the_action_uid_pid_and_process_start_time() {
    let p = subject();
    p.check_with(
        "dev.keyvalet.use",
        "fixture reason",
        |action, process, message, active| {
            assert_eq!(action, "dev.keyvalet.use");
            assert_eq!(
                process,
                format!("{},{},1000", std::process::id(), p.start_time)
            );
            assert_eq!(message, "fixture reason");
            assert!(active.load(std::sync::atomic::Ordering::SeqCst));
            Ok(std::process::ExitStatus::from_raw(0))
        },
    )
    .unwrap();
}

#[test]
fn revoked_or_reused_polkit_subjects_never_run_an_approval_command() {
    for revoked in [false, true] {
        let mut p = subject();
        if revoked {
            p.cancel();
        } else {
            p.start_time = p.start_time.wrapping_add(1);
        }
        assert!(p
            .check_with("dev.keyvalet.unlock", "test", |_, _, _, _| {
                panic!("invalid subjects must be rejected before running polkit")
            })
            .is_err());
    }
}

#[test]
fn polkit_rejects_denial_runner_errors_and_revocation_during_approval() {
    let p = subject();
    assert!(p
        .check_with("dev.keyvalet.use", "test", |_, _, _, _| {
            Ok(std::process::ExitStatus::from_raw(1 << 8))
        })
        .is_err());
    assert_eq!(
        p.check_with("dev.keyvalet.use", "test", |_, _, _, _| {
            Err("fixture runner error".into())
        })
        .unwrap_err(),
        "fixture runner error"
    );
    let clone = p.clone();
    assert!(p
        .check_with("dev.keyvalet.use", "test", |_, _, _, _| {
            clone.cancel();
            Ok(std::process::ExitStatus::from_raw(0))
        })
        .is_err());
}

#[tokio::test]
async fn canceled_polkit_authentication_and_confirmation_fail_closed() {
    let p = subject();
    p.cancel();
    assert!(matches!(
        p.authenticate("test", "cancel").await,
        AuthOutcome::Error(_)
    ));
    assert!(!p.confirm("test", "approve").await);
}

#[test]
fn canceled_approval_cannot_create_or_unlock_a_software_key() {
    let temp = tempfile::tempdir().unwrap();
    let mut p = provider(temp.path());
    let created = p.create_software().unwrap();
    let approval = subject();
    approval.cancel();
    p.approval = Some(approval);
    assert!(p.create("test").is_err());
    assert!(p.unlock(&created.metadata, "test").is_err());
    assert_eq!(std::fs::read_dir(temp.path()).unwrap().count(), 1);
}

#[test]
fn command_wait_preserves_success_and_nonzero_exit_status() {
    for executable in ["/bin/true", "/bin/false"] {
        let status = wait_command(Command::new(executable), Duration::from_secs(5), None).unwrap();
        assert_eq!(status.success(), executable == "/bin/true");
    }
    let temp = tempfile::tempdir().unwrap();
    assert_eq!(
        wait_command(
            Command::new(temp.path().join("missing")),
            Duration::from_secs(5),
            None
        )
        .unwrap_err()
        .kind(),
        io::ErrorKind::NotFound
    );
}

#[test]
fn command_timeout_kills_and_reaps_the_child() {
    let mut child = Command::new("/bin/sleep").arg("30").spawn().unwrap();
    let err = wait_child(&mut child, Duration::ZERO, None).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    assert!(!child.try_wait().unwrap().unwrap().success());
}

#[test]
fn an_already_revoked_session_kills_and_reaps_the_child() {
    let active = std::sync::atomic::AtomicBool::new(false);
    let mut child = Command::new("/bin/sleep").arg("30").spawn().unwrap();
    assert_eq!(
        wait_child(&mut child, Duration::from_secs(5), Some(&active))
            .unwrap_err()
            .kind(),
        io::ErrorKind::Interrupted
    );
    assert!(!child.try_wait().unwrap().unwrap().success());
}

#[test]
fn revoking_a_session_terminates_its_pending_child() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let active = std::sync::Arc::new(AtomicBool::new(true));
    let mut child = Command::new("/bin/sleep").arg("30").spawn().unwrap();
    let flag = active.clone();
    let revoke = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(40));
        flag.store(false, Ordering::SeqCst);
    });
    let start = Instant::now();
    let err = wait_child(&mut child, Duration::from_secs(5), Some(&active)).unwrap_err();
    revoke.join().unwrap();
    assert_eq!(err.kind(), io::ErrorKind::Interrupted);
    assert!(start.elapsed() < Duration::from_secs(5));
    assert!(!child.try_wait().unwrap().unwrap().success());
}

#[test]
fn software_descriptor_contains_no_key_and_refuses_replacement_or_symlink() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let p = provider(temp.path());
    let created = p.create_software().unwrap();
    assert_eq!(*created.key, *p.unlock_software(&created.metadata).unwrap());
    assert!(!created
        .metadata
        .key_blob
        .contains(&STANDARD.encode(created.key.as_ref())));
    let (digest, _) = created.metadata.decode().unwrap();
    let path = p.software_path(&digest);
    std::fs::write(&path, [9u8; 32]).unwrap();
    assert!(p.unlock_software(&created.metadata).is_err());
    std::fs::remove_file(&path).unwrap();
    std::os::unix::fs::symlink("/etc/passwd", &path).unwrap();
    assert!(p.unlock_software(&created.metadata).is_err());
}

#[test]
fn corrupted_hardware_metadata_never_uses_the_software_key() {
    let temp = tempfile::tempdir().unwrap();
    let p = provider(temp.path());
    let mut metadata = p.create_software().unwrap().metadata;
    metadata.version = 3;
    assert!(p.unlock(&metadata, "test").is_err());
}

#[test]
fn software_unlock_reports_missing_truncated_and_insecure_keys() {
    let temp = tempfile::tempdir().unwrap();
    let p = provider(temp.path());
    let created = p.create_software().unwrap();
    let path = p.software_path(&created.metadata.decode().unwrap().0);
    for bytes in [Vec::new(), vec![9; 31], vec![9; 33]] {
        std::fs::write(&path, bytes).unwrap();
        assert!(p.unlock_software(&created.metadata).is_err());
    }
    std::fs::write(&path, created.key.as_ref()).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(p.unlock_software(&created.metadata).is_err());
    std::fs::remove_file(&path).unwrap();
    let error = p.unlock_software(&created.metadata).unwrap_err();
    assert!(error.0.contains("recover-vault --software"));
}

#[test]
fn software_creation_and_unlock_require_a_private_vault_directory() {
    let temp = tempfile::tempdir().unwrap();
    let p = provider(temp.path());
    let created = p.create_software().unwrap();
    std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o750)).unwrap();
    assert!(p.create_software().is_err());
    assert!(p.unlock_software(&created.metadata).is_err());
    assert!(p.workspace().is_err());
    assert!(p.cleanup_software_keys(&created.metadata).is_err());
}

#[test]
fn software_key_cleanup_preserves_the_current_key_and_unrelated_files() {
    let temp = tempfile::tempdir().unwrap();
    let p = provider(temp.path());
    let old = p.create_software().unwrap();
    let current = p.create_software().unwrap();
    let old_path = p.software_path(&old.metadata.decode().unwrap().0);
    let current_path = p.software_path(&current.metadata.decode().unwrap().0);
    let unrelated = [
        "vault.enc",
        "software-short.key",
        "software-bad.key",
        "other.key",
    ];
    for name in unrelated {
        std::fs::write(temp.path().join(name), b"preserve").unwrap();
    }
    let invalid_hex = temp.path().join(format!("software-{}.key", "z".repeat(64)));
    std::fs::write(&invalid_hex, b"preserve").unwrap();
    p.cleanup_software_keys(&current.metadata).unwrap();
    assert!(!old_path.exists());
    assert!(current_path.exists());
    assert_eq!(*current.key, *p.unlock_software(&current.metadata).unwrap());
    for path in unrelated
        .map(|name| temp.path().join(name))
        .into_iter()
        .chain([invalid_hex])
    {
        assert_eq!(std::fs::read(path).unwrap(), b"preserve");
    }
}

#[test]
fn switching_to_tpm_removes_old_software_keys_without_touching_the_vault() {
    let temp = tempfile::tempdir().unwrap();
    let p = provider(temp.path());
    p.create_software().unwrap();
    p.create_software().unwrap();
    let vault = temp.path().join("vault.enc");
    std::fs::write(&vault, b"encrypted vault").unwrap();
    let hardware = p.create_tpm_with(&FixtureTpm::default()).unwrap();
    p.cleanup_software_keys(&hardware.metadata).unwrap();
    assert_eq!(std::fs::read_dir(temp.path()).unwrap().count(), 1);
    assert_eq!(std::fs::read(vault).unwrap(), b"encrypted vault");
}

#[test]
fn software_key_cleanup_refuses_symlinks_and_insecure_files() {
    for symlink in [true, false] {
        let temp = tempfile::tempdir().unwrap();
        let p = provider(temp.path());
        let current = p.create_software().unwrap();
        let foreign = p.software_path(&[7; 32]);
        let target = temp.path().join("unrelated");
        std::fs::write(&target, b"preserve").unwrap();
        if symlink {
            std::os::unix::fs::symlink(&target, &foreign).unwrap();
        } else {
            std::fs::write(&foreign, b"insecure").unwrap();
            std::fs::set_permissions(&foreign, std::fs::Permissions::from_mode(0o644)).unwrap();
        }
        assert!(p.cleanup_software_keys(&current.metadata).is_err());
        assert!(std::fs::symlink_metadata(&foreign).is_ok());
        assert_eq!(std::fs::read(&target).unwrap(), b"preserve");
        assert_eq!(*current.key, *p.unlock_software(&current.metadata).unwrap());
    }
}

#[test]
fn invalid_cleanup_metadata_does_not_delete_any_keys() {
    let temp = tempfile::tempdir().unwrap();
    let p = provider(temp.path());
    let current = p.create_software().unwrap();
    let mut invalid = current.metadata.clone();
    invalid.version = 99;
    assert!(p.cleanup_software_keys(&invalid).is_err());
    assert_eq!(*current.key, *p.unlock_software(&current.metadata).unwrap());
}

#[test]
fn a_foreign_platform_vault_is_rejected_before_approval_or_hardware_access() {
    let temp = tempfile::tempdir().unwrap();
    let p = provider(temp.path());
    let mut peer = vec![0; 65];
    peer[0] = 4;
    let metadata = EnclaveMetadata {
        version: 1,
        key_blob: STANDARD.encode([7; 32]),
        peer_public_key: STANDARD.encode(peer),
    };
    assert!(p
        .unlock(&metadata, "test")
        .unwrap_err()
        .0
        .contains("another platform"));
    assert_eq!(std::fs::read_dir(temp.path()).unwrap().count(), 0);
}

#[test]
fn tpm_metadata_round_trips_through_an_isolated_command_runner() {
    let temp = tempfile::tempdir().unwrap();
    let p = provider(temp.path());
    let tpm = FixtureTpm::default();
    let created = p.create_tpm_with(&tpm).unwrap();
    assert_eq!(created.metadata.provider().unwrap(), ProviderId::Tpm2);
    assert_eq!(
        *created.key,
        *p.unlock_tpm_with(&created.metadata, &tpm).unwrap()
    );
    assert!(!created
        .metadata
        .key_blob
        .contains(&STANDARD.encode(created.key.as_ref())));
    assert_eq!(tpm.calls.lock().unwrap().len(), 7);
    assert_no_tpm_workspace(temp.path());
}

#[test]
fn every_tpm_creation_failure_removes_its_workspace_without_software_fallback() {
    for fail_at in 1..=4 {
        let temp = tempfile::tempdir().unwrap();
        let p = provider(temp.path());
        let software = p.create_software().unwrap();
        let tpm = FixtureTpm {
            fail_at: Some(fail_at),
            ..Default::default()
        };
        assert!(p.create_tpm_with(&tpm).is_err());
        assert_eq!(tpm.calls.lock().unwrap().len(), fail_at);
        assert_no_tpm_workspace(temp.path());
        assert_eq!(std::fs::read_dir(temp.path()).unwrap().count(), 1);
        assert_eq!(
            *software.key,
            *p.unlock_software(&software.metadata).unwrap()
        );
    }
}

#[test]
fn every_tpm_unlock_failure_removes_its_workspace_without_software_fallback() {
    for fail_at in 1..=3 {
        let temp = tempfile::tempdir().unwrap();
        let p = provider(temp.path());
        let software = p.create_software().unwrap();
        let hardware = p.create_tpm_with(&FixtureTpm::default()).unwrap();
        let tpm = FixtureTpm {
            fail_at: Some(fail_at),
            ..Default::default()
        };
        assert!(p.unlock_tpm_with(&hardware.metadata, &tpm).is_err());
        assert_eq!(tpm.calls.lock().unwrap().len(), fail_at);
        assert_no_tpm_workspace(temp.path());
        assert_eq!(
            *software.key,
            *p.unlock_software(&software.metadata).unwrap()
        );
    }
}

fn fail_public_write(path: &Path, bytes: &[u8], owner: u32) -> io::Result<()> {
    if path.file_name().unwrap() == "key.pub" {
        return Err(io::Error::other("fixture public write failure"));
    }
    write_private(path, bytes, owner)
}

fn fail_private_write(path: &Path, bytes: &[u8], owner: u32) -> io::Result<()> {
    if path.file_name().unwrap() == "key.priv" {
        return Err(io::Error::other("fixture private write failure"));
    }
    write_private(path, bytes, owner)
}

#[test]
fn tpm_unlock_write_failures_remove_the_workspace_before_any_command_runs() {
    let temp = tempfile::tempdir().unwrap();
    let mut p = provider(temp.path());
    let metadata = p.create_tpm_with(&FixtureTpm::default()).unwrap().metadata;
    for writer in [
        fail_public_write as fn(&Path, &[u8], u32) -> io::Result<()>,
        fail_private_write,
    ] {
        p.write = writer;
        let tpm = FixtureTpm::default();
        assert!(p
            .unlock_tpm_with(&metadata, &tpm)
            .unwrap_err()
            .0
            .contains("write failure"));
        assert!(tpm.calls.lock().unwrap().is_empty());
        assert_no_tpm_workspace(temp.path());
        assert_eq!(std::fs::read_dir(temp.path()).unwrap().count(), 0);
    }
}

#[test]
fn invalid_tpm_secrets_fail_creation_and_unlock_and_leave_no_workspace() {
    let temp = tempfile::tempdir().unwrap();
    let p = provider(temp.path());
    let hardware = p.create_tpm_with(&FixtureTpm::default()).unwrap();
    let tpm = FixtureTpm {
        invalid_secret: true,
        ..Default::default()
    };
    assert!(p.create_tpm_with(&tpm).is_err());
    assert!(p.unlock_tpm_with(&hardware.metadata, &tpm).is_err());
    assert_no_tpm_workspace(temp.path());
}

#[test]
fn malformed_tpm_metadata_is_rejected_before_running_any_command() {
    let temp = tempfile::tempdir().unwrap();
    let p = provider(temp.path());
    let mut metadata = p.create_tpm_with(&FixtureTpm::default()).unwrap().metadata;
    metadata.key_blob = "invalid base64".into();
    let tpm = FixtureTpm::default();
    assert!(p.unlock_tpm_with(&metadata, &tpm).is_err());
    assert!(tpm.calls.lock().unwrap().is_empty());
    assert_no_tpm_workspace(temp.path());
}

#[test]
fn tpm_key_derivation_matches_the_domain_separated_hkdf_vector() {
    let expected = [
        0x82, 0xca, 0x15, 0x47, 0x98, 0x9a, 0xed, 0x76, 0x72, 0xd6, 0x64, 0xa3, 0x3e, 0x7a, 0x1f,
        0xc9, 0x25, 0x5b, 0x7a, 0xbb, 0xe2, 0x5d, 0x5f, 0x40, 0x10, 0xe7, 0xa4, 0x01, 0x93, 0x18,
        0x7d, 0x42,
    ];
    assert_eq!(*derived_secret(&point()).unwrap(), expected);
    let mut changed = point();
    changed[4] ^= 1;
    assert_ne!(*derived_secret(&changed).unwrap(), expected);
}

#[test]
fn tpm_key_derivation_rejects_truncated_oversized_and_wrong_point_headers() {
    for len in [0, 3, 36, 69, 71] {
        assert!(derived_secret(&vec![0; len]).is_err());
    }
    for offset in [0, 1, 2, 3, 36, 37] {
        let mut invalid = point();
        invalid[offset] ^= 1;
        assert!(derived_secret(&invalid).is_err(), "offset {offset}");
    }
}

#[test]
#[ignore = "Requires TPM 2.0, tpm2-tools and root/tss access: cargo test -p kv-platform tpm_round_trip -- --ignored"]
fn tpm_round_trip_and_hardware_failure_do_not_use_a_software_key() {
    let temp = tempfile::tempdir().unwrap();
    let p = provider(temp.path());
    let software = p.create_software().unwrap();
    let created = p.create_tpm().unwrap();
    assert_eq!(*created.key, *p.unlock_tpm(&created.metadata).unwrap());
    assert_ne!(*created.key, *software.key);
    let (blob, _) = created.metadata.decode().unwrap();
    let mut info: TpmMetadata = serde_json::from_slice(&blob).unwrap();
    let mut private = STANDARD.decode(&info.private_blob).unwrap();
    private[20] ^= 1;
    info.private_blob = STANDARD.encode(private);
    let mut broken = created.metadata.clone();
    broken.key_blob = STANDARD.encode(serde_json::to_vec(&info).unwrap());
    assert!(p.unlock_tpm(&broken).is_err());
    assert!(std::fs::read_dir(temp.path()).unwrap().all(|entry| !entry
        .unwrap()
        .file_name()
        .to_string_lossy()
        .starts_with(".tpm-")));
}
