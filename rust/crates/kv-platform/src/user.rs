//! Dropping root privileges to the user who invoked `sudo`, for subprocesses that must live in
//! that user's GUI session (Touch ID prompts, osascript dialogs). Rust's own
//! `CommandExt::uid/gid` cannot be used for this: std calls `setgid` and then
//! `setgroups(0, NULL)` before `setuid`, and on macOS `setgroups(0, NULL)` leaves a group list of
//! `{0}` whose first entry IS the effective gid -- the child silently keeps egid 0 (wheel).

use std::io;

/// The user who invoked sudo (sudo sets SUDO_UID/SUDO_GID itself). None for uid 0 or gid 0:
/// there is no unprivileged identity to drop to.
pub fn invoking_user() -> Option<(u32, u32)> {
    let uid: u32 = std::env::var("SUDO_UID").ok()?.parse().ok()?;
    let gid: u32 = std::env::var("SUDO_GID").ok()?.parse().ok()?;
    if uid == 0 || gid == 0 {
        return None;
    }
    Some((uid, gid))
}

/// pre_exec hook leaving the child with exactly uid/gid and the single group gid. Use instead of
/// CommandExt::uid/gid: std calls setgroups(0, NULL) after setgid, which on macOS resets the
/// effective gid to 0 (wheel).
///
/// Runs between fork and exec, so it stays async-signal-safe: raw syscalls only, no allocation.
pub fn drop_to(uid: u32, gid: u32) -> impl FnMut() -> io::Result<()> + Send + Sync + 'static {
    move || {
        if uid == 0 || gid == 0 {
            return Err(io::Error::from_raw_os_error(libc::EPERM));
        }
        if unsafe { libc::setgroups(1, &gid) } != 0
            || unsafe { libc::setgid(gid) } != 0
            || unsafe { libc::setuid(uid) } != 0
        {
            return Err(io::Error::last_os_error());
        }
        let dropped = unsafe { libc::getuid() } == uid
            && unsafe { libc::geteuid() } == uid
            && unsafe { libc::getgid() } == gid
            && unsafe { libc::getegid() } == gid
            && unsafe { libc::setuid(0) } != 0;
        if dropped {
            Ok(())
        } else {
            Err(io::Error::from_raw_os_error(libc::EPERM))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::CommandExt;

    #[test]
    fn root_and_wheel_identities_are_refused_before_any_syscall() {
        // Both return before touching the process's real identity, so this is safe to run
        // unprivileged in-process.
        assert!(drop_to(0, 20)().is_err());
        assert!(drop_to(501, 0)().is_err());
    }

    #[test]
    #[ignore = "run the test binary as root via sudo"]
    fn dropped_child_has_exactly_the_invoking_identity() {
        assert_eq!(unsafe { libc::getuid() }, 0);
        let (uid, gid) = invoking_user().expect(
            "SUDO_UID/SUDO_GID must name a non-root, non-wheel user; run this test via `sudo` \
             from a normal account",
        );
        let mut cmd = std::process::Command::new("/bin/sh");
        cmd.args(["-c", "id -u; id -ur; id -g; id -gr"]);
        unsafe { cmd.pre_exec(drop_to(uid, gid)) };
        let out = cmd.output().unwrap();
        assert!(out.status.success());
        let expected = format!("{uid}\n{uid}\n{gid}\n{gid}");
        assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), expected);
    }
}
