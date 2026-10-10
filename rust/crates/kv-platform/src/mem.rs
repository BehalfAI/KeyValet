//! Locking secret-bearing pages so a crash or memory pressure can't swap them to disk.

use std::io;

/// Pin `len` bytes at `ptr` in physical memory. Callers pass vault-key material.
#[cfg(unix)]
pub fn lock(ptr: *const u8, len: usize) -> io::Result<()> {
    if unsafe { libc::mlock(ptr as *const libc::c_void, len) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(windows)]
pub fn lock(ptr: *const u8, len: usize) -> io::Result<()> {
    use windows::Win32::System::Memory::VirtualLock;
    unsafe { VirtualLock(ptr as _, len).map_err(|e| io::Error::from_raw_os_error(e.code().0)) }
}
