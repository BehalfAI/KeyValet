//! Aligned, bounded storage for variable-sized Win32 output structures.

pub struct AlignedBuffer {
    words: Vec<usize>,
    len: usize,
}

impl AlignedBuffer {
    pub fn new(len: usize) -> Self {
        Self {
            words: vec![0; len.div_ceil(std::mem::size_of::<usize>())],
            len,
        }
    }

    pub fn as_mut_ptr(&mut self) -> *mut core::ffi::c_void {
        self.words.as_mut_ptr().cast()
    }

    pub fn bytes(&self, offset: usize, len: usize, initialized: usize) -> Option<&[u8]> {
        if initialized > self.len || offset.checked_add(len)? > initialized {
            return None;
        }
        // All backing words are initialized, including padding. Bounds are checked above.
        Some(unsafe {
            std::slice::from_raw_parts(self.words.as_ptr().cast::<u8>().add(offset), len)
        })
    }

    /// Read a C structure without constructing references into a variable-length byte buffer.
    ///
    /// # Safety
    /// The bytes at this offset must be a valid representation of `T`, as supplied by Win32.
    pub unsafe fn read_copy<T: Copy>(&self, offset: usize, initialized: usize) -> Option<T> {
        let bytes = self.bytes(offset, std::mem::size_of::<T>(), initialized)?;
        Some(unsafe { bytes.as_ptr().cast::<T>().read_unaligned() })
    }

    /// Convert a SID pointer returned inside this buffer to a bounded slice, without
    /// dereferencing the pointer. Win32 may put the SID after a fixed-size TOKEN_USER header.
    fn sid_at(&self, address: usize, initialized: usize) -> Option<&[u8]> {
        let base = self.words.as_ptr() as usize;
        let offset = address.checked_sub(base)?;
        let header = self.bytes(offset, 8, initialized)?;
        if header[0] != 1 || header[1] > 15 {
            return None;
        }
        self.bytes(offset, 8 + 4 * usize::from(header[1]), initialized)
    }
}

#[cfg(windows)]
pub fn token_user_sid(token: windows::Win32::Foundation::HANDLE) -> std::io::Result<Vec<u8>> {
    use windows::Win32::Security::{GetTokenInformation, TokenUser, TOKEN_USER};
    let invalid =
        || std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid TOKEN_USER buffer");
    let mut len = 0u32;
    unsafe {
        let _ = GetTokenInformation(token, TokenUser, None, 0, &mut len);
    }
    if len == 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut buffer = AlignedBuffer::new(len as usize);
    unsafe { GetTokenInformation(token, TokenUser, Some(buffer.as_mut_ptr()), len, &mut len) }
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    let user = unsafe { buffer.read_copy::<TOKEN_USER>(0, len as usize) }.ok_or_else(invalid)?;
    let sid = buffer
        .sid_at(user.User.Sid.0 as usize, len as usize)
        .ok_or_else(invalid)?;
    Ok(sid.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ffi_buffer_is_aligned_and_rejects_truncated_or_oversized_reads() {
        let mut buffer = AlignedBuffer::new(13);
        assert_eq!(
            buffer.as_mut_ptr() as usize % std::mem::align_of::<usize>(),
            0
        );
        unsafe {
            buffer.as_mut_ptr().cast::<u32>().write(42);
        }
        assert_eq!(unsafe { buffer.read_copy::<u32>(0, 13) }, Some(42));
        assert_eq!(unsafe { buffer.read_copy::<u32>(10, 13) }, None);
        assert_eq!(unsafe { buffer.read_copy::<u32>(0, 14) }, None);
        assert_eq!(buffer.bytes(usize::MAX, 2, 13), None);
        assert_eq!(buffer.bytes(0, 14, 14), None);
    }

    #[test]
    fn zero_and_non_word_lengths_remain_aligned_without_exposing_padding() {
        for len in 0..=3 * std::mem::size_of::<usize>() {
            let mut buffer = AlignedBuffer::new(len);
            assert_eq!(
                buffer.as_mut_ptr() as usize % std::mem::align_of::<usize>(),
                0
            );
            assert_eq!(buffer.bytes(0, len, len).unwrap(), vec![0; len]);
            assert_eq!(buffer.bytes(len, 1, len), None);
            assert_eq!(buffer.bytes(0, len + 1, len + 1), None);
        }
    }

    #[test]
    fn reads_only_use_the_reported_initialized_prefix() {
        let buffer = AlignedBuffer::new(32);
        for initialized in 0..=32 {
            assert_eq!(
                buffer.bytes(0, initialized, initialized).unwrap().len(),
                initialized
            );
            assert_eq!(buffer.bytes(initialized, 0, initialized), Some(&[][..]));
            assert_eq!(buffer.bytes(initialized, 1, initialized), None);
            assert_eq!(buffer.bytes(initialized + 1, 0, initialized), None);
        }
    }

    #[test]
    fn offsets_lengths_and_initialized_sizes_cannot_wrap() {
        let buffer = AlignedBuffer::new(16);
        for (offset, len, initialized) in [
            (usize::MAX, 0, 16),
            (usize::MAX, 1, 16),
            (1, usize::MAX, 16),
            (0, 1, usize::MAX),
            (0, 0, usize::MAX),
        ] {
            assert!(buffer.bytes(offset, len, initialized).is_none());
        }
    }

    #[test]
    fn copy_reads_handle_unaligned_structures_and_reject_partial_ones() {
        let mut buffer = AlignedBuffer::new(17);
        let value = 0x0102_0304_0506_0708u64;
        unsafe {
            buffer
                .as_mut_ptr()
                .cast::<u8>()
                .add(1)
                .cast::<u64>()
                .write_unaligned(value);
        }
        assert_eq!(unsafe { buffer.read_copy::<u64>(1, 9) }, Some(value));
        assert_eq!(unsafe { buffer.read_copy::<u64>(1, 8) }, None);
        assert_eq!(unsafe { buffer.read_copy::<u64>(usize::MAX, 17) }, None);
    }

    fn buffer_with_sid(sid: &[u8]) -> (AlignedBuffer, usize) {
        let offset = 2 * std::mem::size_of::<usize>();
        let mut buffer = AlignedBuffer::new(offset + sid.len() + 8);
        let target = unsafe { buffer.as_mut_ptr().cast::<u8>().add(offset) };
        // Only writes inside the allocated buffer; sid_at itself never dereferences address.
        unsafe {
            std::ptr::copy_nonoverlapping(sid.as_ptr(), target, sid.len());
        }
        (buffer, target as usize)
    }

    #[test]
    fn sid_subauthorities_are_bounded_and_trailing_buffer_bytes_are_excluded() {
        for count in [0u8, 1, 15] {
            let mut sid = vec![1, count, 0, 0, 0, 0, 0, 5];
            sid.extend((0..usize::from(count) * 4).map(|i| i as u8));
            let (buffer, address) = buffer_with_sid(&sid);
            assert_eq!(buffer.sid_at(address, buffer.len), Some(sid.as_slice()));
        }
    }

    #[test]
    fn sid_pointers_must_stay_inside_the_initialized_buffer() {
        let sid = [1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
        let (mut buffer, address) = buffer_with_sid(&sid);
        let base = buffer.as_mut_ptr() as usize;
        for invalid in [0, base - 1, base + buffer.len, usize::MAX] {
            assert!(buffer.sid_at(invalid, buffer.len).is_none());
        }
        let offset = address - base;
        assert!(buffer.sid_at(address, offset + sid.len() - 1).is_none());
        assert_eq!(buffer.sid_at(address, offset + sid.len()), Some(&sid[..]));
        assert!(buffer.sid_at(address, buffer.len + 1).is_none());
    }

    #[test]
    fn sid_headers_reject_unknown_revision_and_excess_subauthorities() {
        for (revision, count) in [(0, 1), (2, 1), (1, 16), (1, 255)] {
            let mut sid = vec![revision, count, 0, 0, 0, 0, 0, 5];
            sid.resize(8 + 4 * usize::from(count), 0);
            let (buffer, address) = buffer_with_sid(&sid);
            assert!(buffer.sid_at(address, buffer.len).is_none());
        }
    }

    #[test]
    fn truncated_sid_headers_and_declared_subauthorities_are_rejected() {
        let sid = [1, 2, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0, 19, 0, 0, 0];
        let (mut buffer, address) = buffer_with_sid(&sid);
        let offset = address - buffer.as_mut_ptr() as usize;
        for initialized in 0..sid.len() {
            assert!(buffer.sid_at(address, offset + initialized).is_none());
        }
        assert_eq!(buffer.sid_at(address, offset + sid.len()), Some(&sid[..]));
    }
}
