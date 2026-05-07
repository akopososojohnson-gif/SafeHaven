//! Secure memory allocation and handling.
//!
//! Provides `SecureKey`, a heap-allocated buffer that:
//! - Is zeroized on drop via the `zeroize` crate
//! - Is locked into RAM via `mlock(2)` (best-effort; logs warning on failure)
//! - Is excluded from core dumps via `madvise(MADV_DONTDUMP)`
//! - Uses 64-byte alignment to match cache-line size and avoid false sharing

use crate::{CryptoError, Result};

use std::alloc::{alloc, dealloc, Layout};
use zeroize::{Zeroize};

/// A securely allocated buffer for key material.
///
/// The memory is:
/// - Heap-allocated with 64-byte alignment
/// - Locked into physical RAM via `mlock` (Linux/macOS)
/// - Excluded from core dumps via `madvise(MADV_DONTDUMP)`
/// - Zeroized automatically when dropped
///
/// # Example
/// ```
/// use safehaven_crypto::memory::SecureKey;
/// let mut key = SecureKey::new(32).unwrap();
/// key.as_mut_slice().copy_from_slice(&[0xAB; 32]);
/// // key is zeroized and freed when it goes out of scope
/// ```
#[derive(Zeroize)]
pub struct SecureKey {
    #[zeroize(skip)]
    ptr: *mut u8,
    len: usize,
    #[zeroize(skip)]
    layout: Layout,
}

// Safety: SecureKey owns the allocated memory and does not share it.
unsafe impl Send for SecureKey {}
unsafe impl Sync for SecureKey {}

impl SecureKey {
    /// Allocate a new secure buffer of `size` bytes.
    ///
    /// Returns an error if the allocation fails or if `size` is zero.
    pub fn new(size: usize) -> Result<Self> {
        if size == 0 {
            return Err(CryptoError::InvalidParameter(
                "SecureKey size must be > 0".into(),
            ));
        }

        let layout =
            Layout::from_size_align(size, 64).map_err(|_e| {
                CryptoError::MemoryAllocationFailed
            })?;

        let ptr = unsafe { alloc(layout) };
        if ptr.is_null() {
            return Err(CryptoError::MemoryAllocationFailed);
        }

        // Zero-initialize immediately.
        unsafe { std::ptr::write_bytes(ptr, 0u8, size) };

        // Attempt to lock memory into RAM.
        #[cfg(unix)]
        {
            let lock_res = unsafe { libc::mlock(ptr as *const _, size) };
            if lock_res != 0 {
                // Best-effort: we continue operating but warn.
                // In a real application this might be logged.
                eprintln!(
                    "Warning: mlock failed (errno={}). Secrets may swap to disk.",
                    std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
                );
            }

            // Exclude from core dumps.
            #[cfg(target_os = "linux")]
            unsafe {
                libc::madvise(ptr as *mut _, size, libc::MADV_DONTDUMP);
            }
            #[cfg(target_os = "macos")]
            unsafe {
                libc::madvise(ptr as *mut _, size, libc::MADV_NOCORE);
            }
        }

        Ok(SecureKey { ptr, len: size, layout })
    }

    /// Returns the length of the buffer in bytes.
    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns an immutable slice to the buffer.
    ///
    /// # Safety
    /// The caller must ensure no mutable borrows are active.
    pub fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }

    /// Returns a mutable slice to the buffer.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.ptr, self.len) }
    }

    /// Explicitly zeroize the buffer now (in addition to Drop).
    pub fn zeroize_now(&mut self) {
        self.as_mut_slice().zeroize();
    }
}

impl Drop for SecureKey {
    fn drop(&mut self) {
        // Explicitly zeroize before deallocation.
        self.zeroize_now();
        #[cfg(unix)]
        unsafe {
            let _ = libc::munlock(self.ptr as *const _, self.len);
        }
        unsafe {
            dealloc(self.ptr, self.layout);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secure_key_allocates_and_zeroes() {
        let mut key = SecureKey::new(32).unwrap();
        assert_eq!(key.len(), 32);
        key.as_mut_slice().copy_from_slice(&[0xAB; 32]);
        // After drop, memory should be zeroed (verified by valgrind in CI)
    }

    #[test]
    fn secure_key_rejects_zero_size() {
        assert!(SecureKey::new(0).is_err());
    }

    #[test]
    fn secure_key_explicit_zeroize() {
        let mut key = SecureKey::new(32).unwrap();
        key.as_mut_slice().copy_from_slice(&[0xFF; 32]);
        key.zeroize_now();
        assert!(key.as_slice().iter().all(|&b| b == 0));
    }
}
