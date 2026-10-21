//! Helpers for FreeBSD's `ptrace(PT_IO)` request.

use std::io;

/// `PIOD_READ_D` from FreeBSD's `sys/ptrace.h`.
const PIOD_READ_D: libc::c_int = 1;

/// `struct ptrace_io_desc` from `sys/ptrace.h`, manually defined because the
/// `libc` crate does not expose it.
#[repr(C)]
struct PtraceIoDesc {
    piod_op: libc::c_int,
    piod_offs: *mut libc::c_void,
    piod_addr: *mut libc::c_void,
    piod_len: libc::size_t,
}

// ABI guards: `PT_IO` silently corrupts the request if this layout drifts
// from the kernel's `struct ptrace_io_desc`.
const _: () = assert!(std::mem::size_of::<PtraceIoDesc>() == 32);
const _: () = assert!(std::mem::offset_of!(PtraceIoDesc, piod_op) == 0);
const _: () = assert!(std::mem::offset_of!(PtraceIoDesc, piod_offs) == 8);
const _: () = assert!(std::mem::offset_of!(PtraceIoDesc, piod_addr) == 16);
const _: () = assert!(std::mem::offset_of!(PtraceIoDesc, piod_len) == 24);

/// Reads `buffer.len()` bytes at `address` from the traced process `pid`.
///
/// The caller must be attached to `pid`. Returns the number of bytes actually
/// read, which may be less on a partial transfer.
pub(super) fn read(pid: libc::pid_t, address: usize, buffer: &mut [u8]) -> io::Result<usize> {
    if buffer.is_empty() {
        return Ok(0);
    }

    let mut desc = PtraceIoDesc {
        piod_op: PIOD_READ_D,
        piod_offs: address as *mut libc::c_void,
        piod_addr: buffer.as_mut_ptr().cast(),
        piod_len: buffer.len(),
    };

    // SAFETY: `desc` describes a read of `buffer.len()` bytes into `buffer`,
    // and `pid` is a process we are attached to.
    let result = unsafe {
        libc::ptrace(
            libc::PT_IO,
            pid,
            &mut desc as *mut _ as *mut libc::c_char,
            0,
        )
    };

    if result == -1 {
        return Err(io::Error::last_os_error());
    }

    Ok(desc.piod_len)
}
