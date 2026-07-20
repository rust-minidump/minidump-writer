use {super::super::Pid, super::super::serializers::serialize_io_error, std::io};

/// Handle to a process, which on FreeBSD is simply the process id.
pub type ProcessHandle = libc::pid_t;

/// Operation type for [`PtraceIoDesc`].
///
/// Corresponds to `PIOD_READ_D` in FreeBSD's `sys/ptrace.h`.
const PIOD_READ_D: libc::c_int = 1;

/// Description of a single ptrace I/O operation.
///
/// This is a Rust representation of FreeBSD's `struct ptrace_io_desc`,
/// used with `PT_IO` to perform bulk I/O on a traced process's address space.
#[repr(C)]
struct PtraceIoDesc {
    /// The operation to perform (`PIOD_READ_D`, `PIOD_WRITE_D`, etc.).
    piod_op: libc::c_int,
    /// Offset in the traced process's address space (source for reads).
    piod_offs: *mut libc::c_void,
    /// Buffer in the caller's address space (destination for reads).
    piod_addr: *mut libc::c_void,
    /// Number of bytes to transfer.
    piod_len: libc::size_t,
}

/// Error returned when reading from a traced process fails.
#[derive(Debug, thiserror::Error, serde::Serialize)]
#[error("Copy from process {child} failed (source {src}, offset: {offset}, length: {length})")]
pub struct CopyFromProcessError {
    pub child: Pid,
    pub src: usize,
    pub offset: usize,
    pub length: usize,
    #[source]
    #[serde(serialize_with = "serialize_io_error")]
    pub source: io::Error,
}

/// Reads memory from a traced process using FreeBSD's `ptrace(PT_IO, ...)`.
#[derive(Debug)]
pub struct ProcessReader {
    pub pid: Pid,
}

impl ProcessReader {
    /// Creates a new [`ProcessReader`] for the given process id.
    ///
    /// The process should already be attached via ptrace before calling [`read`](Self::read).
    #[inline]
    pub fn new(pid: ProcessHandle) -> Self {
        Self { pid }
    }

    /// Reads memory from the traced process into the provided buffer.
    ///
    /// Uses FreeBSD's `ptrace(PT_IO)` with `PIOD_READ_D` to read a contiguous
    /// range of the traced process's address space.
    ///
    /// Returns the number of bytes actually read, which may be less than
    /// `dst.len()` if the kernel performed a partial read.
    pub fn read(&self, src: usize, dst: &mut [u8]) -> Result<usize, CopyFromProcessError> {
        if dst.is_empty() {
            return Ok(0);
        }

        let mut desc = PtraceIoDesc {
            piod_op: PIOD_READ_D,
            piod_offs: src as *mut libc::c_void,
            piod_addr: dst.as_mut_ptr() as *mut libc::c_void,
            piod_len: dst.len(),
        };

        let res = unsafe {
            libc::ptrace(
                libc::PT_IO,
                self.pid,
                &mut desc as *mut _ as *mut libc::c_char,
                0,
            )
        };

        if res == -1 {
            let err = io::Error::last_os_error();
            return Err(CopyFromProcessError {
                child: self.pid,
                src,
                offset: 0,
                length: dst.len(),
                source: err,
            });
        }

        Ok(desc.piod_len)
    }
}
