//! FreeBSD process inspection.
//!
//! All process state required to write a minidump is gathered through the
//! [`ProcessInspector`] trait: down-stream modules (thread info, maps,
//! module readers, minidump streams) never invoke `ptrace`/`sysctl`
//! directly.

use std::{
    cell::Cell,
    ffi::{CStr, OsString},
    fmt, io,
    mem::MaybeUninit,
    os::unix::ffi::OsStringExt,
    time::{Duration, Instant},
};

use crate::freebsd::vm_permissions::VmPermissions;

/// A single entry of a process's virtual memory map.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmMapEntry {
    /// The start address of the mapping (inclusive).
    pub start_address: u64,
    /// The end address of the mapping (exclusive).
    pub end_address: u64,
    /// The offset of the mapping within the mapped file, if any.
    pub offset: u64,
    /// The permissions of the mapping.
    pub permissions: VmPermissions,
    /// The pathname of the mapped file, if the mapping is file-backed.
    pub file_path: Option<OsString>,
}

/// Converts a kernel-provided fixed-size path buffer into an `OsString`.
fn c_path_to_option(buf: &[u8]) -> Option<OsString> {
    let len = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    if len == 0 {
        return None;
    }
    Some(OsString::from_vec(buf[..len].to_vec()))
}

pub mod process_reader;
pub mod regs;

pub use process_reader::{CopyFromProcessError, ProcessReader};
pub use regs::{FpRegs, GenRegs};

/// Timeout for the process to report its stop after `PT_ATTACH`.
const ATTACH_TIMEOUT: Duration = Duration::from_secs(5);

/// Interval between `waitpid` polls while waiting for a ptrace stop.
const ATTACH_POLL_INTERVAL: Duration = Duration::from_millis(1);

/// `KVME_TYPE_GUARD` from FreeBSD's `sys/user.h` (not yet exposed by the
/// `libc` crate): an `mmap(MAP_GUARD)` mapping that faults on any access.
const KVME_TYPE_GUARD: libc::c_int = 9;

// `kve_version` is not validated here: `kinfo_getvmmap` (libutil) assembles
// the entries and normalizes them, the version check is only needed by raw
// `KERN_PROC_VMMAP` sysctl consumers.

pub(crate) type Result<T> = std::result::Result<T, Error>;

/// Errors that can occur while inspecting a process.
#[derive(Debug, thiserror::Error, serde::Serialize)]
pub enum Error {
    #[error("failed to attach to process {pid}")]
    Attach {
        pid: libc::pid_t,
        #[source]
        #[serde(serialize_with = "crate::serializers::serialize_io_error")]
        source: io::Error,
    },
    #[error("failed to detach from process {pid}")]
    Detach {
        pid: libc::pid_t,
        #[source]
        #[serde(serialize_with = "crate::serializers::serialize_io_error")]
        source: io::Error,
    },
    #[error("failed to stop process {pid}")]
    StopProcess {
        pid: libc::pid_t,
        #[source]
        #[serde(serialize_with = "crate::serializers::serialize_io_error")]
        source: io::Error,
    },
    #[error("failed to continue process {pid}")]
    ContinueProcess {
        pid: libc::pid_t,
        #[source]
        #[serde(serialize_with = "crate::serializers::serialize_io_error")]
        source: io::Error,
    },
    #[error("failed to suspend thread {tid}")]
    SuspendThread {
        tid: libc::pid_t,
        #[source]
        #[serde(serialize_with = "crate::serializers::serialize_io_error")]
        source: io::Error,
    },
    #[error("failed to resume thread {tid}")]
    ResumeThread {
        tid: libc::pid_t,
        #[source]
        #[serde(serialize_with = "crate::serializers::serialize_io_error")]
        source: io::Error,
    },
    #[error("waitpid on process {pid} failed")]
    WaitPid {
        pid: libc::pid_t,
        #[source]
        #[serde(serialize_with = "crate::serializers::serialize_io_error")]
        source: io::Error,
    },
    #[error("got an unexpected waitpid status ({status:#x}) for process {pid}")]
    UnexpectedWaitStatus {
        pid: libc::pid_t,
        status: libc::c_int,
    },
    #[error("failed to get general-purpose registers for thread {tid}")]
    GetGenRegs {
        tid: libc::pid_t,
        #[source]
        #[serde(serialize_with = "crate::serializers::serialize_io_error")]
        source: io::Error,
    },
    #[error("failed to get floating-point registers for thread {tid}")]
    GetFpRegs {
        tid: libc::pid_t,
        #[source]
        #[serde(serialize_with = "crate::serializers::serialize_io_error")]
        source: io::Error,
    },
    #[error("failed to enumerate threads of process {pid}")]
    GetThreadList {
        pid: libc::pid_t,
        #[source]
        #[serde(serialize_with = "crate::serializers::serialize_io_error")]
        source: io::Error,
    },
    #[error("failed to read the thread names of process {pid}")]
    GetThreadNames {
        pid: libc::pid_t,
        #[source]
        #[serde(serialize_with = "crate::serializers::serialize_io_error")]
        source: io::Error,
    },
    #[error("failed to read the auxv of process {pid}")]
    GetAuxv {
        pid: libc::pid_t,
        #[source]
        #[serde(serialize_with = "crate::serializers::serialize_io_error")]
        source: io::Error,
    },
    #[error("failed to read the memory map of process {pid}")]
    GetVmMap {
        pid: libc::pid_t,
        #[source]
        #[serde(serialize_with = "crate::serializers::serialize_io_error")]
        source: io::Error,
    },
}

/// Provides access to the state of a process running on the local machine.
///
/// Down-stream consumers (thread info, maps/module readers, the minidump
/// streams) always go through this trait instead of issuing `ptrace` or
/// `sysctl` requests themselves.
///
/// All methods that inspect process state (memory, registers, threads)
/// require the process to have been attached via [`attach`](Self::attach)
/// first.
pub trait ProcessInspector: fmt::Debug {
    fn process_reader<'a>(&'a self) -> ProcessReader<'a>;

    fn pid(&self) -> Result<libc::pid_t>;

    /// Attaches to the process with `PT_ATTACH` and waits for it to stop.
    /// Attaching also stops the process.
    fn attach(&self) -> Result<()>;

    /// Detaches from the process with `PT_DETACH`, resuming it.
    fn detach(&self) -> Result<()>;

    /// Reads memory at `address` into `buffer`, returning the number of bytes
    /// read (which may be less than `buffer.len()` on a partial read).
    fn read_at(
        &self,
        address: usize,
        buffer: &mut [u8],
    ) -> std::result::Result<usize, CopyFromProcessError>;

    /// Stops the whole process without establishing a trace.
    fn stop_process(&self) -> Result<()>;

    /// Resumes a process stopped with [`stop_process`](Self::stop_process).
    fn continue_process(&self) -> Result<()>;

    /// Suspends a single thread (light-weight process).
    fn suspend_thread(&self, tid: libc::pid_t) -> Result<()>;

    /// Resumes a thread suspended with
    /// [`suspend_thread`](Self::suspend_thread).
    fn resume_thread(&self, tid: libc::pid_t) -> Result<()>;

    /// Returns the ids of all threads (light-weight processes).
    fn get_thread_list(&self) -> Result<Vec<libc::pid_t>>;

    /// Returns the names of all threads in one go (single `sysctl`).
    ///
    /// The name is the per-thread name set via `pthread_set_name_np`,
    /// falling back to the process command name.
    fn get_thread_names(&self) -> Result<Vec<(libc::pid_t, String)>>;

    fn get_gen_regs(&self, tid: libc::pid_t) -> Result<GenRegs>;

    fn get_fp_regs(&self, tid: libc::pid_t) -> Result<FpRegs>;

    /// Returns the raw auxiliary vector (`Elf_AuxInfo` pairs), or an empty
    /// vector if the process has no auxv entry.
    fn get_auxv(&self) -> Result<Vec<u8>>;

    /// Returns the virtual memory map of the process, with guard
    /// (`mmap(MAP_GUARD)`) and dead (being-torn-down) mappings filtered out.
    fn get_vm_map(&self) -> Result<Vec<VmMapEntry>>;
}

/// Creates a [`ProcessInspector`] for a process running on the local machine.
pub fn local(pid: libc::pid_t) -> Box<dyn ProcessInspector> {
    Box::new(LocalInspector::new(pid))
}

/// Local, `ptrace`-backed [`ProcessInspector`].
///
/// Every FreeBSD ptrace request — including `PT_IO` — requires an
/// established trace relationship, so [`attach`](ProcessInspector::attach)
/// and [`detach`](ProcessInspector::detach) are part of the inspection
/// lifecycle.
#[derive(Debug)]
struct LocalInspector {
    pid: libc::pid_t,
    attached: Cell<bool>,
}

impl LocalInspector {
    fn new(pid: libc::pid_t) -> Self {
        Self {
            pid,
            attached: Cell::new(false),
        }
    }

    /// Issues a ptrace request that takes no address argument.
    fn ptrace(request: libc::c_int, id: libc::pid_t) -> io::Result<()> {
        // SAFETY: `PT_ATTACH`/`PT_DETACH` interpret the `data` argument as a
        // signal number, 0 here, meaning "no signal to deliver"; for
        // `PT_SUSPEND`/`PT_RESUME` the kernel ignores it.
        if unsafe { libc::ptrace(request, id, std::ptr::null_mut(), 0) } == -1 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    /// Returns the process state (`ki_stat`) of `pid`, or `None` if the
    /// process no longer exists (the sysctl succeeds with an empty table
    /// for exited-but-not-reaped and gone pids).
    fn process_state(pid: libc::pid_t) -> io::Result<Option<libc::c_char>> {
        let mib = [libc::CTL_KERN, libc::KERN_PROC, libc::KERN_PROC_PID, pid];
        let mut kproc: libc::kinfo_proc = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of::<libc::kinfo_proc>();
        // SAFETY: the out-buffer and size describe one valid `kinfo_proc`
        // slot.
        if unsafe {
            libc::sysctl(
                mib.as_ptr(),
                mib.len() as libc::c_uint,
                (&mut kproc as *mut _) as *mut libc::c_void,
                &mut len,
                std::ptr::null(),
                0,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        if len < std::mem::size_of::<libc::kinfo_proc>() {
            return Ok(None);
        }
        Ok(Some(kproc.ki_stat))
    }

    /// Waits until `pid` reports a stop, polling with `WNOHANG` until
    /// [`ATTACH_TIMEOUT`] expires.
    fn wait_for_stop(pid: libc::pid_t) -> Result<()> {
        let deadline = Instant::now() + ATTACH_TIMEOUT;
        let mut status: libc::c_int = 0;
        loop {
            // SAFETY: `status` is a valid out-pointer for waitpid and
            // `WNOHANG` makes the call non-blocking.
            let ret = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
            if ret == -1 {
                let err = io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                // Waiting on a process that is not our child fails with
                // ECHILD. Poll the process state instead so we don't race
                // a still-running process.
                if err.raw_os_error() == Some(libc::ECHILD) {
                    loop {
                        match Self::process_state(pid) {
                            Ok(Some(s)) if s == libc::SSTOP => return Ok(()),
                            // Exited or gone: nothing to wait for.
                            Ok(None | Some(libc::SZOMB)) => return Ok(()),
                            Ok(_) => (),
                            Err(_) => return Ok(()), // best effort
                        }
                        if Instant::now() > deadline {
                            return Ok(()); // best effort: proceed anyway
                        }
                        std::thread::sleep(ATTACH_POLL_INTERVAL);
                    }
                }
                return Err(Error::WaitPid { pid, source: err });
            }
            if ret == pid {
                if libc::WIFSTOPPED(status) {
                    return Ok(());
                }
                // The process exited or was signaled instead of stopping.
                return Err(Error::UnexpectedWaitStatus { pid, status });
            }

            if Instant::now() > deadline {
                return Err(Error::WaitPid {
                    pid,
                    source: io::Error::new(
                        io::ErrorKind::TimedOut,
                        "timed out waiting for ptrace stop",
                    ),
                });
            }
            std::thread::sleep(ATTACH_POLL_INTERVAL);
        }
    }
}

impl ProcessInspector for LocalInspector {
    fn process_reader<'a>(&'a self) -> ProcessReader<'a> {
        ProcessReader::new(self)
    }

    fn pid(&self) -> Result<libc::pid_t> {
        Ok(self.pid)
    }

    fn attach(&self) -> Result<()> {
        if self.attached.get() {
            return Ok(());
        }

        Self::ptrace(libc::PT_ATTACH, self.pid).map_err(|source| Error::Attach {
            pid: self.pid,
            source,
        })?;

        if let Err(err) = Self::wait_for_stop(self.pid) {
            // Best-effort cleanup so we don't leave the process traced.
            let _ = Self::ptrace(libc::PT_DETACH, self.pid);
            return Err(err);
        }

        self.attached.set(true);
        Ok(())
    }

    fn detach(&self) -> Result<()> {
        if !self.attached.get() {
            return Ok(());
        }

        match Self::ptrace(libc::PT_DETACH, self.pid) {
            Ok(()) => {
                self.attached.set(false);
                Ok(())
            }
            Err(source) => {
                // ESRCH means the process is gone, nothing to detach from.
                if source.raw_os_error() == Some(libc::ESRCH) {
                    self.attached.set(false);
                    Ok(())
                } else {
                    Err(Error::Detach {
                        pid: self.pid,
                        source,
                    })
                }
            }
        }
    }

    fn read_at(
        &self,
        address: usize,
        buffer: &mut [u8],
    ) -> std::result::Result<usize, CopyFromProcessError> {
        crate::freebsd::ptrace_io::read(self.pid, address, buffer).map_err(|source| {
            CopyFromProcessError {
                child: self.pid,
                src: address,
                length: buffer.len(),
                source,
            }
        })
    }

    fn stop_process(&self) -> Result<()> {
        // SAFETY: kill only sends the signal, the return value is checked.
        if unsafe { libc::kill(self.pid, libc::SIGSTOP) } == -1 {
            return Err(Error::StopProcess {
                pid: self.pid,
                source: io::Error::last_os_error(),
            });
        }

        Self::wait_for_stop(self.pid)
    }

    fn continue_process(&self) -> Result<()> {
        // SAFETY: kill only sends the signal, the return value is checked.
        if unsafe { libc::kill(self.pid, libc::SIGCONT) } == -1 {
            return Err(Error::ContinueProcess {
                pid: self.pid,
                source: io::Error::last_os_error(),
            });
        }
        Ok(())
    }

    fn suspend_thread(&self, tid: libc::pid_t) -> Result<()> {
        Self::ptrace(libc::PT_SUSPEND, tid).map_err(|source| Error::SuspendThread { tid, source })
    }

    fn resume_thread(&self, tid: libc::pid_t) -> Result<()> {
        Self::ptrace(libc::PT_RESUME, tid).map_err(|source| Error::ResumeThread { tid, source })
    }

    fn get_thread_list(&self) -> Result<Vec<libc::pid_t>> {
        // SAFETY: PT_GETNUMLWPS takes no address argument and returns the
        // number of LWPs of the traced process, or -1 on error.
        let num_lwps =
            unsafe { libc::ptrace(libc::PT_GETNUMLWPS, self.pid, std::ptr::null_mut(), 0) };
        if num_lwps == -1 {
            return Err(Error::GetThreadList {
                pid: self.pid,
                source: io::Error::last_os_error(),
            });
        }

        let count = num_lwps as usize;
        let mut tids = vec![0 as libc::pid_t; count];

        // SAFETY: PT_GETLWPLIST fills the provided buffer with thread ids of
        // the traced process, writing at most `count` entries. We provide a
        // valid buffer of exactly that capacity.
        let filled = unsafe {
            libc::ptrace(
                libc::PT_GETLWPLIST,
                self.pid,
                tids.as_mut_ptr().cast(),
                count as libc::c_int,
            )
        };
        if filled == -1 {
            return Err(Error::GetThreadList {
                pid: self.pid,
                source: io::Error::last_os_error(),
            });
        }

        tids.truncate(filled as usize);
        Ok(tids)
    }

    fn get_gen_regs(&self, tid: libc::pid_t) -> Result<GenRegs> {
        let mut regs = MaybeUninit::<libc::reg>::uninit();
        // SAFETY: PT_GETREGS fills the provided buffer with the thread's
        // registers on success, fully initializing it.
        let ret = unsafe { libc::ptrace(libc::PT_GETREGS, tid, regs.as_mut_ptr().cast(), 0) };
        if ret == -1 {
            return Err(Error::GetGenRegs {
                tid,
                source: io::Error::last_os_error(),
            });
        }
        // SAFETY: ptrace returned success, so the kernel has fully
        // initialized the register struct.
        Ok(GenRegs(unsafe { regs.assume_init() }))
    }

    fn get_fp_regs(&self, tid: libc::pid_t) -> Result<FpRegs> {
        let mut fpregs = MaybeUninit::<libc::fpreg>::uninit();
        // SAFETY: PT_GETFPREGS fills the provided buffer with the thread's
        // floating-point registers on success, fully initializing it.
        let ret = unsafe { libc::ptrace(libc::PT_GETFPREGS, tid, fpregs.as_mut_ptr().cast(), 0) };
        if ret == -1 {
            return Err(Error::GetFpRegs {
                tid,
                source: io::Error::last_os_error(),
            });
        }
        // SAFETY: ptrace returned success, so the kernel has fully
        // initialized the register struct.
        Ok(FpRegs(unsafe { fpregs.assume_init() }))
    }

    fn get_auxv(&self) -> Result<Vec<u8>> {
        let mib = [
            libc::CTL_KERN,
            libc::KERN_PROC,
            libc::KERN_PROC_AUXV,
            self.pid,
        ];

        let mut len = 0usize;
        // SAFETY: sysctl is a well-defined kernel interface. We pass a valid
        // mib, a null output buffer with a size pointer to query the required
        // buffer size, and no new value for a read-only query.
        if unsafe {
            libc::sysctl(
                mib.as_ptr(),
                mib.len() as libc::c_uint,
                std::ptr::null_mut(),
                &mut len,
                std::ptr::null(),
                0,
            )
        } != 0
        {
            return Err(Error::GetAuxv {
                pid: self.pid,
                source: io::Error::last_os_error(),
            });
        }

        if len == 0 {
            // The process has no auxv entry.
            return Ok(Vec::new());
        }

        let mut buffer = vec![0u8; len];
        // SAFETY: the buffer has the size reported by the kernel and is
        // valid for writes of `len` bytes.
        if unsafe {
            libc::sysctl(
                mib.as_ptr(),
                mib.len() as libc::c_uint,
                buffer.as_mut_ptr().cast(),
                &mut len,
                std::ptr::null(),
                0,
            )
        } != 0
        {
            return Err(Error::GetAuxv {
                pid: self.pid,
                source: io::Error::last_os_error(),
            });
        }

        buffer.truncate(len);
        Ok(buffer)
    }

    fn get_thread_names(&self) -> Result<Vec<(libc::pid_t, String)>> {
        let mib = [
            libc::CTL_KERN,
            libc::KERN_PROC,
            libc::KERN_PROC_PID | libc::KERN_PROC_INC_THREAD,
            self.pid,
        ];

        let mut len = 0usize;
        // SAFETY: sysctl size-query with a valid mib, null output and a size
        // pointer.
        let ret = unsafe {
            libc::sysctl(
                mib.as_ptr(),
                mib.len() as libc::c_uint,
                std::ptr::null_mut(),
                &mut len,
                std::ptr::null(),
                0,
            )
        };
        if ret != 0 || len == 0 {
            return Err(Error::GetThreadNames {
                pid: self.pid,
                source: io::Error::last_os_error(),
            });
        }

        let mut buffer = vec![0u8; len];

        // SAFETY: the buffer has the kernel-reported size; the kernel fills
        // it with one `kinfo_proc` per thread on success and updates `len`
        // to the number of bytes written.
        let ret = unsafe {
            libc::sysctl(
                mib.as_ptr(),
                mib.len() as libc::c_uint,
                buffer.as_mut_ptr().cast(),
                &mut len,
                std::ptr::null(),
                0,
            )
        };
        if ret != 0 {
            return Err(Error::GetThreadNames {
                pid: self.pid,
                source: io::Error::last_os_error(),
            });
        }

        // Use the length reported by the second call: the thread list may
        // have shrunk between the two sysctls.
        let entry_size = std::mem::size_of::<libc::kinfo_proc>();
        let count = len / entry_size;

        let mut names = Vec::with_capacity(count);
        for i in 0..count {
            // SAFETY: `read_unaligned` sidesteps the (u8-buffer) alignment
            // requirement; `i` is in bounds per the kernel-reported count.
            let kp = unsafe {
                buffer
                    .as_ptr()
                    .add(i * entry_size)
                    .cast::<libc::kinfo_proc>()
                    .read_unaligned()
            };
            // SAFETY: the kernel guarantees that `ki_tdname` and `ki_comm`
            // contain null-terminated strings.
            let name = unsafe { CStr::from_ptr(kp.ki_tdname.as_ptr()) };
            let name = if name.is_empty() {
                // SAFETY: same invariant as `ki_tdname`.
                unsafe { CStr::from_ptr(kp.ki_comm.as_ptr()) }
            } else {
                name
            };
            if !name.is_empty() {
                names.push((kp.ki_tid, name.to_string_lossy().into_owned()));
            }
        }

        Ok(names)
    }

    fn get_vm_map(&self) -> Result<Vec<VmMapEntry>> {
        let mut count: libc::c_int = 0;

        // SAFETY: kinfo_getvmmap is a well-defined libutil function that
        // returns a malloc-allocated array of `kinfo_vmentry` entries on
        // success or NULL on failure. The slice is copied into a Vec before
        // the allocation is freed.
        let entries = unsafe {
            let ptr = libc::kinfo_getvmmap(self.pid, &mut count);
            if ptr.is_null() {
                // libutil doesn't guarantee errno is set on every failure
                // path, so don't report a possibly stale errno.
                return Err(Error::GetVmMap {
                    pid: self.pid,
                    source: io::Error::other("kinfo_getvmmap failed"),
                });
            }
            let slice = std::slice::from_raw_parts(ptr, count as usize);
            let entries = slice.to_vec();
            libc::free(ptr.cast());
            entries
        };

        Ok(vm_entries_to_map(entries))
    }
}

/// Detaches on drop so a discarded inspector can never leave the target
/// process traced and stopped.
impl Drop for LocalInspector {
    fn drop(&mut self) {
        if self.attached.get()
            && let Err(e) = Self::ptrace(libc::PT_DETACH, self.pid)
        {
            // ESRCH: the process is gone, nothing to detach from.
            if e.raw_os_error() != Some(libc::ESRCH) {
                log::error!("failed to detach from process {}: {e}", self.pid);
            }
        }
    }
}

/// Converts `kinfo_vmentry` records into neutral [`VmMapEntry`]s, dropping
/// guard and dead mappings.
fn vm_entries_to_map(entries: Vec<libc::kinfo_vmentry>) -> Vec<VmMapEntry> {
    entries
        .into_iter()
        .filter(|entry| {
            // Guard mappings (`mmap(MAP_GUARD)`) fault on any access and
            // dead entries describe mappings being torn down: neither is
            // real memory, so they never surface as mappings.
            entry.kve_type != KVME_TYPE_GUARD && entry.kve_type != libc::KVME_TYPE_DEAD
        })
        .map(|entry| {
            let mut permissions = VmPermissions::empty();
            if entry.kve_protection & libc::KVME_PROT_READ != 0 {
                permissions |= VmPermissions::READ;
            }
            if entry.kve_protection & libc::KVME_PROT_WRITE != 0 {
                permissions |= VmPermissions::WRITE;
            }
            if entry.kve_protection & libc::KVME_PROT_EXEC != 0 {
                permissions |= VmPermissions::EXECUTE;
            }
            if entry.kve_flags & libc::KVME_FLAG_COW != 0 {
                permissions |= VmPermissions::PRIVATE;
            }

            VmMapEntry {
                start_address: entry.kve_start,
                end_address: entry.kve_end,
                offset: entry.kve_offset,
                permissions,
                file_path: {
                    // libc declares kve_path as a nested [[c_char; 32]; 32]
                    // to work around array trait-impl limits, flatten it
                    // back into a byte slice.
                    let path = entry.kve_path.as_flattened();
                    // SAFETY: `c_char` and `u8` have the same layout.
                    let path = unsafe {
                        std::slice::from_raw_parts(path.as_ptr().cast::<u8>(), path.len())
                    };
                    c_path_to_option(path)
                },
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_inspector_reports_pid() {
        let inspector = local(std::process::id() as libc::pid_t);
        assert_eq!(inspector.pid().unwrap(), std::process::id() as libc::pid_t);
    }
}

#[cfg(test)]
mod vm_map_tests {
    use super::*;

    fn entry(
        start: u64,
        end: u64,
        kve_type: libc::c_int,
        protection: libc::c_int,
    ) -> libc::kinfo_vmentry {
        // SAFETY (test-only): `kinfo_vmentry` is a plain repr(C) struct of
        // integers and byte arrays; zero-initialization is a valid state.
        let mut e: libc::kinfo_vmentry = unsafe { std::mem::zeroed() };
        e.kve_start = start;
        e.kve_end = end;
        e.kve_type = kve_type;
        e.kve_protection = protection;
        e
    }

    #[test]
    fn guard_mappings_are_dropped() {
        // Realistic pthread stack layout:
        // 4K guard | 1M guard (stack pool) | RW stack | RW anonymous
        let entries = vec![
            entry(0x1000, 0x2000, KVME_TYPE_GUARD, 0),
            entry(0x2000, 0x100_2000, KVME_TYPE_GUARD, 0),
            entry(
                0x100_2000,
                0x102_2000,
                libc::KVME_TYPE_SWAP,
                libc::KVME_PROT_READ | libc::KVME_PROT_WRITE,
            ),
            entry(
                0x102_2000,
                0x103_2000,
                libc::KVME_TYPE_DEFAULT,
                libc::KVME_PROT_READ,
            ),
        ];

        let map = vm_entries_to_map(entries);
        assert_eq!(map.len(), 2, "guard entries must be filtered out");

        let stack = &map[0];
        assert!(stack.permissions.contains(VmPermissions::READ));
        assert!(stack.permissions.contains(VmPermissions::WRITE));
        assert!(stack.file_path.is_none());

        // No mapping covers the guard region anymore.
        assert!(
            map.iter()
                .all(|m| !(m.start_address <= 0x1800 && 0x1800 < m.end_address))
        );
    }

    #[test]
    fn cow_flag_maps_to_private() {
        let mut e = entry(
            0x1000,
            0x2000,
            libc::KVME_TYPE_SWAP,
            libc::KVME_PROT_READ | libc::KVME_PROT_WRITE,
        );
        e.kve_flags = libc::KVME_FLAG_COW;
        let map = vm_entries_to_map(vec![e]);
        assert!(map[0].permissions.contains(VmPermissions::PRIVATE));
    }
}
