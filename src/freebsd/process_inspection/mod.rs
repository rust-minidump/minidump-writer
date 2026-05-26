use {
    super::{
        Pid,
        auxv::AuxvError,
        module_reader::{ModuleReaderError, ReadModuleMemory},
        serializers::*,
    },
    core::mem,
    module_reader::MappedModuleMemoryReader,
    process_reader::ProcessReader,
    regs::*,
    std::{
        ffi::{CString, OsString},
        fs::{self, File},
        io::{self, Read},
        os::unix::ffi::OsStringExt,
        path::{Path, PathBuf},
        time::{Duration, Instant},
    },
};

pub mod process_reader;
pub(super) mod regs;

pub(super) mod module_reader;

#[derive(Debug)]
pub struct ProcessInspector {
    pid: libc::pid_t,
    process_reader: ProcessReader,
}

impl ProcessInspector {
    pub fn local(pid: libc::pid_t) -> Self {
        Self {
            pid,
            process_reader: ProcessReader::new(pid),
        }
    }

    pub fn process_reader(&self) -> &ProcessReader {
        &self.process_reader
    }

    pub fn attach_process(&self, timeout: Duration) -> io::Result<()> {
        ptrace_process(libc::PT_ATTACH, self.pid)?;

        const POLL_INTERVAL: Duration = Duration::from_millis(1);
        let end = Instant::now() + timeout;
        let mut status: libc::c_int = 0;
        loop {
            let ret = unsafe { libc::waitpid(self.pid, &mut status, libc::WNOHANG) };
            if ret == -1 {
                let err = io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                let _ = self.detach_process();
                return Err(err);
            }
            if libc::WIFSTOPPED(status) {
                return Ok(());
            }

            std::thread::sleep(POLL_INTERVAL);
            if Instant::now() > end {
                let _ = self.detach_process();
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "timeout waiting for ptrace attach stop",
                ));
            }
        }
    }

    pub fn detach_process(&self) -> io::Result<()> {
        ptrace_process(libc::PT_DETACH, self.pid).or_else(|e| {
            if e.raw_os_error() == Some(libc::ESRCH) {
                Ok(())
            } else {
                Err(e)
            }
        })
    }

    pub fn stop_process(&self, timeout: Duration) -> Result<(), ProcessStopError> {
        if unsafe { libc::kill(self.pid, libc::SIGSTOP) } == -1 {
            return Err(ProcessStopError::Stop(io::Error::last_os_error()));
        }

        const POLL_INTERVAL: Duration = Duration::from_millis(1);
        let end = Instant::now() + timeout;

        loop {
            let mut status: libc::c_int = 0;
            let ret = unsafe { libc::waitpid(self.pid, &mut status, libc::WNOHANG) };

            if ret == -1 {
                let err = io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::ECHILD) {
                    return Ok(());
                }
                return Err(ProcessStopError::WaitPidFailed(err));
            }

            if ret > 0 && libc::WIFSTOPPED(status) {
                return Ok(());
            }

            std::thread::sleep(POLL_INTERVAL);
            if Instant::now() > end {
                return Err(ProcessStopError::Timeout);
            }
        }
    }

    pub fn continue_process(&self) -> io::Result<()> {
        if unsafe { libc::kill(self.pid, libc::SIGCONT) } == -1 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    pub fn suspend_thread(&self, tid: libc::pid_t) -> Result<(), SuspendResumeThreadError> {
        #[cfg(target_arch = "x86_64")]
        {
            if let Ok(regs) = self.get_gen_regs(tid)
                && regs.r_rsp == 0
            {
                return Err(SuspendResumeThreadError::InvalidStackPointer(tid));
            }
        }

        Ok(())
    }

    pub fn resume_thread(&self, _tid: libc::pid_t) -> Result<(), SuspendResumeThreadError> {
        Ok(())
    }

    pub fn read_memory_mapped_module(
        &self,
        path: impl AsRef<Path>,
        offset: u64,
    ) -> Result<MappedModuleMemoryReader, ModuleReaderError> {
        MappedModuleMemoryReader::new(path.as_ref(), offset)
    }

    pub fn stat_file(&self, path: impl Into<PathBuf>) -> io::Result<libc::stat> {
        let path = path.into();
        let c_path = CString::new(path.into_os_string().into_vec())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains nul byte"))?;

        let mut output = unsafe { mem::zeroed::<libc::stat>() };
        let rv = unsafe { libc::stat(c_path.as_ptr(), &mut output) };
        if rv == -1 {
            return Err(io::Error::last_os_error());
        }
        Ok(output)
    }

    pub fn read_file(&self, path: impl AsRef<Path>) -> io::Result<FileReader> {
        File::open(path).map(FileReader)
    }

    pub fn read_dir(&self, path: impl AsRef<Path>) -> io::Result<DirReader> {
        fs::read_dir(path).map(DirReader)
    }

    pub fn read_link(&self, path: impl AsRef<Path>) -> io::Result<PathBuf> {
        fs::read_link(path)
    }

    pub fn path_exists(&self, path: impl AsRef<Path>) -> bool {
        path.as_ref().exists()
    }

    pub fn get_gen_regs(&self, tid: libc::pid_t) -> io::Result<GenRegs> {
        unsafe { ptrace_getregs::<GenRegs>(libc::PT_GETREGS, tid) }
    }

    pub fn get_fp_regs(&self, tid: libc::pid_t) -> io::Result<FpRegs> {
        unsafe { ptrace_getregs::<FpRegs>(libc::PT_GETFPREGS, tid) }
    }

    pub fn get_thread_list(&self) -> io::Result<Vec<Pid>> {
        // SAFETY: ptrace operates on the target pid which has been validated.
        // PT_GETNUMLWPS returns the number of LWPs or -1 on error, which we check.
        let num_lwps = unsafe {
            libc::ptrace(
                libc::PT_GETNUMLWPS,
                self.pid,
                std::ptr::null_mut::<libc::c_char>(),
                0,
            )
        };
        if num_lwps == -1 {
            return Err(io::Error::last_os_error());
        }
        if num_lwps == 0 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Thread enumeration failed for process {}", self.pid),
            ));
        }

        let count = num_lwps as usize;
        let mut tids = vec![0i32; count];

        // SAFETY: ptrace operates on the target pid. PT_GETLWPLIST fills the
        // provided buffer with thread IDs. We provide a valid buffer of correct size.
        let res = unsafe {
            libc::ptrace(
                libc::PT_GETLWPLIST,
                self.pid,
                tids.as_mut_ptr() as *mut libc::c_char,
                count as libc::c_int,
            )
        };
        if res == -1 {
            return Err(io::Error::last_os_error());
        }

        tids.truncate(res as usize);
        Ok(tids)
    }

    pub fn get_thread_name(&self, tid: Pid) -> Option<String> {
        let mib = [
            libc::CTL_KERN,
            libc::KERN_PROC,
            libc::KERN_PROC_PID | libc::KERN_PROC_INC_THREAD,
            self.pid,
        ];

        let mut len: usize = 0;
        // SAFETY: sysctl is a well-defined kernel interface. We pass a valid mib,
        // null output with a size pointer to query the required buffer size, and
        // null new/len for a read-only query. Returns 0 on success.
        let res = unsafe {
            libc::sysctl(
                mib.as_ptr(),
                mib.len() as libc::c_uint,
                std::ptr::null_mut(),
                &mut len,
                std::ptr::null(),
                0,
            )
        };
        if res != 0 || len == 0 {
            return None;
        }

        let mut buffer = vec![0u8; len];

        // SAFETY: sysctl is a well-defined kernel interface. We provide valid
        // pointers for mib, output buffer, and size. The kernel fills the buffer
        // with kinfo_proc entries (one per thread) on success.
        let res = unsafe {
            libc::sysctl(
                mib.as_ptr(),
                mib.len() as libc::c_uint,
                buffer.as_mut_ptr() as *mut libc::c_void,
                &mut len,
                std::ptr::null(),
                0,
            )
        };
        if res != 0 || len == 0 {
            return None;
        }

        let count = len / std::mem::size_of::<libc::kinfo_proc>();

        let kprocs = buffer.as_ptr() as *const libc::kinfo_proc;
        for i in 0..count {
            // SAFETY: The buffer contains `count` fully initialized kinfo_proc
            // entries, so indexing within bounds is safe.
            let kp = unsafe { &*kprocs.add(i) };
            if kp.ki_tid == tid {
                // SAFETY: The kernel guarantees that ki_tdname contains a
                // null-terminated string, so CStr::from_ptr is valid here.
                let tdname = unsafe {
                    std::ffi::CStr::from_ptr(kp.ki_tdname.as_ptr())
                        .to_string_lossy()
                        .into_owned()
                };
                if !tdname.is_empty() {
                    return Some(tdname);
                }
                // SAFETY: Same invariant as ki_tdname above — the kernel
                // guarantees ki_comm contains a null-terminated string.
                let comm = unsafe {
                    std::ffi::CStr::from_ptr(kp.ki_comm.as_ptr())
                        .to_string_lossy()
                        .into_owned()
                };
                if !comm.is_empty() {
                    return Some(comm);
                }
                return None;
            }
        }

        None
    }

    pub fn get_vm_mappings(&self) -> io::Result<Vec<KInfoVmEntry>> {
        let mut count: libc::c_int = 0;

        // SAFETY: kinfo_getvmmap is a well-defined libutil function that returns
        // a heap-allocated array via malloc. We check for null before use.
        // from_raw_parts is safe because the pointer is valid and count matches
        // the array length. free is correct because the pointer came from malloc.
        // The slice is copied to a Vec before freeing.
        unsafe {
            let ptr = kinfo_getvmmap(self.pid, &mut count);
            if ptr.is_null() {
                return Err(io::Error::last_os_error());
            }
            let slice = std::slice::from_raw_parts(ptr, count as usize);
            let vec = slice.to_vec();
            libc::free(ptr as *mut libc::c_void);
            Ok(vec)
        }
    }

    pub fn get_hw_ncpu(&self) -> io::Result<i32> {
        let mib = [libc::CTL_HW, libc::HW_NCPU];
        let mut ncpu: i32 = 0;
        let mut len = mem::size_of::<i32>() as libc::size_t;

        // SAFETY: sysctl is a well-defined kernel interface. We provide valid
        // pointers for mib, output buffer, and size. The kernel fills the
        // buffer and returns 0 on success, which we check.
        unsafe {
            if libc::sysctl(
                mib.as_ptr(),
                mib.len() as libc::c_uint,
                &mut ncpu as *mut i32 as *mut libc::c_void,
                &mut len,
                std::ptr::null(),
                0,
            ) != 0
            {
                return Err(io::Error::last_os_error());
            }
        }

        Ok(ncpu)
    }

    pub fn get_hw_model(&self) -> io::Result<String> {
        let mib = [libc::CTL_HW, libc::HW_MODEL];
        let mut len = 0;

        // SAFETY: sysctl is a well-defined kernel interface. First call gets the
        // required buffer size; second call fills the buffer. We check return values.
        unsafe {
            if libc::sysctl(
                mib.as_ptr(),
                mib.len() as libc::c_uint,
                std::ptr::null_mut(),
                &mut len,
                std::ptr::null(),
                0,
            ) != 0
            {
                return Err(io::Error::last_os_error());
            }

            if len == 0 {
                return Ok(String::from("Unknown"));
            }

            let mut buffer = vec![0u8; len];
            if libc::sysctl(
                mib.as_ptr(),
                mib.len() as libc::c_uint,
                buffer.as_mut_ptr() as *mut libc::c_void,
                &mut len,
                std::ptr::null(),
                0,
            ) != 0
            {
                return Err(io::Error::last_os_error());
            }

            buffer.truncate(len - 1);
            String::from_utf8(buffer).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "non-UTF-8 CPU model string")
            })
        }
    }

    pub fn read_auxv(&self) -> Result<Vec<u8>, AuxvError> {
        let mib = [
            libc::CTL_KERN,
            libc::KERN_PROC,
            libc::KERN_PROC_AUXV,
            self.pid,
        ];

        let mut len = 0;

        // SAFETY: sysctl is a well-defined kernel interface. We provide valid mib,
        // pointers, and check the return value. The kernel fills the buffer on success.
        unsafe {
            if libc::sysctl(
                mib.as_ptr(),
                mib.len() as libc::c_uint,
                std::ptr::null_mut(),
                &mut len,
                std::ptr::null(),
                0,
            ) != 0
            {
                return Err(AuxvError::ReadError(std::io::Error::last_os_error()));
            }

            if len == 0 {
                return Err(AuxvError::NoAuxvEntryFound);
            }

            let mut buffer = vec![0u8; len];

            if libc::sysctl(
                mib.as_ptr(),
                mib.len() as libc::c_uint,
                buffer.as_mut_ptr() as *mut libc::c_void,
                &mut len,
                std::ptr::null(),
                0,
            ) != 0
            {
                return Err(AuxvError::ReadError(std::io::Error::last_os_error()));
            }

            buffer.truncate(len);

            Ok(buffer)
        }
    }
}

#[derive(Debug)]
pub struct FileReader(File);

impl Read for FileReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

#[derive(Debug)]
pub struct DirReader(fs::ReadDir);

impl Iterator for DirReader {
    type Item = io::Result<OsString>;

    fn next(&mut self) -> Option<Self::Item> {
        self.0
            .next()
            .map(|result| result.map(|entry| entry.file_name()))
    }
}

#[derive(Debug, thiserror::Error, serde::Serialize)]
pub enum ProcessStopError {
    #[error("Failed to stop the process")]
    Stop(
        #[source]
        #[serde(serialize_with = "serialize_io_error")]
        io::Error,
    ),
    #[error("Timeout waiting for process to stop")]
    Timeout,
    #[error("Failed to wait for process")]
    WaitPidFailed(
        #[source]
        #[serde(serialize_with = "serialize_io_error")]
        io::Error,
    ),
}

#[derive(Debug, thiserror::Error, serde::Serialize)]
pub enum SuspendResumeThreadError {
    #[error("skipped thread {0} due to invalid stack pointer")]
    InvalidStackPointer(Pid),
}

fn ptrace_process(request: libc::c_int, pid: libc::pid_t) -> io::Result<()> {
    if unsafe { libc::ptrace(request, pid, std::ptr::null_mut::<libc::c_char>(), 0) } == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

const PATH_MAX: usize = 1024;

#[repr(C)]
#[derive(Clone)]
pub struct KInfoVmEntry {
    pub kve_structsize: i32,
    pub kve_type: i32,
    pub kve_start: u64,
    pub kve_end: u64,
    pub kve_offset: u64,
    pub kve_vn_fileid: u64,
    pub kve_vn_fsid_freebsd11: u32,
    pub kve_flags: i32,
    pub kve_resident: i32,
    pub kve_private_resident: i32,
    pub kve_protection: i32,
    pub kve_ref_count: i32,
    pub kve_shadow_count: i32,
    pub kve_vn_type: i32,
    pub kve_vn_size: u64,
    pub kve_vn_rdev_freebsd11: u32,
    pub kve_vn_mode: u16,
    pub kve_status: u16,
    pub kve_type_spec: u64,
    pub kve_vn_rdev: u64,
    pub _kve_ispare: [i32; 8],
    pub kve_path: [u8; PATH_MAX],
}

const _: () = assert!(std::mem::size_of::<KInfoVmEntry>() == 1160);

#[link(name = "util")]
unsafe extern "C" {
    fn kinfo_getvmmap(pid: libc::pid_t, cntp: *mut libc::c_int) -> *mut KInfoVmEntry;
}

/// Safety: request and T must agree on the size of the returned type.
unsafe fn ptrace_getregs<T>(request: libc::c_int, tid: libc::pid_t) -> io::Result<T> {
    let mut output = mem::MaybeUninit::<T>::uninit();
    let res = unsafe { libc::ptrace(request, tid, output.as_mut_ptr().cast::<libc::c_char>(), 0) };
    if res == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { output.assume_init() })
}
