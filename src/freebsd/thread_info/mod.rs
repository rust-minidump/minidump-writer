use {super::Pid, crate::serializers::*};

type Result<T> = std::result::Result<T, ThreadInfoError>;

#[derive(thiserror::Error, Debug, serde::Serialize)]
pub enum ThreadInfoError {
    #[error("Index out of bounds: Got {0}, only have {1}")]
    IndexOutOfBounds(usize, usize),
    #[error("ptrace operation failed")]
    PtraceError(
        #[source]
        #[serde(serialize_with = "serialize_io_error")]
        std::io::Error,
    ),
    #[error("Thread enumeration failed for process {0}")]
    ThreadEnumFailed(Pid),
}

cfg_if::cfg_if! {
    if #[cfg(target_arch = "x86_64")] {
        mod x86_64;
        pub mod x86_64_regs;
        pub type ThreadInfo = x86_64::ThreadInfoX86;
    }
}

impl ThreadInfo {
    pub fn create(process_id: Pid, thread_id: Pid) -> Result<Self> {
        let mut registers = Self::getregs(thread_id)?;
        let fpregs = Self::getfpregs(thread_id)?;
        Self::apply_fpregs_to_context(&mut registers, &fpregs);
        let stack_pointer = registers.rsp as usize;
        let name = get_thread_name(process_id, thread_id);

        Ok(Self {
            tid: thread_id,
            stack_pointer,
            name,
            registers,
            fpregs,
        })
    }
}

pub fn get_thread_list(pid: Pid) -> Result<Vec<Pid>> {
    // SAFETY: ptrace operates on the target pid which has been validated.
    // PT_GETNUMLWPS returns the number of LWPs or -1 on error, which we check.
    let num_lwps = unsafe {
        libc::ptrace(
            libc::PT_GETNUMLWPS,
            pid,
            std::ptr::null_mut::<libc::c_char>(),
            0,
        )
    };
    if num_lwps == -1 {
        return Err(ThreadInfoError::PtraceError(std::io::Error::last_os_error()));
    }
    if num_lwps == 0 {
        return Err(ThreadInfoError::ThreadEnumFailed(pid));
    }

    let count = num_lwps as usize;
    let mut tids = vec![0i32; count];

    // SAFETY: ptrace operates on the target pid. PT_GETLWPLIST fills the
    // provided buffer with thread IDs. We provide a valid buffer of correct size.
    let res = unsafe {
        libc::ptrace(
            libc::PT_GETLWPLIST,
            pid,
            tids.as_mut_ptr() as *mut libc::c_char,
            count as libc::c_int,
        )
    };
    if res == -1 {
        return Err(ThreadInfoError::PtraceError(std::io::Error::last_os_error()));
    }

    tids.truncate(res as usize);
    Ok(tids)
}

/// Retrieves the per-thread name for a specific thread (LWP) in a process.
///
/// Uses `KERN_PROC_INC_THREAD` to get per-thread `kinfo_proc` entries, then
/// matches by `ki_tid` and reads `ki_tdname` (the per-thread name set via
/// `pthread_set_name_np`), falling back to `ki_comm` if `ki_tdname` is empty.
pub fn get_thread_name(pid: Pid, tid: Pid) -> Option<String> {
    let mib = [
        libc::CTL_KERN,
        libc::KERN_PROC,
        libc::KERN_PROC_PID | libc::KERN_PROC_INC_THREAD,
        pid,
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

    let count = len / std::mem::size_of::<libc::kinfo_proc>();
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
    if res != 0 {
        return None;
    }

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
