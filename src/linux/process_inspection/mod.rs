use {
    super::{Pid, maps_reader, serializers},
    core::{ffi::c_void, mem},
    nix::errno::Errno,
    process_reader::ProcessReader,
    regs::*,
    std::{
        fs::File,
        io::{self, Read},
        path::Path,
    },
};

pub mod process_reader;
pub mod regs;

#[cfg(target_env = "gnu")]
type PtraceRequestType = core::ffi::c_uint;

#[cfg(not(target_env = "gnu"))]
type PtraceRequestType = core::ffi::c_int;

#[derive(Debug)]
pub struct ProcessInspector {
    pid: libc::pid_t,
    process_reader: ProcessReader,
}

impl ProcessInspector {
    pub fn local(pid: libc::pid_t) -> Self {
        ProcessInspector {
            pid,
            process_reader: ProcessReader::new(pid),
        }
    }

    pub fn process_reader(&self) -> &ProcessReader {
        &self.process_reader
    }

    pub fn read_file(&self, path: impl AsRef<Path>) -> io::Result<impl Read> {
        File::open(path)
    }

    pub fn get_gen_regs(&self, tid: libc::pid_t) -> nix::Result<GenRegs> {
        getregset(tid).or_else(|_| getregs(tid))
    }

    pub fn get_fp_regs(&self, tid: libc::pid_t) -> nix::Result<FpRegs> {
        getfpregset(tid).or_else(|_| getfpregs(tid))
    }

    #[cfg(target_arch = "x86")]
    pub fn get_fpx_regs(&self, tid: libc::pid_t) -> nix::Result<FpxRegs> {
        const PTRACE_GETFPXREGS: PtraceRequestType = 18;
        unsafe { ptrace_getregs::<FpxRegs>(PTRACE_GETFPXREGS, tid) }
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn ptrace_peekuser(
        &self,
        pid: libc::pid_t,
        addr: usize,
    ) -> nix::Result<[u8; mem::size_of::<libc::c_long>()]> {
        // Since ptrace() is vararg, best to explicitly state arg types
        let addr: *mut libc::c_void = addr as *mut libc::c_void;
        let data: *mut libc::c_void = core::ptr::null_mut();
        Errno::set_raw(0);
        let rv = unsafe { libc::ptrace(libc::PTRACE_PEEKUSER, pid, addr, data) };
        if rv == -1 && Errno::last_raw() != 0 {
            Err(Errno::last())
        } else {
            Ok(rv.to_ne_bytes())
        }
    }
}

fn getregset(_pid: libc::pid_t) -> nix::Result<GenRegs> {
    #[cfg(target_arch = "arm")]
    {
        Err(Errno::ENOTSUP)
    }
    #[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64"))]
    {
        const NT_PRSTATUS: usize = 1;
        ptrace_getregset(NT_PRSTATUS, _pid)
    }
}

fn getregs(pid: libc::pid_t) -> nix::Result<GenRegs> {
    const PTRACE_GETREGS: PtraceRequestType = 12;
    unsafe { ptrace_getregs::<GenRegs>(PTRACE_GETREGS, pid) }
}

fn getfpregset(pid: libc::pid_t) -> nix::Result<FpRegs> {
    #[cfg(target_arch = "arm")]
    {
        const NT_ARM_VFP: usize = 0x400;
        ptrace_getregset(NT_ARM_VFP, pid)
    }
    #[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64"))]
    {
        const NT_PRFPREGSET: usize = 2;
        ptrace_getregset(NT_PRFPREGSET, pid)
    }
}

fn getfpregs(_pid: libc::pid_t) -> nix::Result<FpRegs> {
    #[cfg(target_arch = "arm")]
    {
        Err(Errno::ENOTSUP)
    }
    #[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64"))]
    {
        const PTRACE_GETFPREGS: PtraceRequestType = 14;
        unsafe { ptrace_getregs::<FpRegs>(PTRACE_GETFPREGS, _pid) }
    }
}

/// Safety: RequestType and T must agree on the size of the returned type
unsafe fn ptrace_getregs<T>(request: PtraceRequestType, pid: libc::pid_t) -> nix::Result<T> {
    let mut output = mem::MaybeUninit::<T>::uninit();

    // Since ptrace() is vararg, best to explicitly state arg types
    let addr: *mut c_void = core::ptr::null_mut();
    let data: *mut c_void = output.as_mut_ptr().cast();
    let res = unsafe { libc::ptrace(request, pid, addr, data) };
    Errno::result(res)?;
    Ok(unsafe { output.assume_init() })
}

fn ptrace_getregset<T>(regset_type: usize, pid: libc::pid_t) -> nix::Result<T> {
    let mut output = mem::MaybeUninit::<T>::uninit();
    let mut io = libc::iovec {
        iov_base: output.as_mut_ptr().cast(),
        iov_len: mem::size_of::<T>(),
    };

    // Since ptrace() is vararg, best to explicitly state arg types
    let addr: *mut c_void = regset_type as *mut c_void;
    let data: *mut c_void = (&raw mut io).cast();
    let res = unsafe { libc::ptrace(libc::PTRACE_GETREGSET, pid, addr, data) };
    Errno::result(res)?;

    // PTRACE_GETREGSET returns the number of bytes actually read in iov_len. Need to ensure
    // all bytes of T are actually initialized
    if io.iov_len != mem::size_of::<T>() {
        return Err(Errno::EINVAL);
    }

    Ok(unsafe { output.assume_init() })
}

#[doc(hidden)]
impl ProcessInspector {
    pub fn force_pr_reset(&mut self) {
        self.process_reader = ProcessReader::new(self.pid)
    }
    pub fn force_pr_virtual_mem(&mut self) {
        self.process_reader = ProcessReader::for_virtual_mem(self.pid)
    }
    pub fn force_pr_file(&mut self) -> std::io::Result<()> {
        self.process_reader = ProcessReader::for_file(self.pid)?;
        Ok(())
    }
    pub fn force_pr_ptrace(&mut self) {
        self.process_reader = ProcessReader::for_ptrace(self.pid);
    }
}
