use {
    super::{Pid, serializers::*},
    crate::serializers::*,
    nix::errno::Errno,
    std::{
        ffi::c_void,
        io::{self, BufRead},
        path,
    },
};

#[cfg(target_arch = "x86_64")]
pub use x86::copy_u32_registers;

type Result<T> = std::result::Result<T, ThreadInfoError>;

#[derive(thiserror::Error, Debug, serde::Serialize)]
pub enum ThreadInfoError {
    #[error("Index out of bounds: Got {0}, only have {1}")]
    IndexOutOfBounds(usize, usize),
    #[error("Either ppid ({1}) or tgid ({2}) not found in {0}")]
    InvalidPid(String, Pid, Pid),
    #[error("IO error")]
    IOError(
        #[from]
        #[serde(serialize_with = "serialize_io_error")]
        std::io::Error,
    ),
    #[error("Couldn't parse address")]
    UnparsableInteger(
        #[from]
        #[serde(skip)]
        std::num::ParseIntError,
    ),
    #[error("nix::ptrace() error")]
    PtraceError(
        #[source]
        #[serde(serialize_with = "serialize_nix_error")]
        nix::Error,
    ),
    #[error("Invalid line in /proc/{0}/status: {1}")]
    InvalidProcStatusFile(Pid, String),
}

cfg_if::cfg_if! {
    if #[cfg(any(target_arch = "x86", target_arch = "x86_64"))] {
        mod x86;
        pub type ThreadInfo = x86::ThreadInfoX86;
    } else if #[cfg(target_arch = "arm")] {
        mod arm;
        pub type ThreadInfo = arm::ThreadInfoArm;
    } else if #[cfg(target_arch = "aarch64")] {
        mod aarch64;
        pub type ThreadInfo = aarch64::ThreadInfoAarch64;
    }
}

#[cfg(target_env = "gnu")]
type PtraceRequestType = core::ffi::c_uint;

#[cfg(not(target_env = "gnu"))]
type PtraceRequestType = core::ffi::c_int;

fn get_ppid_and_tgid(tid: Pid) -> Result<(Pid, Pid)> {
    let mut ppid = -1;
    let mut tgid = -1;

    let status_path = path::PathBuf::from(format!("/proc/{tid}/status"));
    let status_file = std::fs::File::open(status_path)?;
    for line in io::BufReader::new(status_file).lines() {
        let l = line?;
        let start = l
            .get(0..6)
            .ok_or_else(|| ThreadInfoError::InvalidProcStatusFile(tid, l.clone()))?;
        match start {
            "Tgid:\t" => {
                tgid = l
                    .get(6..)
                    .ok_or_else(|| ThreadInfoError::InvalidProcStatusFile(tid, l.clone()))?
                    .parse::<Pid>()?;
            }
            "PPid:\t" => {
                ppid = l
                    .get(6..)
                    .ok_or_else(|| ThreadInfoError::InvalidProcStatusFile(tid, l.clone()))?
                    .parse::<Pid>()?;
            }
            _ => continue,
        }
    }
    if ppid == -1 || tgid == -1 {
        return Err(ThreadInfoError::InvalidPid(
            format!("/proc/{tid}/status"),
            ppid,
            tgid,
        ));
    }
    Ok((ppid, tgid))
}

/// Safety: RequestType and T must agree on the size of the returned type
unsafe fn ptrace_getregs<T>(request: PtraceRequestType, pid: libc::pid_t) -> Result<T> {
    let mut output = std::mem::MaybeUninit::uninit();

    // Since ptrace() is vararg, best to explicitly state arg types
    let addr: *mut c_void = std::ptr::null_mut();
    let data: *mut c_void = (&raw mut output).cast();
    let res = unsafe { libc::ptrace(request, pid, addr, data) };
    Errno::result(res).map_err(ThreadInfoError::PtraceError)?;
    Ok(unsafe { output.assume_init() })
}

fn ptrace_getregset<T>(regset_type: usize, pid: libc::pid_t) -> Result<T> {
    let mut output = std::mem::MaybeUninit::<T>::uninit();
    let mut io = libc::iovec {
        iov_base: output.as_mut_ptr().cast(),
        iov_len: std::mem::size_of::<T>(),
    };

    // Since ptrace() is vararg, best to explicitly state arg types
    let addr: *mut c_void = regset_type as *mut c_void;
    let data: *mut c_void = (&raw mut io).cast();
    let res = unsafe { libc::ptrace(libc::PTRACE_GETREGSET, pid, addr, data) };
    Errno::result(res).map_err(ThreadInfoError::PtraceError)?;

    // PTRACE_GETREGSET returns the number of bytes actually read in iov_len. Need to ensure
    // all bytes of T are actually initialized
    if io.iov_len != std::mem::size_of::<T>() {
        return Err(ThreadInfoError::PtraceError(Errno::EINVAL));
    }

    Ok(unsafe { output.assume_init() })
}
