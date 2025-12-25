use {
    super::{serializers::*, Pid},
    crate::serializers::*,
    failspot::failspot,
    nix::{
        errno::Errno,
        sys::{ptrace, signal, stat, wait},
        unistd::Pid as NixPid,
    },
    serde::Serialize,
    std::{
        ffi::OsString,
        io,
        path::{Path, PathBuf},
    },
};

pub use direct::DirectInspector;

mod direct;

pub type FileReader = Box<dyn io::Read>;
pub type FilenameIterator = Box<dyn Iterator<Item = Result<OsString, Error>>>;

#[derive(Debug, Serialize, thiserror::Error)]
pub enum Error {
    #[error("failed to send SIGSTOP to process")]
    SigStop(
        #[source]
        #[serde(serialize_with = "serialize_nix_error")]
        Errno,
    ),
    #[error("failed to send SIGCONT to process")]
    SigCont(
        #[source]
        #[serde(serialize_with = "serialize_nix_error")]
        Errno,
    ),
    #[error("failed to attach to process")]
    PtraceAttach(
        #[source]
        #[serde(serialize_with = "serialize_nix_error")]
        Errno,
    ),
    #[error("waitpid returned unexpected status during ptrace attach")]
    PtraceUnexpectedStatus,
    #[error("failed to reinject non-SIGSTOP signal")]
    ReinjectSignal(
        #[source]
        #[serde(serialize_with = "serialize_nix_error")]
        Errno,
    ),
    #[error("failed while running waitpid")]
    WaitPid(
        #[source]
        #[serde(serialize_with = "serialize_nix_error")]
        Errno,
    ),
    #[error("Skipped thread due to it being part of the seccomp sandbox's trusted code")]
    SeccompTrustedCode,
    #[error("failed to detach from process")]
    PtraceDetach(
        #[source]
        #[serde(serialize_with = "serialize_nix_error")]
        Errno,
    ),
    #[error("failed to open file")]
    OpenFile(
        #[source]
        #[serde(serialize_with = "serialize_io_error")]
        io::Error,
    ),
    #[error("attempt to read directory that is not a directory")]
    NotADirectory,
    #[error("failed to read directory")]
    ReadDirectory(
        #[source]
        #[serde(serialize_with = "serialize_io_error")]
        io::Error,
    ),
    #[error("failed to read symbolic link")]
    ReadLink(
        #[source]
        #[serde(serialize_with = "serialize_io_error")]
        io::Error,
    ),
    #[error("failed trying to stat file")]
    Stat(
        #[source]
        #[serde(serialize_with = "serialize_nix_error")]
        Errno,
    ),
    #[error("failed to read process memory using process_vm_readv method")]
    ReadProcessMemoryReadv(
        #[source]
        #[serde(serialize_with = "serialize_nix_error")]
        Errno,
    ),
    #[error("failed to read process memory using file method")]
    ReadProcessMemoryFile(
        #[source]
        #[serde(serialize_with = "serialize_io_error")]
        io::Error,
    ),
    #[error("failed to read process memory using ptrace method")]
    ReadProcessMemoryPtrace(
        #[source]
        #[serde(serialize_with = "serialize_nix_error")]
        Errno,
        usize,
    ),
    #[error("failed to read process memory using all supported methods")]
    ReadProcessMemory {
        vmem_err: Box<Error>,
        file_err: Box<Error>,
        ptrace_err: Box<Error>,
    },
    #[error("process memory reading unavailable")]
    Unavailable,
}

pub trait ProcessInspector: std::fmt::Debug {
    fn stop_process(&self) -> Result<(), Error>;
    fn continue_process(&self) -> Result<(), Error>;
    fn stat_proc_path(&self, subpath: &Path) -> Result<stat::FileStat, Error>;
    fn read_proc_path(&self, subpath: &Path) -> Result<FileReader, Error>;
    fn read_proc_dir(&self, subdir: &Path) -> Result<FilenameIterator, Error>;
    fn resolve_proc_symlink(&self, subpath: &Path) -> Result<PathBuf, Error>;
    fn attach_to_thread(&self, tid: Pid) -> Result<(), Error>;
    fn detach_from_thread(&self, tid: Pid) -> Result<(), Error>;
    fn read_memory(&self, address: usize, buf: &mut [u8]) -> Result<usize, Error>;
    fn read_memory_to_vec(&self, address: usize, length: usize) -> Result<Vec<u8>, Error> {
        let mut v = vec![0u8; length];
        let bytes_read = self.read_memory(address, v.as_mut_slice())?;
        v.truncate(bytes_read);
        Ok(v)
    }
}

fn stop_process(pid: NixPid) -> Result<(), Error> {
    failspot!(StopProcess bail(Error::SigStop(Errno::EPERM)));
    signal::kill(pid, signal::SIGSTOP).map_err(Error::SigStop)
}

fn continue_process(pid: NixPid) -> Result<(), Error> {
    signal::kill(pid, signal::SIGCONT).map_err(Error::SigCont)
}

/// Suspends a thread by attaching to it.
fn suspend_thread(tid: NixPid) -> Result<(), Error> {
    // This may fail if the thread has just died or debugged.
    ptrace::attach(tid).map_err(Error::PtraceAttach)?;

    loop {
        match wait::waitpid(tid, Some(wait::WaitPidFlag::__WALL)) {
            Ok(wait::WaitStatus::Stopped(_, status)) => {
                // Any signal will stop the thread, make sure it is SIGSTOP. Otherwise, this
                // signal will be delivered after PTRACE_DETACH, and the thread will enter
                // the "T (stopped)" state.
                if status == nix::sys::signal::SIGSTOP {
                    break;
                }

                // Signals other than SIGSTOP that are received need to be reinjected,
                // or they will otherwise get lost.
                ptrace::cont(tid, status).map_err(Error::ReinjectSignal)?;
            }
            Ok(_) => return Err(Error::PtraceUnexpectedStatus),
            Err(Errno::EINTR) => continue,
            Err(e) => {
                ptrace_detach(tid)?;
                return Err(Error::WaitPid(e));
            }
        }
    }
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        // On x86, the stack pointer is NULL or -1, when executing trusted code in
        // the seccomp sandbox. Not only does this cause difficulties down the line
        // when trying to dump the thread's stack, it also results in the minidumps
        // containing information about the trusted threads. This information is
        // generally completely meaningless and just pollutes the minidumps.
        // We thus test the stack pointer and exclude any threads that are part of
        // the seccomp sandbox's trusted code.
        let skip_thread;
        let regs = super::thread_info::ThreadInfo::getregs(tid.into());
        if let Ok(regs) = regs {
            #[cfg(target_arch = "x86_64")]
            {
                skip_thread = regs.rsp == 0;
            }
            #[cfg(target_arch = "x86")]
            {
                skip_thread = regs.esp == 0;
            }
        } else {
            skip_thread = true;
        }
        if skip_thread {
            ptrace_detach(tid)?;
            return Err(Error::SeccompTrustedCode);
        }
    }
    Ok(())
}

/// Resumes a thread by detaching from it.
fn resume_thread(tid: NixPid) -> Result<(), Error> {
    ptrace_detach(tid)
}

/// PTRACE_DETACH the given pid.
///
/// This handles special errno cases (ESRCH) which we won't consider errors.
pub fn ptrace_detach(tid: NixPid) -> Result<(), Error> {
    ptrace::detach(tid, None).or_else(|e| {
        // errno is set to ESRCH if the pid no longer exists, but we don't want to error in that
        // case.
        if e == nix::Error::ESRCH {
            Ok(())
        } else {
            Err(Error::PtraceDetach(e))
        }
    })
}
