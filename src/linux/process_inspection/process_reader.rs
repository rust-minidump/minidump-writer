use {
    super::{Backend, Error, FileReader},
    core::{ffi::c_long, mem},
    std::{ffi::CString, rc::Rc, sync::OnceLock},
};

#[derive(Debug)]
enum Style {
    /// Uses [`process_vm_readv`](https://linux.die.net/man/2/process_vm_readv)
    /// to read the memory.
    ///
    /// This is not available on old <3.2 (really, ancient) kernels, and requires
    /// the same permissions as ptrace
    VirtualMem,
    /// Reads the memory from `/proc/<pid>/mem`
    ///
    /// Available on basically all versions of Linux, but could fail if the process
    /// has insufficient privileges, ie ptrace
    File(FileReader),
    /// Reads the memory with [ptrace (`PTRACE_PEEKDATA`)](https://man7.org/linux/man-pages/man2/ptrace.2.html)
    ///
    /// Reads data one word at a time, so slow, but fairly reliable, as long as
    /// the process can be ptraced
    Ptrace,
    /// No methods succeeded, generally there isn't a case where failing a syscall
    /// will work if called again
    Unavailable,
}

#[derive(Debug, thiserror::Error, serde::Serialize)]
pub enum CopyFromProcessError {
    #[error("Copy from process {child} failed (source {src}, offset: {offset}, length: {length})")]
    StrategyFailed {
        child: libc::pid_t,
        src: usize,
        offset: usize,
        length: usize,
        source: StrategyError,
    },
    #[error("all strategies for reading a process failed")]
    AllStrategiesFailed {
        vmem: StrategyError,
        file: StrategyError,
        ptrace: (StrategyError, usize),
    },
    #[error("process reading is unavailable")]
    Unavailable,
    #[error("an invalid argument was passed")]
    InvalidArgument,
}

#[derive(Debug, thiserror::Error, serde::Serialize)]
pub enum StrategyError {
    #[error(transparent)]
    Backend(Error),
    #[error("an unexpected end of file was reached")]
    UnexpectedEof,
}

pub struct ProcessReader {
    /// The pid of the child to read
    pid: libc::pid_t,
    style: OnceLock<Style>,
    backend: Rc<Backend>,
}

impl std::fmt::Debug for ProcessReader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self.style.get() {
            Some(Style::VirtualMem) => "process_vm_readv",
            Some(Style::File(_)) => "/proc/<pid>/mem",
            Some(Style::Ptrace) => "PTRACE_PEEKDATA",
            Some(Style::Unavailable) => "Unavailable",
            None => "unknown",
        };

        f.write_str(s)
    }
}

impl ProcessReader {
    /// Creates a [`Self`] for the specified process id, the method used will
    /// be probed for on the first access
    #[inline]
    pub(super) fn new(pid: libc::pid_t, backend: Rc<Backend>) -> Self {
        Self {
            pid,
            style: OnceLock::default(),
            backend,
        }
    }

    #[inline]
    #[doc(hidden)]
    pub(super) fn for_virtual_mem(pid: libc::pid_t, backend: Rc<Backend>) -> Self {
        Self {
            pid,
            style: OnceLock::from(Style::VirtualMem),
            backend,
        }
    }

    #[inline]
    #[doc(hidden)]
    pub(super) fn for_file(pid: libc::pid_t, backend: Rc<Backend>) -> Result<Self, Error> {
        let file = Self::open_file(&backend, format!("/proc/{pid}/mem"))?;

        Ok(Self {
            pid,
            style: OnceLock::from(Style::File(file)),
            backend,
        })
    }

    #[inline]
    #[doc(hidden)]
    pub(super) fn for_ptrace(pid: libc::pid_t, backend: Rc<Backend>) -> Self {
        Self {
            pid,
            style: OnceLock::from(Style::Ptrace),
            backend,
        }
    }

    /// Read memory from the process into the given buffer.
    ///
    /// Returns the number of bytes read.
    pub fn read(&self, src: usize, dst: &mut [u8]) -> Result<usize, CopyFromProcessError> {
        if let Some(rs) = self.style.get() {
            return match rs {
                Style::VirtualMem => Self::vmem(&self.backend, src, dst).map_err(|e| (e, 0)),
                Style::File(file) => Self::file(file, src, dst).map_err(|e| (e, 0)),
                Style::Ptrace => Self::ptrace(&self.backend, src, dst),
                Style::Unavailable => return Err(CopyFromProcessError::Unavailable),
            }
            .map_err(|(source, offset)| CopyFromProcessError::StrategyFailed {
                child: self.pid,
                src,
                offset,
                length: dst.len(),
                source,
            });
        }

        const DOUBLE_INIT_MSG: &str = "somehow MemReader initialized twice";

        // Attempt to read in order of speed
        let vmem = match Self::vmem(&self.backend, src, dst) {
            Ok(len) => {
                self.style.set(Style::VirtualMem).expect(DOUBLE_INIT_MSG);
                return Ok(len);
            }
            Err(err) => err,
        };

        let file = match Self::open_file(&self.backend, format!("/proc/{}/mem", self.pid)) {
            Ok(fd) => match Self::file(&fd, src, dst) {
                Ok(len) => {
                    self.style.set(Style::File(fd)).expect(DOUBLE_INIT_MSG);
                    return Ok(len);
                }
                Err(err) => err,
            },
            Err(err) => StrategyError::Backend(err),
        };

        let ptrace = match Self::ptrace(&self.backend, src, dst) {
            Ok(len) => {
                self.style.set(Style::Ptrace).expect(DOUBLE_INIT_MSG);
                return Ok(len);
            }
            Err(err) => err,
        };

        self.style.set(Style::Unavailable).expect(DOUBLE_INIT_MSG);
        Err(CopyFromProcessError::AllStrategiesFailed { vmem, file, ptrace })
    }

    fn open_file(backend: &Backend, path: String) -> Result<FileReader, Error> {
        let c_path = CString::new(path).unwrap();

        match backend {
            Backend::Local(l) => l
                .read_file(&c_path)
                .map(FileReader::Local)
                .map_err(Error::Local),
        }
    }

    #[inline]
    fn vmem(backend: &Backend, src: usize, dst: &mut [u8]) -> Result<usize, StrategyError> {
        match backend {
            Backend::Local(l) => l.read_process_io_vec(dst, src).map_err(Error::Local),
        }
        .map_err(StrategyError::Backend)
    }

    #[inline]
    fn file(reader: &FileReader, src: usize, dst: &mut [u8]) -> Result<usize, StrategyError> {
        let mut offset = 0;

        while offset < dst.len() {
            let bytes_read = reader
                .read_at(&mut dst[offset..], (src + offset).try_into().unwrap())
                .map_err(StrategyError::Backend)?;
            if bytes_read == 0 {
                return Err(StrategyError::UnexpectedEof);
            }
            offset += bytes_read;
        }

        Ok(dst.len())
    }

    #[inline]
    fn ptrace(
        backend: &Backend,
        src: usize,
        dst: &mut [u8],
    ) -> Result<usize, (StrategyError, usize)> {
        let mut offset = 0;

        for chunk in dst.chunks_mut(mem::size_of::<c_long>()) {
            let word = match backend {
                Backend::Local(l) => l.ptrace_peekdata(src + offset).map_err(Error::Local),
            }
            .map_err(|e| (StrategyError::Backend(e), offset))?;
            offset += word.len();
            chunk.copy_from_slice(&word[0..chunk.len()]);
        }

        Ok(dst.len())
    }
}
