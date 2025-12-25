use {
    super::{
        continue_process, resume_thread, stop_process, suspend_thread, Error, FileReader,
        FilenameIterator, Pid, ProcessInspector,
    },
    nix::{sys::stat, unistd::Pid as NixPid},
    std::{
        fs, io,
        path::{Path, PathBuf},
        sync::OnceLock,
    },
};

#[derive(Debug)]
pub struct DirectInspector {
    pid: NixPid,
    read_style: OnceLock<ReadStyle>,
}

impl DirectInspector {
    pub fn new(pid: Pid) -> DirectInspector {
        DirectInspector {
            pid: NixPid::from_raw(pid),
            read_style: OnceLock::default(),
        }
    }
    fn read(&self, address: usize, dst: &mut [u8]) -> Result<usize, Error> {
        if let Some(rs) = self.read_style.get() {
            return rs.read(address, dst);
        }

        const DOUBLE_INIT_MSG: &str = "somehow MemReader initialized twice";

        // Attempt to read in order of speed

        let vmem_err = {
            let rs = ReadStyle::virtual_mem(self.pid);
            match rs.read(address, dst) {
                Ok(len) => {
                    self.read_style.set(rs).expect(DOUBLE_INIT_MSG);
                    return Ok(len);
                }
                Err(e) => e,
            }
        };

        let file_err = match ReadStyle::file(self.pid) {
            Ok(rs) => match rs.read(address, dst) {
                Ok(len) => {
                    self.read_style.set(rs).expect(DOUBLE_INIT_MSG);
                    return Ok(len);
                }
                Err(e) => e,
            },
            Err(e) => e,
        };

        let ptrace_err = {
            let rs = ReadStyle::ptrace(self.pid);
            match rs.read(address, dst) {
                Ok(len) => {
                    self.read_style.set(rs).expect(DOUBLE_INIT_MSG);
                    return Ok(len);
                }
                Err(e) => e,
            }
        };

        self.read_style
            .set(ReadStyle::Unavailable)
            .expect(DOUBLE_INIT_MSG);

        Err(Error::ReadProcessMemory {
            vmem_err: Box::new(vmem_err),
            file_err: Box::new(file_err),
            ptrace_err: Box::new(ptrace_err),
        })
    }
    fn proc_pid_path(&self, subpath: &Path) -> PathBuf {
        let mut p = PathBuf::from(format!("/proc/{}", self.pid));
        p.push(subpath);
        p
    }

    #[cfg(feature = "testing")]
    pub fn for_virtual_mem(pid: Pid) -> Self {
        let pid = NixPid::from_raw(pid);
        DirectInspector {
            pid,
            read_style: OnceLock::from(ReadStyle::virtual_mem(pid)),
        }
    }
    #[cfg(feature = "testing")]
    pub fn for_file(pid: Pid) -> Result<Self, Error> {
        let pid = NixPid::from_raw(pid);
        Ok(DirectInspector {
            pid,
            read_style: OnceLock::from(ReadStyle::file(pid)?),
        })
    }
    #[cfg(feature = "testing")]
    pub fn for_ptrace(pid: Pid) -> Self {
        let pid = NixPid::from_raw(pid);
        DirectInspector {
            pid,
            read_style: OnceLock::from(ReadStyle::ptrace(pid)),
        }
    }
}

impl ProcessInspector for DirectInspector {
    fn stop_process(&self) -> Result<(), Error> {
        stop_process(self.pid)
    }
    fn continue_process(&self) -> Result<(), Error> {
        continue_process(self.pid)
    }
    fn stat_proc_path(&self, subpath: &Path) -> Result<stat::FileStat, Error> {
        let path = self.proc_pid_path(subpath);
        stat::stat(&path).map_err(Error::Stat)
    }
    fn read_proc_path(&self, subpath: &Path) -> Result<FileReader, Error> {
        let path = self.proc_pid_path(subpath);
        let file = fs::File::open(&path).map_err(Error::OpenFile)?;
        let buf_reader = io::BufReader::new(file);
        Ok(Box::new(buf_reader))
    }
    fn read_proc_dir(&self, subdir: &Path) -> Result<FilenameIterator, Error> {
        let path = self.proc_pid_path(subdir);
        if !path.is_dir() {
            return Err(Error::NotADirectory);
        }

        let file_iter = fs::read_dir(&path)
            .map_err(Error::ReadDirectory)?
            .map(|entry| {
                entry
                    .map(|entry| entry.file_name())
                    .map_err(Error::ReadDirectory)
            });

        Ok(Box::new(file_iter))
    }
    fn resolve_proc_symlink(&self, subpath: &Path) -> Result<PathBuf, Error> {
        let path = self.proc_pid_path(subpath);
        fs::read_link(&path).map_err(Error::ReadLink)
    }
    fn attach_to_thread(&self, tid: Pid) -> Result<(), Error> {
        suspend_thread(NixPid::from_raw(tid))
    }
    fn detach_from_thread(&self, tid: Pid) -> Result<(), Error> {
        resume_thread(NixPid::from_raw(tid))
    }
    fn read_memory(&self, address: usize, buf: &mut [u8]) -> Result<usize, Error> {
        self.read(address, buf)
    }
}

#[derive(Debug)]
enum ReadStyle {
    /// Uses [`process_vm_readv`](https://linux.die.net/man/2/process_vm_readv)
    /// to read the memory.
    ///
    /// This is not available on old <3.2 (really, ancient) kernels, and requires
    /// the same permissions as ptrace
    VirtualMem(NixPid),
    /// Reads the memory from `/proc/<pid>/mem`
    ///
    /// Available on basically all versions of Linux, but could fail if the process
    /// has insufficient privileges, ie ptrace
    File(std::fs::File),
    /// Reads the memory with [ptrace (`PTRACE_PEEKDATA`)](https://man7.org/linux/man-pages/man2/ptrace.2.html)
    ///
    /// Reads data one word at a time, so slow, but fairly reliable, as long as
    /// the process can be ptraced
    Ptrace(NixPid),
    /// No methods succeeded, generally there isn't a case where failing a syscall
    /// will work if called again
    Unavailable,
}

impl ReadStyle {
    fn virtual_mem(pid: NixPid) -> Self {
        Self::VirtualMem(pid)
    }
    fn file(pid: NixPid) -> Result<Self, Error> {
        std::fs::File::open(format!("/proc/{pid}/mem"))
            .map(Self::File)
            .map_err(Error::ReadProcessMemoryFile)
    }
    fn ptrace(pid: NixPid) -> Self {
        Self::Ptrace(pid)
    }
    fn read(&self, address: usize, dst: &mut [u8]) -> Result<usize, Error> {
        match self {
            Self::VirtualMem(pid) => {
                let remote = &[nix::sys::uio::RemoteIoVec {
                    base: address,
                    len: dst.len(),
                }];
                nix::sys::uio::process_vm_readv(*pid, &mut [std::io::IoSliceMut::new(dst)], remote)
                    .map_err(Error::ReadProcessMemoryReadv)
            }
            Self::File(file) => {
                use std::os::unix::fs::FileExt;
                file.read_exact_at(dst, address as u64)
                    .map_err(Error::ReadProcessMemoryFile)?;
                Ok(dst.len())
            }
            Self::Ptrace(pid) => {
                let mut offset = 0;
                let mut chunks = dst.chunks_exact_mut(std::mem::size_of::<usize>());

                for chunk in chunks.by_ref() {
                    let word =
                        nix::sys::ptrace::read(*pid, (address + offset) as *mut std::ffi::c_void)
                            .map_err(|err| Error::ReadProcessMemoryPtrace(err, offset))?;
                    chunk.copy_from_slice(&word.to_ne_bytes());
                    offset += std::mem::size_of::<usize>();
                }

                // I don't think there would ever be a case where we would not read on word boundaries, but just in case...
                let last = chunks.into_remainder();
                if !last.is_empty() {
                    let word =
                        nix::sys::ptrace::read(*pid, (address + offset) as *mut std::ffi::c_void)
                            .map_err(|err| Error::ReadProcessMemoryPtrace(err, offset))?;
                    last.copy_from_slice(&word.to_ne_bytes()[..last.len()]);
                }

                Ok(dst.len())
            }
            Self::Unavailable => Err(Error::Unavailable),
        }
    }
}
