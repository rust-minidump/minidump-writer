//! Functionality for reading a remote process's memory

use {
    crate::{errors::CopyFromProcessError, ptrace_dumper::PtraceDumper, Pid},
    plain::Plain,
    std::io,
};

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
    File(std::fs::File),
    /// Reads the memory with [ptrace (`PTRACE_PEEKDATA`)](https://man7.org/linux/man-pages/man2/ptrace.2.html)
    ///
    /// Reads data one word at a time, so slow, but fairly reliable, as long as
    /// the process can be ptraced
    Ptrace,
    /// No methods succeeded, generally there isn't a case where failing a syscall
    /// will work if called again
    Unavailable {
        vmem: nix::Error,
        file: nix::Error,
        ptrace: nix::Error,
    },
}

pub struct MemReader {
    /// The pid of the child to read
    pid: nix::unistd::Pid,
    style: Option<Style>,
}

impl std::fmt::Debug for MemReader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match &self.style {
            Some(Style::VirtualMem) => "process_vm_readv",
            Some(Style::File(_)) => "/proc/<pid>/mem",
            Some(Style::Ptrace) => "PTRACE_PEEKDATA",
            Some(Style::Unavailable { vmem, file, ptrace }) => {
                return write!(
                    f,
                    "process_vm_readv: {vmem}, /proc/<pid>/mem: {file}, PTRACE_PEEKDATA: {ptrace}"
                );
            }
            None => "unknown",
        };

        f.write_str(s)
    }
}

impl MemReader {
    /// Creates a [`Self`] for the specified process id, the method used will
    /// be probed for on the first access
    #[inline]
    pub fn new(pid: i32) -> Self {
        Self {
            pid: nix::unistd::Pid::from_raw(pid),
            style: None,
        }
    }

    #[inline]
    #[doc(hidden)]
    pub fn for_virtual_mem(pid: i32) -> Self {
        Self {
            pid: nix::unistd::Pid::from_raw(pid),
            style: Some(Style::VirtualMem),
        }
    }

    #[inline]
    #[doc(hidden)]
    pub fn for_file(pid: i32) -> std::io::Result<Self> {
        let file = std::fs::File::open(format!("/proc/{pid}/mem"))?;

        Ok(Self {
            pid: nix::unistd::Pid::from_raw(pid),
            style: Some(Style::File(file)),
        })
    }

    #[inline]
    #[doc(hidden)]
    pub fn for_ptrace(pid: i32) -> Self {
        Self {
            pid: nix::unistd::Pid::from_raw(pid),
            style: Some(Style::Ptrace),
        }
    }

    #[inline]
    pub fn read_to_vec(
        &mut self,
        src: usize,
        length: std::num::NonZeroUsize,
    ) -> Result<Vec<u8>, CopyFromProcessError> {
        let mut output = vec![0u8; length.into()];
        let bytes_read = self.read(src, &mut output)?;
        output.truncate(bytes_read);
        Ok(output)
    }

    pub fn read_pod<T: Plain>(&mut self, address: usize) -> io::Result<T> {
        fn as_bytes_mut<T>(obj: &mut T) -> &mut [u8] {
            unsafe {
                std::slice::from_raw_parts_mut(obj as *mut _ as *mut u8, std::mem::size_of::<T>())
            }
        }
        // Safety: All of this is safe to do because `Plain` is an unsafe trait that may only be
        // implemented on types that are valid for every possible bit pattern, so there is nothing
        // that we could read from the other process that isn't a valid value for our type.
        let mut pod_obj: T = unsafe { std::mem::zeroed() };
        let bytes = as_bytes_mut(&mut pod_obj);
        self.read_exact(address, bytes)?;
        Ok(pod_obj)
    }

    pub fn read_pod_vec<T: Plain>(
        &mut self,
        mut address: usize,
        count: usize,
    ) -> io::Result<Vec<T>> {
        let mut v = Vec::with_capacity(count);
        for _ in 0..count {
            v.push(self.read_pod(address)?);
            address += std::mem::size_of::<T>();
        }
        Ok(v)
    }

    pub fn read_until(
        &mut self,
        mut address: usize,
        byte: u8,
        buf: &mut Vec<u8>,
    ) -> io::Result<usize> {
        let start_len = buf.len();
        let mut b = [0u8];
        while self.read(address, &mut b).map_err(io::Error::other)? > 0 {
            buf.push(b[0]);
            if b[0] == byte {
                break;
            }
            address += 1;
        }
        Ok(buf.len() - start_len)
    }

    pub fn read_exact(&mut self, mut address: usize, mut dst: &mut [u8]) -> io::Result<()> {
        while !dst.is_empty() {
            let bytes_read = self.read(address, dst).map_err(io::Error::other)?;
            if bytes_read == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            address += bytes_read;
            dst = &mut dst[bytes_read..];
        }
        Ok(())
    }

    pub fn read(&mut self, address: usize, dst: &mut [u8]) -> Result<usize, CopyFromProcessError> {
        if let Some(rs) = &mut self.style {
            let res = match rs {
                Style::VirtualMem => Self::vmem(self.pid, address, dst).map_err(|s| (s, 0)),
                Style::File(file) => Self::file(file, address, dst).map_err(|s| (s, 0)),
                Style::Ptrace => Self::ptrace(self.pid, address, dst),
                Style::Unavailable { ptrace, .. } => Err((*ptrace, 0)),
            };

            return res.map_err(|(source, offset)| CopyFromProcessError {
                child: self.pid.as_raw(),
                address,
                offset,
                length: dst.len(),
                source,
            });
        }

        // Attempt to read in order of speed
        let vmem = match Self::vmem(self.pid, address, dst) {
            Ok(len) => {
                self.style = Some(Style::VirtualMem);
                return Ok(len);
            }
            Err(err) => err,
        };

        let file = match std::fs::File::open(format!("/proc/{}/mem", self.pid)) {
            Ok(mut file) => match Self::file(&mut file, address, dst) {
                Ok(len) => {
                    self.style = Some(Style::File(file));
                    return Ok(len);
                }
                Err(err) => err,
            },
            Err(err) => nix::Error::from_raw(err.raw_os_error().expect(
                "failed to open /proc/<pid>/mem and the I/O error doesn't have an OS code",
            )),
        };

        let ptrace = match Self::ptrace(self.pid, address, dst) {
            Ok(len) => {
                self.style = Some(Style::Ptrace);
                return Ok(len);
            }
            Err((err, _)) => err,
        };

        self.style = Some(Style::Unavailable { vmem, file, ptrace });
        Err(CopyFromProcessError {
            child: self.pid.as_raw(),
            address,
            offset: 0,
            length: dst.len(),
            source: ptrace,
        })
    }

    #[inline]
    fn vmem(pid: nix::unistd::Pid, address: usize, dst: &mut [u8]) -> Result<usize, nix::Error> {
        let remote = &[nix::sys::uio::RemoteIoVec {
            base: address,
            len: dst.len(),
        }];
        nix::sys::uio::process_vm_readv(pid, &mut [std::io::IoSliceMut::new(dst)], remote)
    }

    #[inline]
    fn file(file: &mut std::fs::File, address: usize, dst: &mut [u8]) -> Result<usize, nix::Error> {
        use std::os::unix::fs::FileExt;

        file.read_exact_at(dst, address as u64).map_err(|err| {
            if let Some(os) = err.raw_os_error() {
                nix::Error::from_raw(os)
            } else {
                nix::Error::E2BIG /* EOF */
            }
        })?;

        Ok(dst.len())
    }

    #[inline]
    fn ptrace(
        pid: nix::unistd::Pid,
        address: usize,
        dst: &mut [u8],
    ) -> Result<usize, (nix::Error, usize)> {
        let mut offset = 0;
        let mut chunks = dst.chunks_exact_mut(std::mem::size_of::<usize>());

        for chunk in chunks.by_ref() {
            let word = nix::sys::ptrace::read(pid, (address + offset) as *mut std::ffi::c_void)
                .map_err(|err| (err, offset))?;
            chunk.copy_from_slice(&word.to_ne_bytes());
            offset += std::mem::size_of::<usize>();
        }

        // I don't think there would ever be a case where we would not read on word boundaries, but just in case...
        let last = chunks.into_remainder();
        if !last.is_empty() {
            let word = nix::sys::ptrace::read(pid, (address + offset) as *mut std::ffi::c_void)
                .map_err(|err| (err, offset))?;
            last.copy_from_slice(&word.to_ne_bytes()[..last.len()]);
        }

        Ok(dst.len())
    }
}

impl PtraceDumper {
    /// Copies a block of bytes from the target process, returning the heap
    /// allocated copy
    #[inline]
    pub fn copy_from_process(
        pid: Pid,
        address: usize,
        length: usize,
    ) -> Result<Vec<u8>, crate::errors::DumperError> {
        let length = std::num::NonZeroUsize::new(length).ok_or(
            crate::errors::DumperError::CopyFromProcessError(CopyFromProcessError {
                address,
                child: pid,
                offset: 0,
                length,
                // TODO: We should make copy_from_process also take a NonZero,
                // as EINVAL could also come from the syscalls that actually read
                // memory as well which could be confusing
                source: nix::errno::Errno::EINVAL,
            }),
        )?;

        let mut mem = MemReader::new(pid);
        Ok(mem.read_to_vec(address, length)?)
    }
}
