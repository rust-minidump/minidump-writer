use super as linux;
use crate::module_reader::{ModuleMemoryReadError, ReadError, ReadModuleMemory};
use linux::maps_reader;
use process_backend::{local, regs::*};
use process_reader::ProcessReader;
use std::{
    borrow::Cow,
    ffi::{CString, OsString, c_int},
    io,
    os::unix::ffi::OsStringExt,
    path::PathBuf,
};

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use process_backend::PTRACE_DATA_LEN;

pub(crate) use process_backend::regs;

pub use process_backend::ProcessReaderKind;

pub mod process_reader;

pub(crate) type Result<T> = core::result::Result<T, Error>;

// This is an arbitrary choice and may need to be tweaked
const MAX_PATH_LEN: usize = 65536;

#[derive(Debug)]
pub struct ProcessInspector {
    pid: libc::pid_t,
    backend: Backend,
}

#[derive(Debug)]
enum Backend {
    Local { backend: local::Backend },
}

pub(crate) fn local(pid: libc::pid_t) -> ProcessInspector {
    set_process_backend_drop_fail_handler();

    let backend = local::Backend::new(pid);

    ProcessInspector {
        pid,
        backend: Backend::Local { backend },
    }
}

impl ProcessInspector {
    pub fn process_reader(&self) -> ProcessReader<'_> {
        ProcessReader::new(self)
    }

    pub fn pid(&self) -> Result<libc::pid_t> {
        match &self.backend {
            Backend::Local { backend, .. } => Ok(backend.pid()),
        }
    }

    pub fn stop_process(&self) -> Result<()> {
        match &self.backend {
            Backend::Local { backend, .. } => backend.stop_process().map_err(Error::Local),
        }
    }

    pub fn continue_process(&self) -> Result<()> {
        match &self.backend {
            Backend::Local { backend, .. } => backend.continue_process().map_err(Error::Local),
        }
    }

    pub fn suspend_thread(&self, tid: libc::pid_t) -> Result<()> {
        match &self.backend {
            Backend::Local { backend, .. } => backend.suspend_thread(tid).map_err(Error::Local),
        }
    }

    pub fn resume_thread(&self, tid: libc::pid_t) -> Result<()> {
        match &self.backend {
            Backend::Local { backend, .. } => backend.resume_thread(tid).map_err(Error::Local),
        }
    }

    pub fn map_module_into_memory(
        &self,
        path: PathBuf,
        offset: u64,
    ) -> Result<MappedModuleMemoryReader> {
        let c_path = CString::new(path.into_os_string().into_vec()).unwrap();
        match &self.backend {
            Backend::Local { backend, .. } => backend
                .map_module_into_memory(&c_path, offset)
                .map(MappedModuleMemoryReader::Local)
                .map_err(Error::Local),
        }
    }

    pub fn stat_file(&self, path: PathBuf) -> Result<libc::stat> {
        let c_path = CString::new(path.into_os_string().into_vec()).unwrap();
        match &self.backend {
            Backend::Local { backend, .. } => backend.stat_file(&c_path).map_err(Error::Local),
        }
    }

    pub fn read_file(&self, path: PathBuf) -> Result<FileReader> {
        let c_path = CString::new(path.into_os_string().into_vec()).unwrap();
        match &self.backend {
            Backend::Local { backend, .. } => backend
                .read_file(&c_path)
                .map(FileReader::Local)
                .map_err(Error::Local),
        }
    }

    pub fn read_dir(&self, path: PathBuf) -> Result<DirReader> {
        let c_path = CString::new(path.into_os_string().into_vec()).unwrap();
        match &self.backend {
            Backend::Local { backend, .. } => backend
                .read_dir(&c_path)
                .map(DirReader::Local)
                .map_err(Error::Local),
        }
    }

    pub fn read_link(&self, path: PathBuf) -> Result<PathBuf> {
        let c_path = CString::new(path.into_os_string().into_vec()).unwrap();

        let mut buf = vec![0u8; MAX_PATH_LEN];

        let len = match &self.backend {
            Backend::Local { backend, .. } => {
                backend.read_link(&c_path, &mut buf).map_err(Error::Local)?
            }
        };

        buf.truncate(len);
        Ok(PathBuf::from(OsString::from_vec(buf)))
    }

    pub fn get_gen_regs(&self, tid: libc::pid_t) -> Result<GenRegs> {
        match &self.backend {
            Backend::Local { backend, .. } => backend.get_gen_regs(tid).map_err(Error::Local),
        }
    }

    pub fn get_fp_regs(&self, tid: libc::pid_t) -> Result<FpRegs> {
        match &self.backend {
            Backend::Local { backend, .. } => backend.get_fp_regs(tid).map_err(Error::Local),
        }
    }

    #[cfg(target_arch = "x86")]
    pub fn get_fpx_regs(&self, tid: libc::pid_t) -> Result<FpxRegs> {
        match &self.backend {
            Backend::Local { backend, .. } => backend.get_fpx_regs(tid).map_err(Error::Local),
        }
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn ptrace_peekuser(&self, addr: usize) -> Result<[u8; PTRACE_DATA_LEN]> {
        match &self.backend {
            Backend::Local { backend, .. } => backend.ptrace_peekuser(addr).map_err(Error::Local),
        }
    }

    pub fn force_process_reader_kind(&mut self, kind: ProcessReaderKind) -> Result<()> {
        match &mut self.backend {
            Backend::Local { backend, .. } => backend
                .force_process_reader_kind(kind)
                .map_err(Error::Local),
        }
    }

    #[doc(hidden)]
    pub fn fail_one_syscall_with(&self, errno: c_int) {
        match &self.backend {
            Backend::Local { backend, .. } => backend.fail_one_syscall_with(errno),
        }
    }
}

#[derive(Debug)]
pub enum FileReader {
    Local(local::FileReader),
}

impl io::Read for FileReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Local(l) => l.read(buf).map_err(Error::Local),
        }
        .map_err(io::Error::other)
    }
}

#[derive(Debug)]
pub enum DirReader {
    Local(local::DirReader),
}

impl Iterator for DirReader {
    type Item = Result<OsString>;
    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Local(l) => Some(
                l.read_next_name()
                    .transpose()?
                    .map(<[u8]>::to_vec)
                    .map(OsString::from_vec)
                    .map_err(Error::Local),
            ),
        }
    }
}

#[derive(Debug)]
pub enum MappedModuleMemoryReader {
    Local(local::MappedModuleMemoryReader),
}

impl MappedModuleMemoryReader {
    pub fn read_exact_at(&self, mut offset: usize, mut buf: &mut [u8]) -> Result<()> {
        if buf.is_empty() {
            return Ok(());
        }

        match self {
            Self::Local(l) => loop {
                let bytes = l.read_at(offset, buf.len()).map_err(Error::Local)?;
                if bytes.is_empty() {
                    return Err(Error::UnexpectedEndOfBuffer);
                }
                let (dst, tail) = buf.split_at_mut(bytes.len());
                dst.copy_from_slice(bytes);
                if tail.is_empty() {
                    return Ok(());
                }
                offset = offset
                    .checked_add(dst.len())
                    .ok_or(Error::AddressOverflowed)?;
                buf = tail;
            },
        }
    }
    pub fn len(&self) -> Result<usize> {
        match self {
            Self::Local(l) => Ok(l.len()),
        }
    }
}

impl ReadModuleMemory for MappedModuleMemoryReader {
    fn read(
        &self,
        offset: u64,
        length: u64,
    ) -> core::result::Result<Cow<'_, [u8]>, ModuleMemoryReadError> {
        let result = (|| {
            let (offset, length) = match (usize::try_from(offset), usize::try_from(length)) {
                (Ok(o), Ok(l)) => (o, l),
                _ => return Err(ReadError::OutOfBounds),
            };

            let mut buf = vec![0u8; length];

            self.read_exact_at(offset, &mut buf)
                .map_err(ReadError::PlatformSpecific)?;

            Ok(buf)
        })();

        result
            .map(Cow::Owned)
            .map_err(|error| ModuleMemoryReadError {
                offset,
                length,
                start_address: None,
                error,
            })
    }
    fn absolute_to_relative(&self, addr: u64) -> Option<u64> {
        Some(addr)
    }
    /// Calculates the absolute address of the specified relative address
    fn relative_to_absolute(&self, addr: u64) -> Option<u64> {
        Some(addr)
    }
    fn is_process_memory(&self) -> bool {
        false
    }
}

#[derive(Debug, thiserror::Error, serde::Serialize)]
pub enum Error {
    #[error("an error occurred running a syscall directly")]
    Local(#[source] local::Error),
    #[error("an address overflowed")]
    AddressOverflowed,
    #[error("unexpected end of buffer reached")]
    UnexpectedEndOfBuffer,
}

fn set_process_backend_drop_fail_handler() {
    fn drop_fail_handler(args: core::fmt::Arguments<'_>) {
        log::error!("a drop() error occurred in process-backend: {args}");
    }
    const HANDLER: process_backend::DropFailHandler =
        process_backend::DropFailHandler::new(drop_fail_handler);
    HANDLER.install_global();
}
