use super as linux;
use crate::module_reader::{ModuleMemoryReadError, ReadError, ReadModuleMemory};
use linux::maps_reader;
use process_backend::{local, regs::*};
use process_reader::{CopyFromProcessError, ProcessReader, ProcessReaderBackend};
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

pub(crate) fn local(pid: libc::pid_t) -> Box<dyn ProcessInspector> {
    set_process_backend_drop_fail_handler();
    Box::new(local::Backend::new(pid))
}

pub trait ProcessInspector: core::fmt::Debug {
    fn process_reader<'a>(&'a self) -> ProcessReader<'a>;
    fn pid(&self) -> Result<libc::pid_t>;
    fn stop_process(&self) -> Result<()>;
    fn continue_process(&self) -> Result<()>;
    fn suspend_thread(&self, tid: libc::pid_t) -> Result<()>;
    fn resume_thread(&self, tid: libc::pid_t) -> Result<()>;
    fn map_module_into_memory(
        &self,
        path: PathBuf,
        offset: u64,
    ) -> Result<MappedModuleMemoryReader>;
    fn stat_file(&self, path: PathBuf) -> Result<libc::stat>;
    fn read_file(&self, path: PathBuf) -> Result<FileReader>;
    fn read_dir(&self, path: PathBuf) -> Result<DirReader>;
    fn read_link(&self, path: PathBuf) -> Result<PathBuf>;
    fn get_gen_regs(&self, tid: libc::pid_t) -> Result<GenRegs>;
    fn get_fp_regs(&self, tid: libc::pid_t) -> Result<FpRegs>;

    #[cfg(target_arch = "x86")]
    fn get_fpx_regs(&self, tid: libc::pid_t) -> Result<FpxRegs>;

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn ptrace_peekuser(&self, addr: usize) -> Result<[u8; PTRACE_DATA_LEN]>;

    fn force_process_reader_kind(&mut self, kind: ProcessReaderKind) -> Result<()>;

    fn fail_one_syscall_with(&self, errno: core::ffi::c_int);
}

impl ProcessInspector for local::Backend {
    fn process_reader<'a>(&'a self) -> ProcessReader<'a> {
        ProcessReader::new(self)
    }

    fn pid(&self) -> Result<libc::pid_t> {
        Ok(local::Backend::pid(self))
    }

    fn stop_process(&self) -> Result<()> {
        local::Backend::stop_process(self).map_err(Error::Local)
    }

    fn continue_process(&self) -> Result<()> {
        local::Backend::continue_process(self).map_err(Error::Local)
    }

    fn suspend_thread(&self, tid: libc::pid_t) -> Result<()> {
        local::Backend::suspend_thread(self, tid).map_err(Error::Local)
    }

    fn resume_thread(&self, tid: libc::pid_t) -> Result<()> {
        local::Backend::resume_thread(self, tid).map_err(Error::Local)
    }

    fn map_module_into_memory(
        &self,
        path: PathBuf,
        offset: u64,
    ) -> Result<MappedModuleMemoryReader> {
        let c_path = CString::new(path.into_os_string().into_vec()).unwrap();
        let reader =
            local::Backend::map_module_into_memory(self, &c_path, offset).map_err(Error::Local)?;
        Ok(MappedModuleMemoryReader(reader))
    }

    fn stat_file(&self, path: PathBuf) -> Result<libc::stat> {
        let c_path = CString::new(path.into_os_string().into_vec()).unwrap();
        local::Backend::stat_file(self, &c_path).map_err(Error::Local)
    }

    fn read_file(&self, path: PathBuf) -> Result<FileReader> {
        let c_path = CString::new(path.into_os_string().into_vec()).unwrap();
        let reader = local::Backend::read_file(self, &c_path).map_err(Error::Local)?;
        Ok(FileReader(reader))
    }

    fn read_dir(&self, path: PathBuf) -> Result<DirReader> {
        let c_path = CString::new(path.into_os_string().into_vec()).unwrap();
        let reader = local::Backend::read_dir(self, &c_path).map_err(Error::Local)?;
        Ok(DirReader(reader))
    }

    fn read_link(&self, path: PathBuf) -> Result<PathBuf> {
        let c_path = CString::new(path.into_os_string().into_vec()).unwrap();
        let mut buf = vec![0u8; MAX_PATH_LEN];
        let len = local::Backend::read_link(self, &c_path, &mut buf).map_err(Error::Local)?;
        buf.truncate(len);
        Ok(PathBuf::from(OsString::from_vec(buf)))
    }
    fn get_gen_regs(&self, tid: libc::pid_t) -> Result<GenRegs> {
        local::Backend::get_gen_regs(self, tid).map_err(Error::Local)
    }

    fn get_fp_regs(&self, tid: libc::pid_t) -> Result<FpRegs> {
        local::Backend::get_fp_regs(self, tid).map_err(Error::Local)
    }

    #[cfg(target_arch = "x86")]
    fn get_fpx_regs(&self, tid: libc::pid_t) -> Result<FpxRegs> {
        local::Backend::get_fpx_regs(self, tid).map_err(Error::Local)
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn ptrace_peekuser(&self, addr: usize) -> Result<[u8; PTRACE_DATA_LEN]> {
        local::Backend::ptrace_peekuser(self, addr).map_err(Error::Local)
    }

    fn force_process_reader_kind(&mut self, kind: ProcessReaderKind) -> Result<()> {
        local::Backend::force_process_reader_kind(self, kind).map_err(Error::Local)
    }

    #[doc(hidden)]
    fn fail_one_syscall_with(&self, errno: c_int) {
        local::Backend::fail_one_syscall_with(self, errno)
    }
}

impl ProcessReaderBackend for local::Backend {
    fn process_inspector(&self) -> &dyn ProcessInspector {
        self
    }

    fn read_at(
        &self,
        src: usize,
        dst: &mut [u8],
    ) -> core::result::Result<usize, CopyFromProcessError> {
        local::Backend::process_reader(self)
            .read_at(src, dst)
            .map_err(|e| CopyFromProcessError::Backend(Error::Local(e)))
    }
}

#[derive(Debug)]
pub struct FileReader(local::FileReader);

impl io::Read for FileReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0
            .read(buf)
            .map_err(Error::Local)
            .map_err(io::Error::other)
    }
}

#[derive(Debug)]
pub struct DirReader(local::DirReader);

impl Iterator for DirReader {
    type Item = Result<OsString>;
    fn next(&mut self) -> Option<Self::Item> {
        Some(
            self.0
                .read_next_name()
                .transpose()?
                .map(<[u8]>::to_vec)
                .map(OsString::from_vec)
                .map_err(Error::Local),
        )
    }
}

#[derive(Debug)]
pub struct MappedModuleMemoryReader(local::MappedModuleMemoryReader);

impl MappedModuleMemoryReader {
    pub fn read_exact_at(&self, mut offset: usize, mut buf: &mut [u8]) -> Result<()> {
        if buf.is_empty() {
            return Ok(());
        }

        loop {
            let bytes = self.0.read_at(offset, buf.len()).map_err(Error::Local)?;
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
        }
    }
    pub fn len(&self) -> Result<usize> {
        Ok(self.0.len())
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
