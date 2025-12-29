//! Common module reader types.
use {
    crate::process_reader::{CopyFromProcessError, ProcessReader},
    std::borrow::Cow,
};

#[cfg(any(target_os = "linux", target_os = "android"))]
pub use crate::linux::module_reader::*;

#[cfg(target_os = "windows")]
pub use crate::windows::module_reader::*;

#[cfg(target_os = "macos")]
pub use crate::mac::module_reader::*;

/// Module memory, which may either be represented by a slice or by an offset into a process's
/// address space.
#[derive(Clone, Copy)]
pub enum ModuleMemory<'a> {
    Slice(&'a [u8]),
    Process {
        reader: &'a ProcessReader,
        start_address: u64,
    },
}

impl<'buf> From<&'buf [u8]> for ModuleMemory<'buf> {
    fn from(value: &'buf [u8]) -> Self {
        Self::Slice(value)
    }
}

#[derive(Debug, thiserror::Error, serde::Serialize)]
#[error("Error reading {length} bytes at {offset:#x}{}: {error}",
    .start_address.map(|s| format!(" (module start address {s:#x})")).unwrap_or_default()
)]
pub struct ModuleMemoryReadError {
    offset: u64,
    length: u64,
    start_address: Option<u64>,
    #[source]
    error: ReadError,
}

#[derive(Debug, thiserror::Error, serde::Serialize)]
pub enum ReadError {
    #[error("Attempted to read 0 bytes from process memory")]
    ZeroLengthProcessRead,
    #[error("Read overflowed the address space")]
    Overflow,
    #[error("Read was out of slice memory bounds")]
    OutOfBounds,
    #[error(transparent)]
    CopyError(#[from] CopyFromProcessError),
}

impl<'a> ModuleMemory<'a> {
    pub fn from_process(reader: &'a ProcessReader, start_address: usize) -> Self {
        Self::Process {
            reader,
            start_address: start_address as u64,
        }
    }

    #[inline]
    pub fn read(&self, offset: u64, length: u64) -> Result<Cow<'a, [u8]>, ModuleMemoryReadError> {
        let error = move |start_address, error| ModuleMemoryReadError {
            start_address,
            offset,
            length,
            error,
        };

        match self {
            Self::Process {
                reader,
                start_address,
            } => {
                let error = |e| error(Some(*start_address), e);
                let len = std::num::NonZeroUsize::new(length as usize)
                    .ok_or_else(|| error(ReadError::ZeroLengthProcessRead))?;
                let proc_offset = start_address
                    .checked_add(offset)
                    .ok_or_else(|| error(ReadError::Overflow))?;
                reader
                    .read_to_vec(proc_offset as _, len)
                    .map(Cow::Owned)
                    .map_err(|err| error(err.into()))
            }
            Self::Slice(s) => {
                let error = |e| error(None, e);
                let end = offset
                    .checked_add(length)
                    .ok_or_else(|| error(ReadError::Overflow))?;
                s.get(offset as usize..end as usize)
                    .map(Cow::Borrowed)
                    .ok_or_else(|| error(ReadError::OutOfBounds))
            }
        }
    }

    /// Calculates the relative address of the specified absolute address
    #[inline]
    pub fn absolute_to_relative(&self, addr: u64) -> Option<u64> {
        let Self::Process { start_address, .. } = self else {
            return Some(addr);
        };
        addr.checked_sub(*start_address)
    }

    /// Calculates the absolute address of the specified relative address
    #[inline]
    pub fn relative_to_absolute(&self, addr: u64) -> Option<u64> {
        let Self::Process { start_address, .. } = self else {
            return Some(addr);
        };
        start_address.checked_add(addr)
    }

    #[inline]
    pub fn is_process_memory(&self) -> bool {
        matches!(self, Self::Process { .. })
    }
}
