#![no_std]
#![cfg(any(target_os = "linux", target_os = "android"))]

pub use drop_fail_handler::Handler as DropFailHandler;

#[macro_use]
mod drop_fail_handler;

pub mod local;
pub mod regs;

/// This is the longest path length we guarantee we can handle, since we won't be able to allocate
/// in the fork of the crashed process. We can increase if necessary.
pub const MAX_PATH_LEN: usize = 256;

#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub enum ProcessReaderKind {
    Unspecified,
    VirtualMem,
    File,
    Ptrace,
}
