#![no_std]
#![cfg(any(target_os = "linux", target_os = "android"))]

pub use drop_fail_handler::Handler as DropFailHandler;

#[macro_use]
mod drop_fail_handler;

pub mod local;
pub mod regs;

mod wrapper;

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub const PTRACE_DATA_LEN: usize = core::mem::size_of::<libc::c_long>();

#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub enum ProcessReaderKind {
    Unspecified,
    VirtualMem,
    File,
    Ptrace,
}
