//! Thread enumeration and per-thread state on FreeBSD.
//!
//! All process access goes through the
//! [`ProcessInspector`](crate::freebsd::process_inspection::ProcessInspector);
//! this module never issues `ptrace`/`sysctl` requests itself.

use super::process_inspection;

type Result<T> = std::result::Result<T, ThreadInfoError>;

#[derive(thiserror::Error, Debug, serde::Serialize)]
pub enum ThreadInfoError {
    #[error("Index out of bounds: Got {0}, only have {1}")]
    IndexOutOfBounds(usize, usize),
    #[error("thread enumeration failed")]
    ThreadEnumFailed(#[source] process_inspection::Error),
    #[error("failed to get general-purpose registers")]
    GetGenRegsFailed(#[source] process_inspection::Error),
    #[error("failed to get floating-point registers")]
    GetFpRegsFailed(#[source] process_inspection::Error),
}

cfg_if::cfg_if! {
    if #[cfg(target_arch = "x86_64")] {
        mod x86_64;
        pub mod x86_64_regs;

        pub type ThreadInfo = x86_64::ThreadInfoX86;
    }
}
