//! FreeBSD implementation of minidump generation.
//!
//! All process state required to write a minidump is gathered through the
//! [`ProcessInspector`] trait: down-stream modules (thread info, maps,
//! module readers, minidump streams) never invoke `ptrace`/`sysctl`
//! directly.
//!
//! [`ProcessInspector`]: process_inspection::ProcessInspector

// `WriterError` is large and clippy doesn't like that, but not a huge deal atm
#![allow(clippy::result_large_err)]

pub mod process_inspection;

pub mod app_memory;
pub mod auxv;
pub mod crash_context;
pub mod dumper_cpu_info;
pub mod maps_reader;
pub mod module_reader;
pub mod thread_info;
pub mod vm_permissions;

mod ptrace_io;

pub use crate::freebsd::crash_context::CrashContext;
pub use process_inspection::{local, process_reader};

pub type Pid = i32;
