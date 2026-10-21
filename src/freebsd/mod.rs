//! FreeBSD implementation of minidump generation.
//!
//! All process state required to write a minidump is gathered through the
//! [`ProcessInspector`] trait: down-stream modules (thread info, maps,
//! module readers, minidump streams) never invoke `ptrace`/`sysctl`
//! directly.
//!
//! [`ProcessInspector`]: process_inspection::ProcessInspector

pub mod process_inspection;

pub mod vm_permissions;

mod ptrace_io;

pub use process_inspection::{local, process_reader};

pub type Pid = i32;
