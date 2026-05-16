// `WriterError` is large and clippy doesn't like that, but not a huge deal atm
#![allow(clippy::result_large_err)]

pub mod app_memory;
pub mod auxv;
pub mod crash_context;
pub mod dumper_cpu_info;
pub mod maps_reader;
pub mod minidump_writer;
pub mod module_reader;
pub mod process_reader;
mod serializers;
pub mod thread_info;
pub mod vm_permissions;

pub use maps_reader::FREEBSD_GATE_LIBRARY_NAME;
pub type Pid = i32;
