// `WriterError` is large and clippy doesn't like that, but not a huge deal atm
#![allow(clippy::result_large_err)]

pub use maps_reader::LINUX_GATE_LIBRARY_NAME;

pub mod app_memory;
pub mod crash_context;
pub mod maps_reader;
pub mod minidump_writer;
pub mod module_reader;
pub mod thread_info;

pub(crate) mod auxv;

// TODO - Only public for testing
#[cfg(feature = "testing")]
pub mod process_inspection;

#[cfg(not(feature = "testing"))]
mod process_inspection;

mod dso_debug;
mod dumper_cpu_info;
mod serializers;

#[cfg(target_os = "android")]
mod android;

pub type Pid = i32;
