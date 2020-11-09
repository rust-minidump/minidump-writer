use std::error;
use std::result;

type Error = Box<dyn error::Error + std::marker::Send + std::marker::Sync>;
pub type Result<T> = result::Result<T, Error>;

mod auxv_reader;
pub mod cpu_set;
pub mod linux_ptrace_dumper;
mod maps_reader;
pub mod minidump_cpu;
pub mod thread_info;

pub use maps_reader::LINUX_GATE_LIBRARY_NAME;
