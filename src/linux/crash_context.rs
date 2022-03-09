// Minidump defines register structures which are different from the raw
// structures which we get from the kernel. These are platform specific
// functions to juggle the ucontext_t and user structures into minidump format.

cfg_if::cfg_if! {
    if #[cfg(target_arch = "x86_64")] {
        mod x86_64;
    } else if #[cfg(target_arch = "x86")] {
        mod x86;
    } else if #[cfg(target_arch = "aarch64")] {
        mod aarch64;
    } else if #[cfg(target_arch = "arm")] {
        mod arm;
    } else if #[cfg(target_arch = "mips")] {
        mod mips;
    }
}

use crate::minidump_cpu::{FloatStateCPU, RawContextCPU};
pub use exception_handler::CrashContext;

pub trait CpuContext {
    fn get_instruction_pointer(&self) -> usize;
    fn get_stack_pointer(&self) -> usize;
    fn fill_cpu_context(&self, cpu_ctx: &mut RawContextCPU);
}
