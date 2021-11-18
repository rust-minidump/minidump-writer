// Minidump defines register structures which are different from the raw
// structures which we get from the kernel. These are platform specific
// functions to juggle the ucontext_t and user structures into minidump format.

cfg_if::cfg_if! {
    if #[cfg(target_arch = "x86_64")] {
        mod crash_context_x86_64;
    } else if #[cfg(target_arch = "x86")] {
        mod crash_context_x86;
    } else if #[cfg(target_arch = "aarch64")] {
        mod crash_context_aarch64;
    } else if #[cfg(target_arch = "arm")] {
        mod crash_context_arm;
    } else if #[cfg(target_arch = "mips")] {
        mod crash_context_mips;
    }
}

use crate::minidump_cpu::RawContextCPU;

// #[cfg(target_arch = "aarch64")]
// pub type fpstate_t = libc::fpsimd_context; // Currently not part of libc! This will produce an error.
// #[cfg(not(any(
//     target_arch = "aarch64",
//     target_arch = "mips",
//     target_arch = "arm-eabi"
// )))]
// #[cfg(target_arch = "x86")]
// #[allow(non_camel_case_types)]
// pub type fpstate_t = libc::_libc_fpstate;
// #[cfg(target_arch = "x86_64")]
// #[allow(non_camel_case_types)]
// pub type fpstate_t = libc::user_fpregs_struct;

pub use exception_handler::CrashContext;

pub trait CpuContext {
    fn get_instruction_pointer(&self) -> usize;
    fn get_stack_pointer(&self) -> usize;
    fn fill_cpu_context(&self, cpu_ctx: &mut RawContextCPU);
}
