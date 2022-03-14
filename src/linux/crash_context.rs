//! Minidump defines register structures which are different from the raw
//! structures which we get from the kernel. These are platform specific
//! functions to juggle the ucontext_t and user structures into minidump format.

#![allow(non_camel_case_types)]

cfg_if::cfg_if! {
    if #[cfg(target_arch = "x86_64")] {
        pub(crate) mod x86_64;

        pub type fpstate_t = libc::user_fpregs_struct;
    } else if #[cfg(target_arch = "x86")] {
        pub(crate) mod x86;

        pub type fpstate_t = libc::_libc_fpstate;
    } else if #[cfg(target_arch = "arm")] {
        pub(crate) mod arm;
    } else if #[cfg(target_arch = "aarch64")] {
        pub(crate) mod aarch64;

        /// Magic value written by the kernel and our custom getcontext
        pub const FPSIMD_MAGIC: u32 = 0x46508001;

        #[repr(C)]
        #[derive(Clone)]
        pub struct _aarch64_ctx {
            pub magic: u32,
            pub size: u32,
        }

        #[repr(C)]
        #[derive(Clone)]
        pub struct fpsimd_context {
            pub head: _aarch64_ctx,
            pub fpsr: u32,
            pub fpcr: u32,
            pub vregs: [u128; 32],
        }

        pub type fpstate_t = fpsimd_context;
    }
}

#[repr(C)]
#[derive(Clone)]
pub struct CrashContext {
    pub siginfo: libc::siginfo_t,
    pub tid: libc::pid_t, // the crashing thread.
    #[cfg(not(target_arch = "arm"))]
    pub context: libc::ucontext_t,
    // #ifdef this out because FP state is not part of user ABI for Linux ARM.
    // In case of MIPS Linux FP state is already part of ucontext_t so
    // 'float_state' is not required.
    #[cfg(not(target_arch = "arm"))]
    pub float_state: fpstate_t,
}
