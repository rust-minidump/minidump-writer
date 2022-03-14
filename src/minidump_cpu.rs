cfg_if::cfg_if! {
    if #[cfg(target_arch = "x86_64")] {
        pub type RawContextCPU = minidump_common::format::CONTEXT_AMD64;
        pub type FloatStateCPU = minidump_common::format::XMM_SAVE_AREA32;
    } else if #[cfg(target_arch = "x86")] {
        pub type RawContextCPU = minidump_common::format::CONTEXT_X86;
        pub type FloatStateCPU = minidump_common::format::FLOATING_SAVE_AREA_X86;
    } else if #[cfg(target_arch = "arm")] {
        pub mod arm;
        pub use arm as imp;
        pub type RawContextCPU = arm::MDRawContextARM;
    } else if #[cfg(target_arch = "aarch64")] {
        pub type RawContextCPU = minidump_common::format::CONTEXT_ARM64_OLD;
        pub type FloatStateCPU = minidump_common::format::FLOATING_SAVE_AREA_ARM64_OLD;
    } else if #[cfg(target_arch = "mips")] {
        compile_error!("flesh me out");
    } else {
        compile_error!("unsupported target architecture");
    }
}
