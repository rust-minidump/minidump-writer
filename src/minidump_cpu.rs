cfg_if::cfg_if! {
    if #[cfg(target_arch = "x86_64")] {
        pub(crate) mod amd64;
        pub(crate) use amd64 as imp;

        pub type RawContextCPU = imp::MDRawContextAMD64;
    } else if #[cfg(target_arch = "x86")] {
        pub(crate) mod x86;
        pub(crate) pub use x86 as imp;

        pub type RawContextCPU = imp::MDRawContextX86;
    } else if #[cfg(target_arch = "arm")] {
        pub(crate) mod arm;
        pub(crate) pub use arm as imp;

        pub type RawContextCPU = imp::MDRawContextARM;
    } else if #[cfg(target_arch = "aarch64")] {
        pub(crate) mod aarch64;
        pub(crate) pub use aarch64 as imp;

        compile_error!("flesh me out");
    } else {
        compile_error!("unsupported target architecture");
    }
}
