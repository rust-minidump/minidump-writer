cfg_if::cfg_if! {
    if #[cfg(any(target_os = "linux", target_os = "android"))] {
        mod linux;

        pub use linux::*;
    }
}

pub mod minidump_cpu;
pub mod minidump_format;
