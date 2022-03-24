cfg_if::cfg_if! {
    if #[cfg(any(target_os = "linux", target_os = "android"))] {
        mod linux;

        pub use linux::*;
    } else if #[cfg(target_os = "windows")] {
        mod windows;

        pub use windows::*;
    }
}

pub mod minidump_cpu;
pub mod minidump_format;
