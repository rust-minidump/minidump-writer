// Because of the nature of this crate, there are lots of times we cast aliased types to `u64`
// Often, on 64-bit platforms, it's already that, so Clippy gets upset at the u64-to-u64
// conversion.
#![allow(clippy::useless_conversion)]

cfg_if::cfg_if! {
    if #[cfg(any(target_os = "linux", target_os = "android"))] {
        mod linux;

        failspot::failspot_name! {
            pub enum FailSpotName {
                StopProcess,
                FillMissingAuxvInfo,
                ThreadName,
                SuspendThreads,
                CpuInfoFileOpen,
            }
        }

        pub use linux::*;
    } else if #[cfg(target_os = "windows")] {
        mod windows;

        pub use windows::*;
    } else if #[cfg(target_os = "macos")] {
        mod mac;

        pub use mac::*;
    }
}

pub mod dir_section;
pub mod mem_writer;
pub mod minidump_cpu;
pub mod minidump_format;
pub mod module_reader;
pub mod process_reader;

mod serializers;

/// Re-export of crash-context
pub use ::crash_context;
