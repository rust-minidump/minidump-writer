cfg_if::cfg_if! {
    if #[cfg(any(
        target_arch = "x86_64",
        target_arch = "x86",
        target_arch = "mips",
        target_arch = "mips64"
    ))]
    {
        pub mod x86_mips;
        pub use x86_mips as imp;
    } else if #[cfg(any(
        target_arch = "arm",
        target_arch = "aarch64",
    ))]
    {
        pub mod arm;
        pub use arm as imp;
    }
}

pub use imp::write_cpu_information;

use crate::minidump_format::PlatformId;
use nix::sys::utsname::uname;

/// Retrieves the [`MDOSPlatform`] and synthesized version information
pub fn os_information() -> (PlatformId, String) {
    let info = uname();
    let vers = format!(
        "{} {} {} {}",
        info.sysname(),
        info.release(),
        info.version(),
        info.machine()
    );

    (
        if cfg!(target_os = "android") {
            PlatformId::Android
        } else {
            PlatformId::Linux
        },
        vers,
    )
}
