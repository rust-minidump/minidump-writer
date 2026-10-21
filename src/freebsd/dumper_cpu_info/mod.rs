use {
    crate::{minidump_format::PlatformId, serializers::*},
    std::mem::MaybeUninit,
};

cfg_if::cfg_if! {
    if #[cfg(target_arch = "x86_64")] {
        pub mod x86_64;
        pub use x86_64 as imp;
    }
}

pub use imp::write_cpu_information;

#[derive(Debug, thiserror::Error, serde::Serialize)]
pub enum CpuInfoError {
    #[error("Failed to read CPU information")]
    ReadError(
        #[source]
        #[serde(serialize_with = "serialize_io_error")]
        std::io::Error,
    ),
    #[error("Failed to parse CPU information")]
    ParseError,
}

pub fn os_information() -> (PlatformId, String) {
    // The minidump format has no FreeBSD-specific platform id; use Linux as
    // the generic Unix-like identifier, like other minidump tools do.
    let platform_id = PlatformId::Linux;

    let mut uname_info = MaybeUninit::<libc::utsname>::zeroed();
    // SAFETY: uname fills the whole buffer with null-terminated strings on
    // success, making assume_init valid.
    let info = unsafe {
        if libc::uname(uname_info.as_mut_ptr()) != 0 {
            return (platform_id, "FreeBSD <unknown>".to_owned());
        }
        uname_info.assume_init()
    };

    let os = c_char_array_to_str(&info.sysname).unwrap_or("FreeBSD");
    let release = c_char_array_to_str(&info.release).unwrap_or("unknown");
    let version = c_char_array_to_str(&info.version).unwrap_or("unknown");
    let machine = c_char_array_to_str(&info.machine).unwrap_or("unknown");

    (platform_id, format!("{os} {release} {version} {machine}"))
}

fn c_char_array_to_str(arr: &[libc::c_char]) -> Option<&str> {
    let len = arr.iter().position(|&c| c == 0).unwrap_or(arr.len());
    // SAFETY: `c_char` and `u8` have the same layout; `from_utf8` validates
    // the bytes afterwards.
    let bytes = unsafe { std::slice::from_raw_parts(arr.as_ptr().cast::<u8>(), len) };
    std::str::from_utf8(bytes).ok()
}
