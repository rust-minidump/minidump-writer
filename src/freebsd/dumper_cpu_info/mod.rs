use {
    crate::{minidump_format::PlatformId, serializers::*},
    std::mem::MaybeUninit,
};

cfg_if::cfg_if! {
    if #[cfg(any(
        target_arch = "x86_64",
        target_arch = "x86",
    ))]
    {
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
    // Note: PlatformId doesn't have a FreeBSD-specific value.
    // Use PlatformId::Unix which is the Breakpad extension for generic
    // Unix-like platforms, rather than incorrectly claiming Linux.
    let platform_id = PlatformId::Unix;

    let mut uname_info = MaybeUninit::<libc::utsname>::zeroed();

    // SAFETY: uname is a well-defined POSIX system call. We provide a valid
    // pointer to a zeroed utsname buffer that the kernel fills on success.
    // On success, assume_init() is safe because the kernel fully initializes
    // the struct with valid null-terminated strings.
    let info = unsafe {
        if libc::uname(uname_info.as_mut_ptr()) != 0 {
            let machine = if cfg!(target_arch = "x86_64") {
                "x86_64"
            } else if cfg!(target_arch = "x86") {
                "x86"
            } else if cfg!(target_arch = "aarch64") {
                "aarch64"
            } else if cfg!(target_arch = "arm") {
                "arm"
            } else {
                "<unknown>"
            };

            return (
                platform_id,
                format!("FreeBSD <unknown> <unknown> {}", machine),
            );
        }

        let uname_info = uname_info.assume_init();

        let sysname = c_char_array_to_str(&uname_info.sysname).unwrap_or("FreeBSD");
        let release = c_char_array_to_str(&uname_info.release).unwrap_or("unknown");
        let version = c_char_array_to_str(&uname_info.version).unwrap_or("unknown");
        let machine = c_char_array_to_str(&uname_info.machine).unwrap_or("unknown");

        format!("{} {} {} {}", sysname, release, version, machine)
    };

    (platform_id, info)
}

fn c_char_array_to_str(arr: &[libc::c_char]) -> Option<&str> {
    let len = arr.iter().position(|&c| c == 0).unwrap_or(arr.len());
    // SAFETY: The kernel guarantees null-terminated strings in utsname fields.
    // We compute the length up to the null terminator and cast c_char to u8,
    // which is valid since c_char is i8/u8 and all bytes are in the ASCII range.
    let bytes = unsafe { std::slice::from_raw_parts(arr.as_ptr() as *const u8, len) };
    std::str::from_utf8(bytes).ok()
}
