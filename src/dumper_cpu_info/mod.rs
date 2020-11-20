#[cfg(any(target_arch = "x86_64", target_arch = "x86", target_arch = "mips"))]
#[path = "cpu_info_x86_mips.rs"]
pub mod imp;
#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
#[path = "cpu_info_arm.rs"]
pub mod imp;

pub use imp::write_cpu_information;
