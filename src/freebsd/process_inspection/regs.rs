#[cfg(target_arch = "x86_64")]
pub(super) type GenRegs = libc::reg;

#[cfg(target_arch = "x86_64")]
pub(super) type FpRegs = libc::fpreg;
