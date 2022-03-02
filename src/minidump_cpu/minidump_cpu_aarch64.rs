/// A u128 that matches the layout of uint128_t for C FFI purposes
/// **BUT NOT THE ABI**. This is safe for pass-by-ref but not pass-by-value.
///
/// Rust underaligns u128 compared to C's ABI due to a long-standing llvm bug.
/// Unfortuantely library code *can't* perfectly work around this, because
/// primitives have magic ABIs.
/// 
/// Although repr(transparent) *exists* to preserve the magic ABI of primitives,
/// you can't combine this with other reprs (which makes a kind of sense),
/// and we need to apply repr(align(16)).
/// 
/// The upshot of this is that this type (or a struct containing it) can be
/// passed *by-reference* to C, but if you try to pass it *by-value* then
/// the ABI might not match and this value may not be passed to the function
/// right.
/// 
/// This is good enough for our purposes, because we largely just want this
/// for APIs like linux's getcontext which does in fact work by-reference.
/// 
/// See "i128 / u128 are not compatible with C's definition."
/// https://github.com/rust-lang/rust/issues/54341
#[repr(C, align(16))]
#[derive(Debug, Copy, Clone, Default)]
#[allow(non_camel_case_types)]
pub struct layout_only_ffi_u128(u128);

impl layout_only_ffi_u128 {
    pub fn to_ne_bytes(self) -> [u8; 16] {
        self.0.to_ne_bytes()
    }
}

pub const MD_FLOATINGSAVEAREA_ARM64_FPR_COUNT: usize = 32;
pub const MD_CONTEXT_ARM64_GPR_COUNT: usize = 33;



/* Indices into iregs for registers with a dedicated or conventional
 * purpose.
 */
#[allow(non_camel_case_types)]
pub enum MDARM64RegisterNumbers {
    MD_CONTEXT_ARM64_REG_FP = 29,
    MD_CONTEXT_ARM64_REG_LR = 30,
    MD_CONTEXT_ARM64_REG_SP = 31,
    MD_CONTEXT_ARM64_REG_PC = 32,
}

/* Windows only?
#[repr(C)]
#[derive(Default)]
pub struct MDRawContextARM64 {
    pub context_flags: u32,
    pub cpsr: u32,
    pub iregs: [u64; 32],
    pub pc: u64,
    pub float_save: libc_user_fpsimd_struct,
    pub bcr: [u32; 8],
    pub bvr: [u64; 8],
    pub wcr: [u32; 2],
    pub wvr: [u64; 2],
}
*/

#[repr(C)]
#[derive(Default)]
pub struct MDRawContextARM64Old {
    pub context_flags: u64,
    pub iregs: [u64; 32],
    pub pc: u64,
    pub cpsr: u32,
    pub float_save: FloatingSaveAreaARM64Old,
}

/// aarch64 floating point state
#[repr(C)]
#[derive(Debug, Copy, Clone, Default)]
#[allow(non_camel_case_types)]
pub struct libc_user_fpsimd_struct {
    pub regs: [layout_only_ffi_u128; 32usize],
    pub fpsr: u32,
    pub fpcr: u32,
}

/// aarch64 floating point state (old)
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct FloatingSaveAreaARM64Old {
    pub fpsr: u32,
    pub fpcr: u32,
    pub regs: [layout_only_ffi_u128; 32usize],
}

pub const MD_CONTEXT_ARM64: u32 = 0x400000;
pub const MD_CONTEXT_ARM64_OLD: u64 = 0x80000000;

pub const MD_CONTEXT_ARM64_ALL_OLD: u64 = MD_CONTEXT_ARM64_OLD | 0x2 | 0x4;

/*
/* For (MDRawContextARM64_Old).context_flags.  These values indicate the type of
 * context stored in the structure. MD_CONTEXT_ARM64_OLD is Breakpad-defined.
 * This value was chosen to avoid likely conflicts with MD_CONTEXT_*
 * for other CPUs. */
#define MD_CONTEXT_ARM64_OLD                   0x80000000
#define MD_CONTEXT_ARM64_INTEGER_OLD           (MD_CONTEXT_ARM64_OLD | 0x00000002)
#define MD_CONTEXT_ARM64_FLOATING_POINT_OLD    (MD_CONTEXT_ARM64_OLD | 0x00000004)

#define MD_CONTEXT_ARM64_FULL_OLD              (MD_CONTEXT_ARM64_INTEGER_OLD | \
                                          MD_CONTEXT_ARM64_FLOATING_POINT_OLD)

#define MD_CONTEXT_ARM64_ALL_OLD               (MD_CONTEXT_ARM64_INTEGER_OLD | \
                                          MD_CONTEXT_ARM64_FLOATING_POINT_OLD)

*/