use minidump_common::format::*;
#[cfg(target_arch = "x86_64")]
pub type RawContextCPU = MDRawContextAMD64;
#[cfg(target_arch = "x86")]
pub type RawContextCPU = MDRawContextX86;
#[cfg(target_arch = "arm")]
pub type RawContextCPU = MDRawContextARM;
#[cfg(target_arch = "aarch64")]
pub type RawContextCPU = MDRawContextX86;
#[cfg(target_arch = "mips")]
pub type RawContextCPU = MDRawContextMIPS;

pub const MD_CONTEXT_AMD64_CONTROL: u32 = MD_CONTEXT_AMD64 | 0x00000001;
/* CONTEXT_CONTROL */
pub const MD_CONTEXT_AMD64_INTEGER: u32 = MD_CONTEXT_AMD64 | 0x00000002;
/* CONTEXT_INTEGER */
pub const MD_CONTEXT_AMD64_SEGMENTS: u32 = MD_CONTEXT_AMD64 | 0x00000004;
/* CONTEXT_SEGMENTS */
pub const MD_CONTEXT_AMD64_FLOATING_POINT: u32 = MD_CONTEXT_AMD64 | 0x00000008;
/* CONTEXT_FLOATING_POINT */
pub const MD_CONTEXT_AMD64_DEBUG_REGISTERS: u32 = MD_CONTEXT_AMD64 | 0x00000010;
/* CONTEXT_DEBUG_REGISTERS */
pub const MD_CONTEXT_AMD64_XSTATE: u32 = MD_CONTEXT_AMD64 | 0x00000040;
/* CONTEXT_XSTATE */

/* WinNT.h refers to CONTEXT_MMX_REGISTERS but doesn't appear to define it
* I think it really means CONTEXT_FLOATING_POINT.
*/

pub const MD_CONTEXT_AMD64_FULL: u32 =
    MD_CONTEXT_AMD64_CONTROL | MD_CONTEXT_AMD64_INTEGER | MD_CONTEXT_AMD64_FLOATING_POINT;
/* CONTEXT_FULL */

pub const MD_CONTEXT_AMD64_ALL: u32 =
    MD_CONTEXT_AMD64_FULL | MD_CONTEXT_AMD64_SEGMENTS | MD_CONTEXT_AMD64_DEBUG_REGISTERS;
/* CONTEXT_ALL */
