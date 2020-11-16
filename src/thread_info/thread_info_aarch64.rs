use super::Pid;
use crate::minidump_cpu::imp::{MDARM64RegisterNumbers, MD_FLOATINGSAVEAREA_ARM64_FPR_COUNT};
use libc;

#[cfg(target_arch = "aarch64")]
#[derive(Debug)]
pub struct ThreadInfoAarch64 {
    pub stack_pointer: libc::c_ulonglong,
    pub tgid: Pid, // thread group id
    pub ppid: Pid, // parent process
    pub regs: libc::user_regs_struct,
    pub fpregs: libc::user_fpsimd_struct,
}

impl ThreadInfoAarch64 {
    pub fn get_instruction_pointer(&self) -> libc::c_ulonglong {
        self.regs.pc
    }

    pub fn fill_cpu_context(&self, out: &mut RawContextCPU) {
        // out->context_flags = MD_CONTEXT_ARM64_FULL_OLD;
        out.cpsr = self.regs.pstate as u32;
        for idx in 0..MDARM64RegisterNumbers::MD_CONTEXT_ARM64_REG_SP {
            out.iregs[idx] = self.regs.regs[idx];
        }
        out.iregs[MDARM64RegisterNumbers::MD_CONTEXT_ARM64_REG_SP] = self.regs.sp;
        out.iregs[MDARM64RegisterNumbers::MD_CONTEXT_ARM64_REG_PC] = self.regs.pc;
        out.float_save.fpsr = self.fpregs.fpsr;
        out.float_save.fpcr = self.fpregs.fpcr;

        // my_memcpy(&out->float_save.regs, &fpregs.vregs,
        //     MD_FLOATINGSAVEAREA_ARM64_FPR_COUNT * 16);
        unsafe {
            std::ptr::copy(
                &std::mem::transmute::<&[u32], [u8; MD_FLOATINGSAVEAREA_ARM64_FPR_COUNT * 16]>(
                    &self.fpregs.vregs,
                ),
                out.float_save.regs,
                MD_FLOATINGSAVEAREA_ARM64_FPR_COUNT * 16,
            )
        }
    }
}
