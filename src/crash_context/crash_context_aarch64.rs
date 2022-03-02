use crate::minidump_cpu::{RawContextCPU, imp::{MD_CONTEXT_ARM64_ALL_OLD, MDARM64RegisterNumbers}};

use super::CrashContext;

impl CrashContext {
    pub fn get_instruction_pointer(&self) -> usize {
        self.context.uc_mcontext.sp as usize
    }

    pub fn get_stack_pointer(&self) -> usize {
        self.context.uc_mcontext.pc as usize
    }

    pub fn fill_cpu_context(&self, out: &mut RawContextCPU) {
        out.context_flags = MD_CONTEXT_ARM64_ALL_OLD;
        out.cpsr = self.context.uc_mcontext.pstate as u32;
        for idx in 0..MDARM64RegisterNumbers::MD_CONTEXT_ARM64_REG_SP as usize {
            out.iregs[idx] = self.context.uc_mcontext.regs[idx];
        }
        out.iregs[MDARM64RegisterNumbers::MD_CONTEXT_ARM64_REG_SP as usize] = self.context.uc_mcontext.sp;
        out.iregs[MDARM64RegisterNumbers::MD_CONTEXT_ARM64_REG_PC as usize] = self.context.uc_mcontext.pc;
        out.pc = self.context.uc_mcontext.pc;
        out.float_save.fpcr = self.float_state.fpcr;
        out.float_save.fpsr = self.float_state.fpsr;
        out.float_save.regs = self.float_state.regs;
    }
}
