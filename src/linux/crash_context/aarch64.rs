use super::CrashContext;
use crate::{
    minidump_cpu::{RawContextCPU, FP_REG_COUNT, GP_REG_COUNT},
    minidump_format::format,
};

impl CrashContext {
    pub fn get_instruction_pointer(&self) -> usize {
        self.context.uc_mcontext.pc as usize
    }

    pub fn get_stack_pointer(&self) -> usize {
        self.context.uc_mcontext.sp as usize
    }

    pub fn fill_cpu_context(&self, out: &mut RawContextCPU) {
        out.context_flags = format::ContextFlagsArm64Old::CONTEXT_ARM64_OLD_FULL.bits() as u64;

        out.cpsr = self.context.uc_mcontext.pstate as u32;
        out.iregs[..GP_REG_COUNT].copy_from_slice(&self.context.uc_mcontext.regs[..GP_REG_COUNT]);
        out.sp = self.context.uc_mcontext.sp;
        out.pc = self.context.uc_mcontext.pc;

        out.fpsr = self.float_state.fpsr;
        out.fpcr = self.float_state.fpcr;
        out.float_regs[..FP_REG_COUNT].copy_from_slice(&self.float_state.vregs[..FP_REG_COUNT]);
    }
}
