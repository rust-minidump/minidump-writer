use super::CrashContext;
use crate::{minidump_cpu::RawContextCPU, minidump_format::format};

impl CrashContext {
    pub fn get_instruction_pointer(&self) -> usize {
        self.context.uc_mcontext.pc as usize
    }

    pub fn get_stack_pointer(&self) -> usize {
        self.context.uc_mcontext.sp as usize
    }

    pub fn fill_cpu_context(&self, out: &mut RawContextCPU) {
        out.context_flags = format::ContextFlagsArm64Old::CONTEXT_ARM64_FULL_OLD.bits() as u64;

        out.cpsr = self.context.uc_mcontext.pstate as u32;
        out.iregs[..31].copy_from_slice(&self.context.uc_mcontext.regs[..31]);
        out.iregs[31] = self.context.uc_mcontext.sp;
        out.pc = self.context.uc_mcontext.pc;

        out.float_save.fpsr = self.float_state.fpsr;
        out.float_save.fpcr = self.float_state.fpcr;
        out.float_save.regs[..16].copy_from_slice(&self.float_state.vregs[..16]);
    }
}
