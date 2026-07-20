use {
    super::x86_64_regs::{Fpregs, apply_fpregs_to_context, reg_to_minidump_context},
    super::{Pid, ProcessInspector, Result, ThreadInfoError},
    crate::minidump_cpu::RawContextCPU,
};

pub struct ThreadInfoX86 {
    pub tid: Pid,
    pub stack_pointer: usize,
    pub name: Option<String>,
    pub registers: RawContextCPU,
    pub fpregs: Fpregs,
}

impl ThreadInfoX86 {
    pub fn getregs(process_inspector: &ProcessInspector, pid: Pid) -> Result<RawContextCPU> {
        let reg = process_inspector
            .get_gen_regs(pid)
            .map_err(ThreadInfoError::PtraceError)?;
        Ok(reg_to_minidump_context(&reg))
    }

    pub fn getfpregs(process_inspector: &ProcessInspector, pid: Pid) -> Result<Fpregs> {
        process_inspector
            .get_fp_regs(pid)
            .map_err(ThreadInfoError::PtraceError)
    }

    pub fn get_stack_pointer(&self) -> usize {
        self.stack_pointer
    }

    pub fn get_instruction_pointer(&self) -> usize {
        self.registers.rip as usize
    }

    pub fn apply_fpregs_to_context(context: &mut RawContextCPU, fpregs: &Fpregs) {
        apply_fpregs_to_context(context, fpregs);
    }
}
