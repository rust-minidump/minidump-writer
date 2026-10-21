//! x86_64 thread state.

use {
    super::{
        Result, ThreadInfoError,
        x86_64_regs::{Fpregs, Reg, apply_fpregs_to_context, reg_to_minidump_context},
    },
    crate::{
        freebsd::{
            Pid,
            process_inspection::{FpRegs, GenRegs, ProcessInspector},
        },
        minidump_cpu::RawContextCPU,
    },
    error_graph::WriteErrorList,
};

pub struct ThreadInfoX86 {
    pub tid: Pid,
    pub stack_pointer: usize,
    pub registers: GenRegs,
    pub fpregs: Option<FpRegs>,
}

impl ThreadInfoX86 {
    /// Gathers the state of thread `tid` of the inspected process.
    ///
    /// A failure to read the floating-point registers is only recorded as a
    /// soft error (the general-purpose registers are required, the
    /// floating-point ones are not).
    pub fn create(
        process_inspector: &dyn ProcessInspector,
        tid: Pid,
        mut soft_errors: impl WriteErrorList<ThreadInfoError>,
    ) -> Result<Self> {
        let registers = process_inspector
            .get_gen_regs(tid)
            .map_err(ThreadInfoError::GetGenRegsFailed)?;

        let fpregs = match process_inspector
            .get_fp_regs(tid)
            .map_err(ThreadInfoError::GetFpRegsFailed)
        {
            Ok(regs) => Some(regs),
            Err(e) => {
                soft_errors.push(e);
                None
            }
        };

        let stack_pointer = registers.0.r_rsp as usize;

        Ok(Self {
            tid,
            stack_pointer,
            registers,
            fpregs,
        })
    }

    pub fn get_stack_pointer(&self) -> usize {
        self.stack_pointer
    }

    pub fn get_instruction_pointer(&self) -> usize {
        self.registers.0.r_rip as usize
    }

    /// Fills `out` with the thread's register state in minidump format.
    pub fn fill_cpu_context(&self, out: &mut RawContextCPU) {
        let reg: &Reg = &self.registers.0;
        *out = reg_to_minidump_context(reg);
        if let Some(fpregs) = &self.fpregs {
            let fpregs: &Fpregs = &fpregs.0;
            apply_fpregs_to_context(out, fpregs);
        }
    }
}
