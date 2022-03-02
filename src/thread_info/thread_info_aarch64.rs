use super::{Pid, CommonThreadInfo};
use crate::errors::ThreadInfoError;
use crate::minidump_cpu::imp::{MDARM64RegisterNumbers, MD_FLOATINGSAVEAREA_ARM64_FPR_COUNT, libc_user_fpsimd_struct, MD_CONTEXT_ARM64_OLD, MD_CONTEXT_ARM64_ALL_OLD};
use crate::minidump_cpu::RawContextCPU;
use libc;
use nix::sys::ptrace;

type Result<T> = std::result::Result<T, ThreadInfoError>;

#[cfg(target_arch = "aarch64")]
#[derive(Debug)]
pub struct ThreadInfoAarch64 {
    pub stack_pointer: libc::c_ulonglong,
    pub tgid: Pid, // thread group id
    pub ppid: Pid, // parent process
    pub regs: libc::user_regs_struct,
    pub fpregs: libc_user_fpsimd_struct,
}

impl CommonThreadInfo for ThreadInfoAarch64 {}

impl ThreadInfoAarch64 {
    // nix currently doesn't support PTRACE_GETFPREGS, so we have to do it ourselves
    fn getfpregs(pid: Pid) -> Result<libc_user_fpsimd_struct> {
        Self::ptrace_get_data::<libc_user_fpsimd_struct>(
            ptrace::Request::PTRACE_GETFPREGS,
            None,
            nix::unistd::Pid::from_raw(pid),
        )
    }

    // nix currently doesn't support PTRACE_GETFPREGS, so we have to do it ourselves
    fn getregs(pid: Pid) -> Result<libc::user_regs_struct> {
        Self::ptrace_get_data::<libc::user_regs_struct>(
            ptrace::Request::PTRACE_GETFPREGS,
            None,
            nix::unistd::Pid::from_raw(pid),
        )
    }

    pub fn get_instruction_pointer(&self) -> libc::c_ulonglong {
        self.regs.pc
    }

    pub fn fill_cpu_context(&self, out: &mut RawContextCPU) {
        out.context_flags = MD_CONTEXT_ARM64_ALL_OLD;
        out.cpsr = self.regs.pstate as u32;
        for idx in 0..MDARM64RegisterNumbers::MD_CONTEXT_ARM64_REG_SP as usize {
            out.iregs[idx] = self.regs.regs[idx];
        }
        out.iregs[MDARM64RegisterNumbers::MD_CONTEXT_ARM64_REG_SP as usize] = self.regs.sp;
        out.iregs[MDARM64RegisterNumbers::MD_CONTEXT_ARM64_REG_PC as usize] = self.regs.pc;
        out.pc = self.regs.pc;
        out.float_save.fpcr = self.fpregs.fpcr;
        out.float_save.fpsr = self.fpregs.fpsr;
        out.float_save.regs = self.fpregs.regs;
    }
    pub fn create_impl(_pid: Pid, tid: Pid) -> Result<Self> {
        let (ppid, tgid) = Self::get_ppid_and_tgid(tid)?;
        let regs = Self::getregs(tid)?;
        let fpregs = Self::getfpregs(tid)?;

        let stack_pointer = regs.uregs[13] as usize;

        Ok(ThreadInfoAarch64 {
            stack_pointer,
            tgid,
            ppid,
            regs,
            fpregs,
        })
    }
}