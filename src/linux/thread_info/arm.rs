use {
    super::{Pid, PtraceRequestType, ThreadInfoError},
    crate::minidump_cpu::RawContextCPU,
};

type Result<T> = std::result::Result<T, ThreadInfoError>;

// Not defined by libc because this works only for cores support VFP
#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Debug, Eq, Hash, PartialEq, Copy, Clone, Default)]
pub struct user_fpregs_struct {
    pub fpregs: [u64; 32],
    pub fpscr: u32,
}

#[repr(C)]
#[derive(Debug, Eq, Hash, PartialEq, Copy, Clone, Default)]
pub struct user_regs_struct {
    uregs: [u32; 18],
}

#[derive(Debug)]
pub struct ThreadInfoArm {
    pub stack_pointer: usize,
    pub tgid: Pid, // thread group id
    pub ppid: Pid, // parent process
    pub regs: user_regs_struct,
    pub fpregs: user_fpregs_struct,
}

impl ThreadInfoArm {
    fn getfpregs(pid: Pid) -> Result<user_fpregs_struct> {
        const NT_ARM_VFP: usize = 0x400;
        super::ptrace_getregset(NT_ARM_VFP, pid)
    }

    fn getregs(pid: Pid) -> Result<user_regs_struct> {
        const PTRACE_GETREGS: PtraceRequestType = 12;
        unsafe { super::ptrace_getregs::<user_regs_struct>(PTRACE_GETREGS, pid) }
    }

    pub fn get_instruction_pointer(&self) -> usize {
        self.regs.uregs[15] as usize
    }

    pub fn fill_cpu_context(&self, out: &mut RawContextCPU) {
        out.context_flags =
            crate::minidump_format::format::ContextFlagsArm::CONTEXT_ARM_FULL.bits();

        out.iregs.copy_from_slice(&self.regs.uregs[..16]);
        out.cpsr = self.regs.uregs[16];
        out.float_save.fpscr = self.fpregs.fpscr as u64;
        out.float_save.regs = self.fpregs.fpregs;
    }

    pub fn create(_pid: Pid, tid: Pid) -> Result<Self> {
        let (ppid, tgid) = super::get_ppid_and_tgid(tid)?;
        let regs = Self::getregs(tid)?;
        let fpregs = Self::getfpregs(tid).unwrap_or(Default::default());

        let stack_pointer = regs.uregs[13] as usize;

        Ok(ThreadInfoArm {
            stack_pointer,
            tgid,
            ppid,
            regs,
            fpregs,
        })
    }
}
