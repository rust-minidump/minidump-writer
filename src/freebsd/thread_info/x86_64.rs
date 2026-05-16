use {
    super::x86_64_regs::{Fpregs, Reg, apply_fpregs_to_context, reg_to_minidump_context},
    super::{Pid, Result, ThreadInfoError},
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
    pub fn getregs(pid: Pid) -> Result<RawContextCPU> {
        let mut reg = std::mem::MaybeUninit::<Reg>::uninit();
        // SAFETY: ptrace operates on the target pid which has been validated.
        // PT_GETREGS fills the provided buffer with register data on success.
        let res = unsafe {
            libc::ptrace(
                libc::PT_GETREGS,
                pid,
                reg.as_mut_ptr() as *mut libc::c_char,
                0,
            )
        };
        if res == -1 {
            return Err(ThreadInfoError::PtraceError(std::io::Error::last_os_error()));
        }
        // SAFETY: ptrace returned success, so the kernel has fully initialized
        // the Reg struct with valid register data.
        let reg = unsafe { reg.assume_init() };
        Ok(reg_to_minidump_context(&reg))
    }

    pub fn getfpregs(pid: Pid) -> Result<Fpregs> {
        let mut fpregs = std::mem::MaybeUninit::<Fpregs>::uninit();
        // SAFETY: ptrace operates on the target pid which has been validated.
        // PT_GETFPREGS fills the provided buffer with floating-point register data on success.
        let res = unsafe {
            libc::ptrace(
                libc::PT_GETFPREGS,
                pid,
                fpregs.as_mut_ptr() as *mut libc::c_char,
                0,
            )
        };
        if res == -1 {
            return Err(ThreadInfoError::PtraceError(std::io::Error::last_os_error()));
        }
        // SAFETY: ptrace returned success, so the kernel has fully initialized
        // the Fpregs struct with valid floating-point register data.
        Ok(unsafe { fpregs.assume_init() })
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
