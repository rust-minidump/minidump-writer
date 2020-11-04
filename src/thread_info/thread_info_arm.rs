use super::Pid;
use libc;

#[derive(Debug)]
pub struct ThreadInfoArm {
    pub stack_pointer: libc::c_ulonglong,
    pub tgid: Pid, // thread group id
    pub ppid: Pid, // parent process
    pub regs: libc::user_regs,
    pub fpregs: libc::user_fpregs,
}

impl ThreadInfoArm {
    #[cfg(target_arch = "arm")]
    pub fn get_instruction_pointer(&self) -> libc::c_ulonglong {
        self.regs.uregs[15]
    }
}
