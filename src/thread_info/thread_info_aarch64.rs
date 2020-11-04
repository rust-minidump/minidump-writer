use super::Pid;
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
}
