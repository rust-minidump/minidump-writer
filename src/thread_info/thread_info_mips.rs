use super::Pid;
use libc;

#[derive(Debug)]
pub struct ThreadInfoMips {
    pub stack_pointer: libc::c_ulonglong,
    pub tgid: Pid, // thread group id
    pub ppid: Pid, // parent process
    // Use the structure defined in <sys/ucontext.h>
    pub mcontext: libc::mcontext_t,
}

impl ThreadInfoMips {
    #[cfg(target_arch = "mips")]
    pub fn get_instruction_pointer(&self) -> libc::c_ulonglong {
        self.mcontext.pc
    }
}
