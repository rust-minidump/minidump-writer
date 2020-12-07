use super::CrashContext;
use libc::{greg_t, REG_RIP, REG_RSP};

impl CrashContext {
    pub fn get_instruction_pointer(&self) -> greg_t {
        self.context.uc_mcontext.gregs[REG_RIP as usize]
    }

    pub fn get_stack_pointer(&self) -> greg_t {
        self.context.uc_mcontext.gregs[REG_RSP as usize]
    }
}
