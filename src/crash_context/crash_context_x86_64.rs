use crate::minidump_cpu::imp::*;

use crate::thread_info::to_u128;
use libc::{
    REG_CSGSFS, REG_EFL, REG_R10, REG_R11, REG_R12, REG_R13, REG_R14, REG_R15, REG_R8, REG_R9,
    REG_RAX, REG_RBP, REG_RBX, REG_RCX, REG_RDI, REG_RDX, REG_RIP, REG_RSI, REG_RSP,
};

impl super::CpuContext for super::CrashContext {
    fn get_instruction_pointer(&self) -> usize {
        self.context.uc_mcontext.gregs[REG_RIP as usize] as usize
    }

    fn get_stack_pointer(&self) -> usize {
        self.context.uc_mcontext.gregs[REG_RSP as usize] as usize
    }

    fn fill_cpu_context(&self, out: &mut super::RawContextCPU) {
        out.context_flags = MD_CONTEXT_AMD64_FULL;

        {
            let gregs = &self.context.uc_mcontext.gregs;
            out.cs = (gregs[REG_CSGSFS as usize] & 0xffff) as u16;

            out.fs = ((gregs[REG_CSGSFS as usize] >> 32) & 0xffff) as u16;
            out.gs = ((gregs[REG_CSGSFS as usize] >> 16) & 0xffff) as u16;

            out.eflags = gregs[REG_EFL as usize] as u32;

            out.rax = gregs[REG_RAX as usize] as u64;
            out.rcx = gregs[REG_RCX as usize] as u64;
            out.rdx = gregs[REG_RDX as usize] as u64;
            out.rbx = gregs[REG_RBX as usize] as u64;

            out.rsp = gregs[REG_RSP as usize] as u64;
            out.rbp = gregs[REG_RBP as usize] as u64;
            out.rsi = gregs[REG_RSI as usize] as u64;
            out.rdi = gregs[REG_RDI as usize] as u64;
            out.r8 = gregs[REG_R8 as usize] as u64;
            out.r9 = gregs[REG_R9 as usize] as u64;
            out.r10 = gregs[REG_R10 as usize] as u64;
            out.r11 = gregs[REG_R11 as usize] as u64;
            out.r12 = gregs[REG_R12 as usize] as u64;
            out.r13 = gregs[REG_R13 as usize] as u64;
            out.r14 = gregs[REG_R14 as usize] as u64;
            out.r15 = gregs[REG_R15 as usize] as u64;

            out.rip = gregs[REG_RIP as usize] as u64;
        }

        {
            let fs = &self.float_state;
            out.flt_save.control_word = fs.cwd;
            out.flt_save.status_word = fs.swd;
            out.flt_save.tag_word = fs.ftw as u8;
            out.flt_save.error_opcode = fs.fop;
            out.flt_save.error_offset = fs.rip as u32;
            out.flt_save.data_offset = fs.rdp as u32;
            out.flt_save.error_selector = 0; // We don't have this.
            out.flt_save.data_selector = 0; // We don't have this.
            out.flt_save.mx_csr = fs.mxcsr;
            out.flt_save.mx_csr_mask = fs.mxcr_mask;

            let data = to_u128(&fs.st_space);
            for idx in 0..data.len() {
                out.flt_save.float_registers[idx] = data[idx];
            }

            let data = to_u128(&fs.xmm_space);
            for idx in 0..data.len() {
                out.flt_save.xmm_registers[idx] = data[idx];
            }
        }
    }
}
