use crate::minidump_cpu::RawContextCPU;
use libc;
type Pid = u32;

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[derive(Debug)]
struct ThreadInfo {
    stack_pointer: libc::c_ulonglong,
    tgid: Pid, // thread group id
    ppid: Pid, // parent process
    regs: libc::user_regs_struct,
    fpregs: libc::user_fpregs_struct,
    #[cfg(target_arch = "x86_64")]
    dregs: [libc::c_ulonglong; 8],
    #[cfg(target_arch = "x86")]
    dregs: [libc::c_int; 8],
    #[cfg(target_arch = "x86")]
    fpxregs: libc::user_fpxregs_struct,
}

#[cfg(target_arch = "aarch64")]
#[derive(Debug)]
struct ThreadInfo {
    stack_pointer: libc::c_ulonglong,
    tgid: Pid, // thread group id
    ppid: Pid, // parent process
    regs: libc::user_regs_struct,
    fpregs: libc::user_fpsimd_struct,
}

#[cfg(target_arch = "arm")]
#[derive(Debug)]
struct ThreadInfo {
    stack_pointer: libc::c_ulonglong,
    tgid: Pid, // thread group id
    ppid: Pid, // parent process
    regs: libc::user_regs,
    fpregs: libc::user_fpregs,
}

#[cfg(target_arch = "mips")]
#[derive(Debug)]
struct ThreadInfo {
    stack_pointer: libc::c_ulonglong,
    tgid: Pid, // thread group id
    ppid: Pid, // parent process
    // Use the structure defined in <sys/ucontext.h>
    mcontext: libc::mcontext_t,
}

impl ThreadInfo {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    const NUM_DEBUG_REGISTERS: u32 = 8;

    #[cfg(target_arch = "x86_64")]
    fn get_instruction_pointer(&self) -> libc::c_ulonglong {
        self.regs.rip
    }

    #[cfg(target_arch = "x86")]
    fn get_instruction_pointer(&self) -> libc::c_ulonglong {
        self.regs.eip
    }

    #[cfg(target_arch = "arm")]
    fn get_instruction_pointer(&self) -> libc::c_ulonglong {
        self.regs.uregs[15]
    }

    #[cfg(target_arch = "aarch64")]
    fn get_instruction_pointer(&self) -> libc::c_ulonglong {
        self.regs.pc
    }

    #[cfg(target_arch = "mips")]
    fn get_instruction_pointer(&self) -> libc::c_ulonglong {
        self.mcontext.pc
    }

    #[cfg(target_arch = "x86_64")]
    fn fill_cpu_context(&self, out: &mut RawContextCPU) {
        // out.context_flags = self.MD_CONTEXT_AMD64_FULL |
        //                      MD_CONTEXT_AMD64_SEGMENTS;

        out.cs = self.regs.cs as u16; // TODO: This is u64, do we loose information by doing this?

        out.ds = self.regs.ds as u16; // TODO: This is u64, do we loose information by doing this?
        out.es = self.regs.es as u16; // TODO: This is u64, do we loose information by doing this?
        out.fs = self.regs.fs as u16; // TODO: This is u64, do we loose information by doing this?
        out.gs = self.regs.gs as u16; // TODO: This is u64, do we loose information by doing this?

        out.ss = self.regs.ss as u16; // TODO: This is u64, do we loose information by doing this?
        out.eflags = self.regs.eflags as u32; // TODO: This is u64, do we loose information by doing this?

        out.dr0 = self.dregs[0];
        out.dr1 = self.dregs[1];
        out.dr2 = self.dregs[2];
        out.dr3 = self.dregs[3];
        // 4 and 5 deliberatly omitted because they aren't included in the minidump
        // format.
        out.dr6 = self.dregs[6];
        out.dr7 = self.dregs[7];

        out.rax = self.regs.rax;
        out.rcx = self.regs.rcx;
        out.rdx = self.regs.rdx;
        out.rbx = self.regs.rbx;

        out.rsp = self.regs.rsp;

        out.rbp = self.regs.rbp;
        out.rsi = self.regs.rsi;
        out.rdi = self.regs.rdi;
        out.r8 = self.regs.r8;
        out.r9 = self.regs.r9;
        out.r10 = self.regs.r10;
        out.r11 = self.regs.r11;
        out.r12 = self.regs.r12;
        out.r13 = self.regs.r13;
        out.r14 = self.regs.r14;
        out.r15 = self.regs.r15;

        out.rip = self.regs.rip;

        out.flt_save.control_word = self.fpregs.cwd;
        out.flt_save.status_word = self.fpregs.swd;
        out.flt_save.tag_word = self.fpregs.ftw as u8; // TODO: This is u16, do we loose information by doing this?
        out.flt_save.error_opcode = self.fpregs.fop;
        out.flt_save.error_offset = self.fpregs.rip as u32; // TODO: This is u64, do we loose information by doing this?
        out.flt_save.error_selector = 0; // We don't have this.
        out.flt_save.data_offset = self.fpregs.rdp as u32; // TODO: This is u64, do we loose information by doing this?
        out.flt_save.data_selector = 0; // We don't have this.
        out.flt_save.mx_csr = self.fpregs.mxcsr;
        out.flt_save.mx_csr_mask = self.fpregs.mxcr_mask;
        // unsafe {
        //     std::ptr::copy(
        //         &self.fpregs.st_space,
        //         &mut out.flt_save.float_registers as &mut [u32; 32],
        //         8 * 16,
        //     );
        // }
        // my_memcpy(&out.flt_save.float_registers, &self.fpregs.st_space, 8 * 16);
        // my_memcpy(&out.flt_save.xmm_registers, &self.fpregs.xmm_space, 16 * 16);
    }
}
