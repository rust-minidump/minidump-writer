use {
    super::CrashContext,
    crate::{
        freebsd::thread_info::x86_64_regs::copy_float_save_to_context, minidump_cpu::RawContextCPU,
        minidump_format::format,
    },
};

impl CrashContext {
    pub fn get_instruction_pointer(&self) -> usize {
        self.ucontext.uc_mcontext.mc_rip as usize
    }

    pub fn get_stack_pointer(&self) -> usize {
        self.ucontext.uc_mcontext.mc_rsp as usize
    }

    pub fn fill_cpu_context(&self, out: &mut RawContextCPU) {
        let mc = &self.ucontext.uc_mcontext;

        *out = RawContextCPU {
            context_flags: format::ContextFlagsAmd64::CONTEXT_AMD64_FULL.bits()
                | format::ContextFlagsAmd64::CONTEXT_AMD64_SEGMENTS.bits(),
            cs: mc.mc_cs as u16,
            fs: mc.mc_fs,
            gs: mc.mc_gs,
            es: mc.mc_es,
            ds: mc.mc_ds,
            ss: mc.mc_ss as u16,
            eflags: mc.mc_rflags as u32,
            rax: mc.mc_rax as u64,
            rcx: mc.mc_rcx as u64,
            rdx: mc.mc_rdx as u64,
            rbx: mc.mc_rbx as u64,
            rsp: mc.mc_rsp as u64,
            rbp: mc.mc_rbp as u64,
            rsi: mc.mc_rsi as u64,
            rdi: mc.mc_rdi as u64,
            r8: mc.mc_r8 as u64,
            r9: mc.mc_r9 as u64,
            r10: mc.mc_r10 as u64,
            r11: mc.mc_r11 as u64,
            r12: mc.mc_r12 as u64,
            r13: mc.mc_r13 as u64,
            r14: mc.mc_r14 as u64,
            r15: mc.mc_r15 as u64,
            rip: mc.mc_rip as u64,
            ..Default::default()
        };

        // Even when the process uses XSAVE, the kernel reports
        // `_MC_FPFMT_XMM` for signal contexts and `mc_fpstate` carries an
        // FXSAVE-compatible image (extended state lives in `mc_xfpustate`).
        if mc.mc_fpformat == libc::_MC_FPFMT_XMM {
            // SAFETY: FreeBSD stores the signal-time XMM/FXSAVE payload in
            // mc_fpstate when mc_fpformat identifies that format.
            let bytes = unsafe {
                std::slice::from_raw_parts(
                    mc.mc_fpstate.as_ptr() as *const u8,
                    std::mem::size_of_val(&mc.mc_fpstate),
                )
            };
            copy_float_save_to_context(out, bytes);
        }
    }
}
