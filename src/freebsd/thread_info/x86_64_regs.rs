use crate::{minidump_cpu::RawContextCPU, minidump_format::format};

pub type Reg = libc::reg;
pub type Fpregs = libc::fpreg;

#[allow(clippy::field_reassign_with_default)]
pub fn reg_to_minidump_context(reg: &Reg) -> RawContextCPU {
    let mut context = RawContextCPU::default();

    context.context_flags = format::ContextFlagsAmd64::CONTEXT_AMD64_FULL.bits()
        | format::ContextFlagsAmd64::CONTEXT_AMD64_SEGMENTS.bits();

    context.rax = reg.r_rax as u64;
    context.rcx = reg.r_rcx as u64;
    context.rdx = reg.r_rdx as u64;
    context.rbx = reg.r_rbx as u64;
    context.rsp = reg.r_rsp as u64;
    context.rbp = reg.r_rbp as u64;
    context.rsi = reg.r_rsi as u64;
    context.rdi = reg.r_rdi as u64;
    context.r8 = reg.r_r8 as u64;
    context.r9 = reg.r_r9 as u64;
    context.r10 = reg.r_r10 as u64;
    context.r11 = reg.r_r11 as u64;
    context.r12 = reg.r_r12 as u64;
    context.r13 = reg.r_r13 as u64;
    context.r14 = reg.r_r14 as u64;
    context.r15 = reg.r_r15 as u64;
    context.rip = reg.r_rip as u64;

    context.eflags = reg.r_rflags as u32;
    context.cs = reg.r_cs as u16;
    context.ds = reg.r_ds;
    context.es = reg.r_es;
    context.fs = reg.r_fs;
    context.gs = reg.r_gs;
    context.ss = reg.r_ss as u16;

    context
}

pub fn apply_fpregs_to_context(context: &mut RawContextCPU, fpregs: &Fpregs) {
    // SAFETY: `libc::fpreg` is FreeBSD's PT_GETFPREGS ABI payload. It is a
    // plain C register-save area, and copying its initialized bytes preserves
    // the kernel-provided FXSAVE-compatible data verbatim.
    let bytes = unsafe {
        std::slice::from_raw_parts(
            fpregs as *const Fpregs as *const u8,
            std::mem::size_of::<Fpregs>(),
        )
    };
    copy_float_save_to_context(context, bytes);
}

pub fn copy_float_save_to_context(context: &mut RawContextCPU, bytes: &[u8]) {
    let len = std::cmp::min(context.float_save.len(), bytes.len());
    context.float_save[..len].copy_from_slice(&bytes[..len]);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reg_abi_size() {
        assert_eq!(std::mem::size_of::<Reg>(), 176);
    }

    #[test]
    fn test_fpregs_abi_size() {
        assert_eq!(std::mem::size_of::<Fpregs>(), 512);
    }

    #[test]
    fn test_reg_conversion() {
        let reg = Reg {
            r_r15: 1,
            r_r14: 2,
            r_r13: 3,
            r_r12: 4,
            r_r11: 5,
            r_r10: 6,
            r_r9: 7,
            r_r8: 8,
            r_rdi: 9,
            r_rsi: 10,
            r_rbp: 11,
            r_rbx: 12,
            r_rdx: 13,
            r_rcx: 14,
            r_rax: 15,
            r_trapno: 16,
            r_fs: 17,
            r_gs: 18,
            r_err: 19,
            r_es: 20,
            r_ds: 21,
            r_rip: 22,
            r_cs: 23,
            r_rflags: 24,
            r_rsp: 25,
            r_ss: 26,
        };

        let context = reg_to_minidump_context(&reg);

        assert_eq!(context.r15, 1);
        assert_eq!(context.r14, 2);
        assert_eq!(context.r13, 3);
        assert_eq!(context.r12, 4);
        assert_eq!(context.r11, 5);
        assert_eq!(context.r10, 6);
        assert_eq!(context.r9, 7);
        assert_eq!(context.r8, 8);
        assert_eq!(context.rdi, 9);
        assert_eq!(context.rsi, 10);
        assert_eq!(context.rbp, 11);
        assert_eq!(context.rbx, 12);
        assert_eq!(context.rdx, 13);
        assert_eq!(context.rcx, 14);
        assert_eq!(context.rax, 15);
        assert_eq!(context.fs, 17);
        assert_eq!(context.gs, 18);
        assert_eq!(context.es, 20);
        assert_eq!(context.ds, 21);
        assert_eq!(context.rip, 22);
        assert_eq!(context.cs, 23);
        assert_eq!(context.eflags, 24);
        assert_eq!(context.rsp, 25);
        assert_eq!(context.ss, 26);
    }
}
