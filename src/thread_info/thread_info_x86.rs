use super::{CommonThreadInfo, Pid};
use crate::minidump_cpu::RawContextCPU;
use crate::Result;
use libc;
use nix::errno::Errno;
use nix::sys::ptrace;
use nix::unistd;

#[derive(Debug)]
pub struct ThreadInfoX86 {
    pub stack_pointer: libc::c_ulonglong,
    pub tgid: Pid, // thread group id
    pub ppid: Pid, // parent process
    pub regs: libc::user_regs_struct,
    pub fpregs: libc::user_fpregs_struct,
    #[cfg(target_arch = "x86_64")]
    pub dregs: [libc::c_ulonglong; 8],
    #[cfg(target_arch = "x86")]
    pub dregs: [libc::c_int; 8],
    #[cfg(target_arch = "x86")]
    pub fpxregs: libc::user_fpxregs_struct,
}

impl CommonThreadInfo for ThreadInfoX86 {}

#[derive(Debug)]
#[allow(non_camel_case_types)]
enum NT_Elf {
    NT_NONE = 0,
    NT_PRSTATUS = 1,
    NT_PRFPREG = 2,
    NT_PRPSINFO = 3,
    NT_TASKSTRUCT = 4,
    NT_AUXV = 6,
}

impl ThreadInfoX86 {
    pub const NUM_DEBUG_REGISTERS: u32 = 8;
    // nix currently doesn't support PTRACE_GETREGSET, so we have to do it ourselves
    fn getregset(pid: Pid) -> Result<libc::user_regs_struct> {
        Self::ptrace_get_data::<libc::user_regs_struct>(
            ptrace::Request::PTRACE_GETREGSET,
            Some(NT_Elf::NT_PRSTATUS),
            nix::unistd::Pid::from_raw(pid),
        )
    }

    // nix currently doesn't support PTRACE_GETREGSET, so we have to do it ourselves
    fn getfpregset(pid: Pid) -> Result<libc::user_fpregs_struct> {
        Self::ptrace_get_data::<libc::user_fpregs_struct>(
            ptrace::Request::PTRACE_GETREGSET,
            Some(NT_Elf::NT_PRFPREG),
            nix::unistd::Pid::from_raw(pid),
        )
    }

    // nix currently doesn't support PTRACE_GETREGSET, so we have to do it ourselves
    fn getfpregs(pid: Pid) -> Result<libc::user_fpregs_struct> {
        Self::ptrace_get_data::<libc::user_fpregs_struct>(
            ptrace::Request::PTRACE_GETFPREGS,
            None,
            nix::unistd::Pid::from_raw(pid),
        )
    }
    /// SLIGHTLY MODIFIED COPY FROM CRATE nix
    /// Function for ptrace requests that return values from the data field.
    /// Some ptrace get requests populate structs or larger elements than `c_long`
    /// and therefore use the data field to return values. This function handles these
    /// requests.
    fn ptrace_get_data<T>(
        request: ptrace::Request,
        flag: Option<NT_Elf>,
        pid: nix::unistd::Pid,
    ) -> Result<T> {
        let mut data = std::mem::MaybeUninit::uninit();
        let res = unsafe {
            libc::ptrace(
                request as ptrace::RequestType,
                libc::pid_t::from(pid),
                flag.unwrap_or(NT_Elf::NT_NONE),
                data.as_mut_ptr() as *const _ as *const libc::c_void,
            )
        };
        Errno::result(res)?;
        Ok(unsafe { data.assume_init() })
    }

    /// COPY FROM CRATE nix BECAUSE ITS NOT PUBLIC
    fn ptrace_peek(
        request: ptrace::Request,
        pid: unistd::Pid,
        addr: ptrace::AddressType,
        data: *mut libc::c_void,
    ) -> nix::Result<libc::c_long> {
        let ret = unsafe {
            Errno::clear();
            libc::ptrace(
                request as ptrace::RequestType,
                libc::pid_t::from(pid),
                addr,
                data,
            )
        };
        match Errno::result(ret) {
            Ok(..) | Err(nix::Error::Sys(Errno::UnknownErrno)) => Ok(ret),
            err @ Err(..) => err,
        }
    }

    fn peek_user(pid: Pid, addr: ptrace::AddressType) -> nix::Result<libc::c_long> {
        Self::ptrace_peek(
            ptrace::Request::PTRACE_PEEKUSER,
            nix::unistd::Pid::from_raw(pid),
            addr,
            std::ptr::null_mut(),
        )
    }

    pub fn create_impl(_pid: Pid, tid: Pid) -> Result<Self> {
        let (ppid, tgid) = Self::get_ppid_and_tgid(tid)?;
        let regs = Self::getregset(tid).or_else(|_| ptrace::getregs(unistd::Pid::from_raw(tid)))?;
        let fpregs = Self::getfpregset(tid).or_else(|_| Self::getfpregs(tid))?;

        // #if defined(__i386)
        // #if !defined(bit_FXSAVE)  // e.g. Clang
        // #define bit_FXSAVE bit_FXSR
        // #endif
        //   // Detect if the CPU supports the FXSAVE/FXRSTOR instructions
        //   int eax, ebx, ecx, edx;
        //   __cpuid(1, eax, ebx, ecx, edx);
        //   if (edx & bit_FXSAVE) {
        //     if (sys_ptrace(PTRACE_GETFPXREGS, tid, NULL, &info->fpxregs) == -1) {
        //       return false;
        //     }
        //   } else {
        //     memset(&info->fpxregs, 0, sizeof(info->fpxregs));
        //   }
        // #endif  // defined(__i386)
        #[cfg(target_arch = "x86_64")]
        let dregs: [libc::c_ulonglong; 8] = [0; 8];
        #[cfg(target_arch = "x86")]
        let dregs: [libc::c_int; 8] = [0; 8];

        // for idx in 0..Self::NUM_DEBUG_REGISTERS {}
        // for (unsigned i = 0; i < ThreadInfo::kNumDebugRegisters; ++i) {
        //     if (sys_ptrace(
        //         PTRACE_PEEKUSER, tid,
        //         reinterpret_cast<void*> (offsetof(struct user,
        //           u_debugreg[0]) + i *
        //         sizeof(debugreg_t)),
        //         &info->dregs[i]) == -1) {
        //       return false;
        //   }
        // }

        #[cfg(target_arch = "x86_64")]
        let stack_pointer = regs.rsp;
        #[cfg(target_arch = "x86")]
        let stack_pointer = regs.esp;

        Ok(ThreadInfoX86 {
            stack_pointer,
            tgid,
            ppid,
            regs,
            fpregs,
            dregs,
        })
    }

    #[cfg(target_arch = "x86_64")]
    pub fn get_instruction_pointer(&self) -> libc::c_ulonglong {
        self.regs.rip
    }

    #[cfg(target_arch = "x86")]
    pub fn get_instruction_pointer(&self) -> libc::c_ulonglong {
        self.regs.eip
    }

    pub fn fill_cpu_context(&self, out: &mut RawContextCPU) {
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
