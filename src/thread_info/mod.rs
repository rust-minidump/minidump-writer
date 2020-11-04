use crate::Result;
use std::io::{self, BufRead};
use std::path;
pub type Pid = i32;

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[path = "thread_info_x86.rs"]
mod imp;
#[cfg(target_arch = "arm")]
#[path = "thread_info_arm.rs"]
mod imp;
#[cfg(target_arch = "aarch64")]
#[path = "thread_info_aarch64.rs"]
mod imp;
#[cfg(target_arch = "mips")]
#[path = "thread_info_mips.rs"]
mod imp;

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub type ThreadInfo = imp::ThreadInfoX86;
#[cfg(target_arch = "arm")]
pub type ThreadInfo = imp::ThreadInfoArm;
#[cfg(target_arch = "aarch64")]
pub type ThreadInfo = imp::ThreadInfoAarch64;
#[cfg(target_arch = "mips")]
pub type ThreadInfo = imp::ThreadInfoMips;

trait CommonThreadInfo {
    fn get_ppid_and_tgid(tid: Pid) -> Result<(Pid, Pid)> {
        let mut ppid = -1;
        let mut tgid = -1;

        let status_path = path::PathBuf::from(format!("/proc/{}/status", tid));
        let status_file = std::fs::File::open(status_path)?;
        for line in io::BufReader::new(status_file).lines() {
            let l = line?;
            match &l[0..6] {
                "Tgid:\t" => tgid = l[6..].parse::<Pid>()?,
                "PPid:\t" => ppid = l[6..].parse::<Pid>()?,
                _ => continue,
            }
        }
        if ppid == -1 || tgid == -1 {
            return Err("ppid or tgid is -1".into());
        }
        Ok((ppid, tgid))
    }
}
impl ThreadInfo {
    pub fn create(pid: Pid, tid: Pid) -> Result<Self> {
        Self::create_impl(pid, tid)
    }
    // bool LinuxPtraceDumper::ReadRegisterSet(ThreadInfo* info, pid_t tid)
    // {
    // #ifdef PTRACE_GETREGSET
    //   struct iovec io;
    //   info->GetGeneralPurposeRegisters(&io.iov_base, &io.iov_len);
    //   if (sys_ptrace(PTRACE_GETREGSET, tid, (void*)NT_PRSTATUS, (void*)&io) == -1) {
    //     return false;
    //   }

    //   info->GetFloatingPointRegisters(&io.iov_base, &io.iov_len);
    //   if (sys_ptrace(PTRACE_GETREGSET, tid, (void*)NT_FPREGSET, (void*)&io) == -1) {
    //     return false;
    //   }
    //   return true;
    // #else
    //   return false;
    // #endif
    // }

    // bool LinuxPtraceDumper::ReadRegisters(ThreadInfo* info, pid_t tid) {
    // #ifdef PTRACE_GETREGS
    //   void* gp_addr;
    //   info->GetGeneralPurposeRegisters(&gp_addr, NULL);
    //   if (sys_ptrace(PTRACE_GETREGS, tid, NULL, gp_addr) == -1) {
    //     return false;
    //   }

    // #if !(defined(__ANDROID__) && defined(__ARM_EABI__))
    //   // When running an arm build on an arm64 device, attempting to get the
    //   // floating point registers fails. On Android, the floating point registers
    //   // aren't written to the cpu context anyway, so just don't get them here.
    //   // See http://crbug.com/508324
    //   void* fp_addr;
    //   info->GetFloatingPointRegisters(&fp_addr, NULL);
    //   if (sys_ptrace(PTRACE_GETFPREGS, tid, NULL, fp_addr) == -1) {
    //     return false;
    //   }
    // #endif  // !(defined(__ANDROID__) && defined(__ARM_EABI__))
    //   return true;
    // #else  // PTRACE_GETREGS
    //   return false;
    // #endif
    // }
}
