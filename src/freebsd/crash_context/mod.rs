//! FreeBSD-native CrashContext implementation.
//!
//! Unlike Linux which uses the `crash-context` crate, FreeBSD defines its own
//! signal and context structures directly using `libc` types.

pub struct CrashContext {
    pub siginfo: libc::siginfo_t,
    pub ucontext: libc::ucontext_t,
    pub pid: i32,
    pub tid: i32,
}

impl std::fmt::Debug for CrashContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CrashContext")
            .field("siginfo", &"<siginfo>")
            .field("pid", &self.pid)
            .field("tid", &self.tid)
            .finish_non_exhaustive()
    }
}

cfg_if::cfg_if! {
    if #[cfg(target_arch = "x86_64")] {
        mod x86_64;
    }
}
