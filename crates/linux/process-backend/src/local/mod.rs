use {
    core::{cell::RefCell, ffi::c_int},
    libc::pid_t,
    syscall_invoker::SyscallInvoker,
};

pub use error::Error;

mod error;
mod syscall_invoker;

#[derive(Debug)]
pub struct Backend {
    pid: pid_t,
    syscall_invoker: RefCell<SyscallInvoker>,
}

impl Backend {
    pub fn new(pid: libc::pid_t) -> Self {
        Self {
            pid,
            syscall_invoker: Default::default(),
        }
    }
    pub fn stop_process(&self) -> Result<(), Error> {
        self.standard_syscall(|| unsafe { libc::kill(self.pid, libc::SIGSTOP) })
            .map_err(Error::SigStopFailed)?;
        Ok(())
    }

    pub fn continue_process(&self) -> Result<(), Error> {
        self.standard_syscall(|| unsafe { libc::kill(self.pid, libc::SIGCONT) })
            .map_err(Error::SigContFailed)?;
        Ok(())
    }

    pub fn standard_syscall<T, F>(&self, f: F) -> Result<T, c_int>
    where
        F: FnOnce() -> T,
        T: From<i8> + core::cmp::PartialEq,
    {
        self.syscall_invoker.borrow_mut().invoke_standard(f)
    }

    pub fn special_syscall<T, F>(&self, f: F) -> Result<T, c_int>
    where
        F: FnOnce() -> Result<T, ()>,
    {
        self.syscall_invoker.borrow_mut().invoke(f)
    }

    #[cfg(feature = "testing")]
    pub fn fail_one_syscall_with(&self, errno: c_int) {
        self.syscall_invoker
            .borrow_mut()
            .fail_one_syscall_with(errno);
    }
}

fn errno() -> c_int {
    unsafe { *errno_location() }
}

#[cfg(target_os = "android")]
fn errno_location() -> *mut c_int {
    unsafe { libc::__errno() }
}

#[cfg(not(target_os = "android"))]
fn errno_location() -> *mut c_int {
    unsafe { libc::__errno_location() }
}
