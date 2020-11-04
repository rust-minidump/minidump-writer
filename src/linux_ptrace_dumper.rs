// use libc::c_void;
use crate::thread_info::{Pid, ThreadInfo};
use crate::Result;
use nix::errno::Errno;
use nix::sys::{ptrace, wait};
use std::ffi::c_void;
use std::path;

#[derive(Debug)]
struct LinuxPtraceDumper {
    pid: Pid,
    threads_suspended: bool,
    threads: Vec<Pid>,
}

impl LinuxPtraceDumper {
    /// Constructs a dumper for extracting information of a given process
    /// with a process ID of |pid|.
    pub fn new(pid: Pid) -> Self {
        LinuxPtraceDumper {
            pid,
            threads_suspended: false,
            threads: Vec::new(),
        }
    }

    /// Copies content of |length| bytes from a given process |child|,
    /// starting from |src|, into |dest|. This method uses ptrace to extract
    /// the content from the target process. Always returns true.
    pub fn copy_from_process(
        &self,
        dest: &mut Vec<i64>,
        child: nix::unistd::Pid,
        src: *mut c_void,
        length: usize,
    ) -> bool {
        let done = 0 as usize;
        while done < length {
            match ptrace::read(child, src) {
                Ok(word) => dest.push(word),
                Err(_) => {
                    return false;
                }
            }
        }
        true
    }

    /// Suspends a thread by attaching to it.
    fn suspend_thread(&self, child: nix::unistd::Pid) -> Result<()> {
        // This may fail if the thread has just died or debugged.
        ptrace::attach(child)?;
        loop {
            match wait::waitpid(child, Some(wait::WaitPidFlag::__WALL)) {
                Ok(_) => break,
                Err(nix::Error::Sys(Errno::EINTR)) => {
                    ptrace::detach(child, None)?;
                    return Err(format!("Failed to attach to: {:?}. Got EINTR.", child).into());
                }
                Err(_) => continue,
            }
        }
        if cfg!(any(target_arch = "x86", target_arch = "x86_64")) {
            // On x86, the stack pointer is NULL or -1, when executing trusted code in
            // the seccomp sandbox. Not only does this cause difficulties down the line
            // when trying to dump the thread's stack, it also results in the minidumps
            // containing information about the trusted threads. This information is
            // generally completely meaningless and just pollutes the minidumps.
            // We thus test the stack pointer and exclude any threads that are part of
            // the seccomp sandbox's trusted code.
            let skip_thread;
            let regs = ptrace::getregs(child);
            if regs.is_err() {
                skip_thread = true;
            } else {
                let regs = regs.unwrap(); // Always save to unwrap here
                #[cfg(target_arch = "x86_64")]
                {
                    skip_thread = regs.rsp == 0;
                }
                #[cfg(target_arch = "x86")]
                {
                    skip_thread = regs.esp == 0;
                }
            }
            if skip_thread {
                ptrace::detach(child, None)?;
                return Err(format!("Skipped thread {:?} due to it being part of the seccomp sandbox's trusted code", child).into());
            }
        }
        Ok(())
    }

    /// Resumes a thread by detaching from it.
    pub fn resume_thread(&self, child: nix::unistd::Pid) -> Result<()> {
        ptrace::detach(child, None)?;
        Ok(())
    }

    /// Parse /proc/$pid/task to list all the threads of the process identified by
    /// pid.
    fn enumerate_threads(&mut self) -> Result<()> {
        let task_path = path::PathBuf::from(format!("/proc/{}/task", self.pid));
        if task_path.is_dir() {
            for entry in std::fs::read_dir(task_path)? {
                let name = entry?
                    .file_name()
                    .to_str()
                    .ok_or("Unparsable filename")?
                    .parse::<Pid>();
                if let Ok(tid) = name {
                    self.threads.push(tid);
                }
            }
        }
        Ok(())
    }

    /// Read thread info from /proc/$pid/status.
    /// Fill out the |tgid|, |ppid| and |pid| members of |info|. If unavailable,
    /// these members are set to -1. Returns true if all three members are
    /// available.
    pub fn get_thread_info_by_index(&self, index: usize) -> Result<ThreadInfo> {
        if index > self.threads.len() {
            return Err(format!(
                "Index out of bounds! Got {}, only have {}\n",
                index,
                self.threads.len()
            )
            .into());
        }

        let tid = self.threads[index];
        ThreadInfo::create(self.pid, tid)
    }
}
