// use libc::c_void;
use crate::auxv_reader::{AuxvType, ProcfsAuxvIter};
use crate::maps_reader::{MappingInfo, MappingInfoParsingResult};
use crate::thread_info::{Pid, ThreadInfo};
use crate::Result;
use nix::errno::Errno;
use nix::sys::{ptrace, wait};
use std::collections::HashMap;
use std::convert::TryInto;
use std::ffi::c_void;
use std::io::{BufRead, BufReader};
use std::path;

#[derive(Debug)]
pub struct LinuxPtraceDumper {
    pid: Pid,
    threads_suspended: bool,
    pub threads: Vec<Pid>,
    pub auxv: HashMap<AuxvType, AuxvType>,
    pub mappings: Vec<MappingInfo>,
}

pub const AT_SYSINFO_EHDR: u64 = 33;

impl LinuxPtraceDumper {
    /// Constructs a dumper for extracting information of a given process
    /// with a process ID of |pid|.
    pub fn new(pid: Pid) -> Result<Self> {
        let mut dumper = LinuxPtraceDumper {
            pid,
            threads_suspended: false,
            threads: Vec::new(),
            auxv: HashMap::new(),
            mappings: Vec::new(),
        };
        dumper.init()?;
        Ok(dumper)
    }

    pub fn init(&mut self) -> Result<()> {
        self.read_auxv()?;
        self.enumerate_threads()?;
        self.enumerate_mappings()?;
        Ok(())
    }
    /// Copies content of |length| bytes from a given process |child|,
    /// starting from |src|, into |dest|. This method uses ptrace to extract
    /// the content from the target process. Always returns true.
    pub fn copy_from_process(
        &self,
        child: Pid,
        src: *mut c_void,
        num_of_words: isize,
    ) -> Result<Vec<libc::c_long>> {
        let pid = nix::unistd::Pid::from_raw(child);
        let mut res = Vec::new();
        for idx in 0isize..num_of_words {
            match ptrace::read(pid, unsafe { src.offset(idx) }) {
                Ok(word) => res.push(word),
                Err(e) => {
                    return Err(format!("Failed in ptrace::reach: {:?}", e).into());
                }
            }
        }
        Ok(res)
    }

    /// Suspends a thread by attaching to it.
    pub fn suspend_thread(&self, child: Pid) -> Result<()> {
        let pid = nix::unistd::Pid::from_raw(child);
        // This may fail if the thread has just died or debugged.
        ptrace::attach(pid)?;
        loop {
            match wait::waitpid(pid, Some(wait::WaitPidFlag::__WALL)) {
                Ok(_) => break,
                Err(nix::Error::Sys(Errno::EINTR)) => {
                    ptrace::detach(pid, None)?;
                    return Err(format!("Failed to attach to: {:?}. Got EINTR.", pid).into());
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
            let regs = ptrace::getregs(pid);
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
                ptrace::detach(pid, None)?;
                return Err(format!("Skipped thread {:?} due to it being part of the seccomp sandbox's trusted code", child).into());
            }
        }
        Ok(())
    }

    /// Resumes a thread by detaching from it.
    pub fn resume_thread(&self, child: Pid) -> Result<()> {
        let pid = nix::unistd::Pid::from_raw(child);
        ptrace::detach(pid, None)?;
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

    fn read_auxv(&mut self) -> Result<()> {
        let auxv_path = path::PathBuf::from(format!("/proc/{}/auxv", self.pid));
        let auxv_file = std::fs::File::open(auxv_path)?;
        let input = BufReader::new(auxv_file);
        let reader = ProcfsAuxvIter::new(input);
        for item in reader {
            let item = item?;
            self.auxv.insert(item.key, item.value);
        }
        Ok(())
    }

    fn enumerate_mappings(&mut self) -> Result<()> {
        // linux_gate_loc is the beginning of the kernel's mapping of
        // linux-gate.so in the process.  It doesn't actually show up in the
        // maps list as a filename, but it can be found using the AT_SYSINFO_EHDR
        // aux vector entry, which gives the information necessary to special
        // case its entry when creating the list of mappings.
        // See http://www.trilithium.com/johan/2005/08/linux-gate/ for more
        // information.
        let linux_gate_loc = *self.auxv.get(&AT_SYSINFO_EHDR).unwrap_or(&0);
        // Although the initial executable is usually the first mapping, it's not
        // guaranteed (see http://crosbug.com/25355); therefore, try to use the
        // actual entry point to find the mapping.
        let entry_point_loc = *self.auxv.get(&libc::AT_ENTRY).unwrap_or(&0);

        let auxv_path = path::PathBuf::from(format!("/proc/{}/maps", self.pid));
        let auxv_file = std::fs::File::open(auxv_path)?;

        for line in BufReader::new(auxv_file).lines() {
            // /proc/<pid>/maps looks like this
            // 7fe34a863000-7fe34a864000 rw-p 00009000 00:31 4746408                    /usr/lib64/libogg.so.0.8.4
            let line = line?;
            match MappingInfo::parse_from_line(&line, linux_gate_loc, self.mappings.last_mut()) {
                Ok(MappingInfoParsingResult::Success(map)) => self.mappings.push(map),
                Ok(MappingInfoParsingResult::SkipLine) => continue,
                Err(_) => continue,
            }
        }

        if entry_point_loc != 0 {
            let mut swap_idx = None;
            for (idx, module) in self.mappings.iter().enumerate() {
                // If this module contains the entry-point, and it's not already the first
                // one, then we need to make it be first.  This is because the minidump
                // format assumes the first module is the one that corresponds to the main
                // executable (as codified in
                // processor/minidump.cc:MinidumpModuleList::GetMainModule()).
                if entry_point_loc >= module.start_address.try_into().unwrap()
                    && entry_point_loc < (module.start_address + module.size).try_into().unwrap()
                {
                    swap_idx = Some(idx);
                    break;
                }
            }
            if let Some(idx) = swap_idx {
                self.mappings.swap(0, idx);
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

    // Find the mapping which the given memory address falls in.
    fn find_mapping<'a>(&'a self, address: usize) -> Option<&'a MappingInfo> {
        for map in &self.mappings {
            if address >= map.start_address && address - map.start_address < map.size {
                return Some(&map);
            }
        }
        None
    }

    // Find the mapping which the given memory address falls in. Uses the
    // unadjusted mapping address range from the kernel, rather than the
    // biased range.
    fn find_mapping_no_bias<'a>(&'a self, address: usize) -> Option<&'a MappingInfo> {
        for map in &self.mappings {
            if address >= map.system_mapping_info.start_address
                && address < map.system_mapping_info.end_address
            {
                return Some(&map);
            }
        }
        None
    }
}
