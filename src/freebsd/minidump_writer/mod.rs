use {
    super::Pid,
    crate::{
        auxv::AuxvDumpInfo,
        dir_section::{DirSection, DumpBuf},
        mem_writer::{Buffer, MemoryArrayWriter, MemoryWriter},
        minidump_format::*,
    },
    error_graph::{ErrorList, WriteErrorList},
    std::{
        io::{Seek, Write},
        time::Duration,
    },
};

pub mod app_memory_stream;
pub mod errors;
pub mod exception_stream;
pub mod handle_data_stream;
pub mod mappings;
pub mod memory_info_list_stream;
pub mod memory_list_stream;
pub mod systeminfo_stream;
pub mod thread_list_stream;
pub mod thread_names_stream;

pub use self::errors::{ContinueProcessError, InitError, StopProcessError, WriterError};
pub use crate::auxv::{AuxvType, DirectAuxvDumpInfo};

pub type AppMemoryList = Vec<crate::freebsd::app_memory::AppMemory>;

#[derive(Debug)]
pub struct MinidumpWriterConfig {
    process_id: Pid,
    blamed_thread: Pid,
    minidump_size_limit: Option<u64>,
    skip_stacks_if_mapping_unreferenced: bool,
    principal_mapping_address: Option<usize>,
    user_mapping_list: Vec<crate::freebsd::maps_reader::MappingInfo>,
    app_memory: AppMemoryList,
    memory_blocks: Vec<MDMemoryDescriptor>,
    principal_mapping: Option<crate::freebsd::maps_reader::MappingInfo>,
    sanitize_stack: bool,
    crash_context: Option<crate::freebsd::crash_context::CrashContext>,
    crashing_thread_context: CrashingThreadContext,
    stop_timeout: Duration,
    direct_auxv_dump_info: Option<DirectAuxvDumpInfo>,
}

#[derive(Debug)]
pub struct MinidumpWriter {
    pub process_id: Pid,
    process_attached: bool,
    threads_suspended: bool,
    pub threads: Vec<Thread>,
    pub auxv: crate::auxv::AuxvDumpInfo,
    pub mappings: Vec<crate::freebsd::maps_reader::MappingInfo>,
    pub page_size: usize,
    pub sanitize_stack: bool,
    pub minidump_size_limit: Option<u64>,
    pub user_mapping_list: Vec<crate::freebsd::maps_reader::MappingInfo>,
    pub crashing_thread_context: CrashingThreadContext,
    pub stop_timeout: Duration,
    pub skip_stacks_if_mapping_unreferenced: bool,
    pub principal_mapping_address: Option<usize>,
    pub principal_mapping: Option<crate::freebsd::maps_reader::MappingInfo>,
    pub blamed_thread: Pid,
    pub crash_context: Option<crate::freebsd::crash_context::CrashContext>,
    pub app_memory: AppMemoryList,
    pub memory_blocks: Vec<MDMemoryDescriptor>,
}

#[derive(Debug, Clone)]
pub struct Thread {
    pub tid: Pid,
    pub name: Option<String>,
}

#[derive(Debug, Default)]
pub enum CrashingThreadContext {
    #[default]
    None,
    CrashContext(MDLocationDescriptor),
    CrashContextPlusAddress((MDLocationDescriptor, usize)),
}

impl MinidumpWriterConfig {
    pub fn new(process_id: Pid, blamed_thread: Pid) -> Self {
        Self {
            process_id,
            blamed_thread,
            minidump_size_limit: Default::default(),
            skip_stacks_if_mapping_unreferenced: Default::default(),
            principal_mapping_address: Default::default(),
            user_mapping_list: Default::default(),
            app_memory: Default::default(),
            memory_blocks: Default::default(),
            principal_mapping: Default::default(),
            sanitize_stack: Default::default(),
            crash_context: Default::default(),
            crashing_thread_context: Default::default(),
            stop_timeout: Duration::from_millis(100),
            direct_auxv_dump_info: Default::default(),
        }
    }

    pub fn set_minidump_size_limit(&mut self, limit: u64) -> &mut Self {
        self.minidump_size_limit = Some(limit);
        self
    }

    pub fn set_crash_context(
        &mut self,
        crash_context: crate::freebsd::crash_context::CrashContext,
    ) -> &mut Self {
        self.crash_context = Some(crash_context);
        self
    }

    pub fn set_user_mapping_list(
        &mut self,
        list: Vec<crate::freebsd::maps_reader::MappingInfo>,
    ) -> &mut Self {
        self.user_mapping_list = list;
        self
    }

    pub fn set_principal_mapping_address(&mut self, addr: usize) -> &mut Self {
        self.principal_mapping_address = Some(addr);
        self
    }

    pub fn set_app_memory(&mut self, app_memory: AppMemoryList) -> &mut Self {
        self.app_memory = app_memory;
        self
    }

    pub fn skip_stacks_if_mapping_unreferenced(&mut self) -> &mut Self {
        self.skip_stacks_if_mapping_unreferenced = true;
        self
    }

    pub fn sanitize_stack(&mut self) -> &mut Self {
        self.sanitize_stack = true;
        self
    }

    pub fn stop_timeout(&mut self, duration: Duration) -> &mut Self {
        self.stop_timeout = duration;
        self
    }

    pub fn set_direct_auxv_dump_info(&mut self, info: DirectAuxvDumpInfo) -> &mut Self {
        self.direct_auxv_dump_info = Some(info);
        self
    }

    pub fn write(self, destination: &mut (impl Write + Seek)) -> Result<Vec<u8>, WriterError> {
        let mut soft_errors = ErrorList::default();
        let mut writer = self.build();
        writer.init(soft_errors.subwriter(WriterError::InitErrors))?;
        let mut buffer = Buffer::with_capacity(0);
        writer.write_dump(&mut buffer, destination, soft_errors)?;
        Ok(buffer.into())
    }

    pub fn build_for_testing(
        self,
        soft_errors: impl WriteErrorList<InitError>,
    ) -> Result<MinidumpWriter, InitError> {
        let mut writer = self.build();
        writer.init(soft_errors)?;
        Ok(writer)
    }

    fn build(self) -> MinidumpWriter {
        let auxv = self
            .direct_auxv_dump_info
            .map(AuxvDumpInfo::from)
            .unwrap_or_default();

        MinidumpWriter {
            process_id: self.process_id,
            process_attached: Default::default(),
            threads_suspended: Default::default(),
            threads: Default::default(),
            auxv,
            mappings: Default::default(),
            page_size: Default::default(),
            sanitize_stack: self.sanitize_stack,
            minidump_size_limit: self.minidump_size_limit,
            user_mapping_list: self.user_mapping_list,
            crashing_thread_context: self.crashing_thread_context,
            stop_timeout: self.stop_timeout,
            skip_stacks_if_mapping_unreferenced: self.skip_stacks_if_mapping_unreferenced,
            principal_mapping_address: self.principal_mapping_address,
            principal_mapping: self.principal_mapping,
            blamed_thread: self.blamed_thread,
            crash_context: self.crash_context,
            app_memory: self.app_memory,
            memory_blocks: self.memory_blocks,
        }
    }
}

impl MinidumpWriter {
    fn init(&mut self, mut soft_errors: impl WriteErrorList<InitError>) -> Result<(), InitError> {
        // 1. Cannot ptrace same process
        if self.process_id == std::process::id() as i32 {
            return Err(InitError::CannotPtraceSameProcess);
        }

        // 2. Attach so FreeBSD ptrace requests can inspect the stopped process.
        // Requests such as PT_GETNUMLWPS, PT_IO, and PT_GETREGS require a
        // traced target; PT_ATTACH also stops the process.
        if let Err(e) = self.attach_process(self.stop_timeout) {
            soft_errors.push(InitError::IOError(
                format!("Failed to attach to PID {}", self.process_id),
                e,
            ));

            // Fall back to a plain stop so non-ptrace data collection can still
            // proceed where possible.
            if let Err(e) = self.stop_process(self.stop_timeout) {
                soft_errors.push(InitError::StopProcessFailed(e));
            }
        }

        // 3. Fill missing auxv info
        if let Err(e) = self.auxv.try_filling_missing_info(self.process_id) {
            soft_errors.push(InitError::FillMissingAuxvInfoFailed(e));
        }

        // 4. Enumerate threads
        if let Err(e) = self.enumerate_threads() {
            soft_errors.push(InitError::EnumerateThreadsFailed(Box::new(e)));
        }

        // 5. Enumerate mappings
        if let Err(e) = self.enumerate_mappings() {
            soft_errors.push(InitError::EnumerateMappingsFailed(Box::new(e)));
        }

        // 6. Get page size via libc::sysconf
        // SAFETY: sysconf is a well-defined POSIX function. _SC_PAGESIZE always
        // succeeds on a valid system, but we check for <= 0 just in case.
        let page_size_raw = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        if page_size_raw <= 0 {
            return Err(InitError::PageSizeError(
                #[allow(clippy::io_other_error)]
                std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Failed to get PAGE_SIZE from sysctl",
                ),
            ));
        }
        self.page_size = page_size_raw as usize;

        // 7. Suspend threads
        let threads_count = self.threads.len();
        self.suspend_threads(soft_errors.subwriter(InitError::SuspendThreadsErrors));

        // 8. Check if any threads left
        if self.threads.is_empty() {
            soft_errors.push(InitError::SuspendNoThreadsLeft(threads_count));
        }

        // 9. Principal mapping check
        if self.skip_stacks_if_mapping_unreferenced {
            if let Some(address) = self.principal_mapping_address {
                self.principal_mapping = self.find_mapping_no_bias(address).cloned();
            }
            if !self.crash_thread_references_principal_mapping() {
                soft_errors.push(InitError::PrincipalMappingNotReferenced);
            }
        }

        Ok(())
    }

    fn enumerate_threads(&mut self) -> Result<(), InitError> {
        let tids = crate::freebsd::thread_info::get_thread_list(self.process_id).map_err(|e| {
            InitError::IOError(
                format!("Failed to enumerate threads for PID {}", self.process_id),
                #[allow(clippy::io_other_error)]
                std::io::Error::new(std::io::ErrorKind::Other, e.to_string()),
            )
        })?;

        for tid in tids {
            let name = crate::freebsd::thread_info::get_thread_name(self.process_id, tid);
            self.threads.push(Thread { tid, name });
        }

        Ok(())
    }

    fn enumerate_mappings(&mut self) -> Result<(), InitError> {
        self.mappings = crate::freebsd::maps_reader::MappingInfo::for_pid(self.process_id, None)
            .map_err(InitError::AggregateMappingsFailed)?;

        if let Some(entry) = self.auxv.get_entry_address() {
            let entry_usize = entry as usize;
            if let Some(idx) = self
                .mappings
                .iter()
                .position(|m| (m.start_address..m.start_address + m.size).contains(&entry_usize))
            {
                self.mappings.swap(0, idx);
            }
        }

        Ok(())
    }

    fn stop_process(&mut self, timeout: Duration) -> Result<(), StopProcessError> {
        let pid = self.process_id;

        // SAFETY: kill sends a signal to the target pid. We check the return
        // value and use SIGSTOP which is a standard stop signal.
        if unsafe { libc::kill(pid, libc::SIGSTOP) } == -1 {
            return Err(StopProcessError::Stop(std::io::Error::last_os_error()));
        }

        const POLL_INTERVAL: Duration = Duration::from_millis(1);
        let end = std::time::Instant::now() + timeout;

        loop {
            let mut status: libc::c_int = 0;
            // SAFETY: waitpid waits for state changes in the child. We provide a
            // valid status pointer and use WNOHANG for non-blocking polling.
            let ret = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };

            if ret == -1 {
                let err = std::io::Error::last_os_error();
                // ECHILD means the process is not a child, which is expected
                // when sending SIGSTOP to a non-child. In that case, assume stopped.
                if err.raw_os_error() == Some(libc::ECHILD) {
                    return Ok(());
                }
                return Err(StopProcessError::WaitPidFailed(err));
            }

            if ret > 0 && libc::WIFSTOPPED(status) {
                return Ok(());
            }

            std::thread::sleep(POLL_INTERVAL);
            if std::time::Instant::now() > end {
                return Err(StopProcessError::Timeout);
            }
        }
    }

    fn continue_process(&mut self) -> Result<(), ContinueProcessError> {
        // SAFETY: kill sends SIGCONT to the target pid to resume it.
        // We check the return value for errors.
        if unsafe { libc::kill(self.process_id, libc::SIGCONT) } == -1 {
            return Err(ContinueProcessError::Continue(
                std::io::Error::last_os_error(),
            ));
        }
        Ok(())
    }

    fn attach_process(&mut self, timeout: Duration) -> std::io::Result<()> {
        // SAFETY: ptrace(PT_ATTACH) attaches to the target process. We check the
        // return value and then wait for the kernel-reported ptrace stop.
        if unsafe {
            libc::ptrace(
                libc::PT_ATTACH,
                self.process_id,
                std::ptr::null_mut::<libc::c_char>(),
                0,
            )
        } == -1
        {
            return Err(std::io::Error::last_os_error());
        }

        self.process_attached = true;

        const POLL_INTERVAL: Duration = Duration::from_millis(1);
        let end = std::time::Instant::now() + timeout;
        let mut status: libc::c_int = 0;
        loop {
            // SAFETY: waitpid waits for the attached process to report its
            // ptrace stop. We provide a valid status pointer and retry EINTR.
            let ret = unsafe { libc::waitpid(self.process_id, &mut status, libc::WNOHANG) };
            if ret == -1 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                let _ = Self::ptrace_detach_inner(self.process_id);
                self.process_attached = false;
                return Err(err);
            }
            if libc::WIFSTOPPED(status) {
                return Ok(());
            }

            std::thread::sleep(POLL_INTERVAL);
            if std::time::Instant::now() > end {
                let _ = Self::ptrace_detach_inner(self.process_id);
                self.process_attached = false;
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "timeout waiting for ptrace attach stop",
                ));
            }
        }
    }

    fn ptrace_detach_inner(child: Pid) -> Result<(), WriterError> {
        // SAFETY: ptrace operates on the target pid which has been validated.
        // PT_DETACH detaches from the traced process and resumes it.
        if unsafe {
            libc::ptrace(
                libc::PT_DETACH,
                child,
                std::ptr::null_mut::<libc::c_char>(),
                0,
            )
        } == -1
        {
            let err = std::io::Error::last_os_error();
            // ESRCH means the process is gone — not an error
            if err.raw_os_error() == Some(libc::ESRCH) {
                Ok(())
            } else {
                Err(WriterError::PtraceDetachError(child, err))
            }
        } else {
            Ok(())
        }
    }

    fn suspend_thread(child: Pid) -> Result<(), WriterError> {
        // The process has already been stopped and attached. The per-thread
        // check here only filters threads whose register state is not useful.
        #[cfg(target_arch = "x86_64")]
        {
            use crate::freebsd::thread_info::ThreadInfo;
            #[allow(clippy::collapsible_if)]
            if let Ok(regs) = ThreadInfo::getregs(child) {
                if regs.rsp == 0 {
                    return Err(WriterError::DetachSkippedThread(child));
                }
            }
        }

        Ok(())
    }

    fn resume_thread(child: Pid) -> Result<(), WriterError> {
        let _ = child;
        Ok(())
    }

    fn suspend_threads(&mut self, mut soft_errors: impl WriteErrorList<WriterError>) {
        self.threads.retain(|x| match Self::suspend_thread(x.tid) {
            Ok(()) => true,
            Err(e) => {
                soft_errors.push(e);
                false
            }
        });
        self.threads_suspended = true;
    }

    fn resume_threads(&mut self, mut soft_errors: impl WriteErrorList<WriterError>) {
        if self.threads_suspended {
            for thread in &self.threads {
                if let Err(e) = Self::resume_thread(thread.tid) {
                    soft_errors.push(e);
                }
            }
        }
        self.threads_suspended = false;
    }

    pub fn copy_from_process(
        pid: Pid,
        src: usize,
        length: usize,
    ) -> Result<Vec<u8>, crate::freebsd::process_reader::CopyFromProcessError> {
        let length = std::num::NonZeroUsize::new(length).ok_or(
            crate::freebsd::process_reader::CopyFromProcessError {
                src,
                child: pid,
                offset: 0,
                length,
                source: std::io::Error::new(std::io::ErrorKind::InvalidInput, "length is zero"),
            },
        )?;

        let mem = crate::freebsd::process_reader::ProcessReader::new(pid);
        mem.read_to_vec(src, length)
    }

    pub fn get_thread_info_by_index(
        &self,
        index: usize,
    ) -> Result<crate::freebsd::thread_info::ThreadInfo, crate::freebsd::thread_info::ThreadInfoError>
    {
        if index >= self.threads.len() {
            return Err(
                crate::freebsd::thread_info::ThreadInfoError::IndexOutOfBounds(
                    index,
                    self.threads.len(),
                ),
            );
        }
        crate::freebsd::thread_info::ThreadInfo::create(self.process_id, self.threads[index].tid)
    }

    pub fn find_mapping(
        &self,
        address: usize,
    ) -> Option<&crate::freebsd::maps_reader::MappingInfo> {
        self.mappings
            .iter()
            .find(|map| address >= map.start_address && address - map.start_address < map.size)
    }

    pub fn find_mapping_no_bias(
        &self,
        address: usize,
    ) -> Option<&crate::freebsd::maps_reader::MappingInfo> {
        self.mappings.iter().find(|map| {
            address >= map.system_mapping_info.start_address
                && address < map.system_mapping_info.end_address
        })
    }

    fn may_be_stack(mapping: Option<&crate::freebsd::maps_reader::MappingInfo>) -> bool {
        if let Some(mapping) = mapping {
            return mapping.permissions.intersects(
                crate::freebsd::vm_permissions::VmPermissions::READ
                    | crate::freebsd::vm_permissions::VmPermissions::WRITE,
            );
        }
        false
    }

    pub fn get_stack_info(&self, int_stack_pointer: usize) -> Result<(usize, usize), WriterError> {
        let mut stack_pointer = int_stack_pointer & !(self.page_size - 1);
        let mut mapping = self.find_mapping(stack_pointer);

        let guard_page_max_addr = stack_pointer.saturating_add(1024 * 1024);

        while !Self::may_be_stack(mapping) && stack_pointer <= guard_page_max_addr {
            stack_pointer += self.page_size;
            mapping = self.find_mapping(stack_pointer);
        }

        mapping
            .map(|mapping| {
                let valid_stack_pointer = if mapping.contains_address(stack_pointer) {
                    stack_pointer
                } else {
                    mapping.start_address
                };
                let stack_len = mapping.size - (valid_stack_pointer - mapping.start_address);
                (valid_stack_pointer, stack_len)
            })
            .ok_or(WriterError::NoStackPointerMapping)
    }

    pub fn sanitize_stack_copy(
        &self,
        stack_copy: &mut [u8],
        stack_pointer: usize,
        sp_offset: usize,
    ) -> Result<(), WriterError> {
        let defaced;
        #[cfg(target_pointer_width = "64")]
        {
            defaced = 0x0defaced0defacedusize.to_ne_bytes();
        }
        #[cfg(target_pointer_width = "32")]
        {
            defaced = 0x0defacedusize.to_ne_bytes();
        };

        let test_bits = 11;
        let array_size: usize = 1 << (test_bits - 3);
        let array_mask = array_size - 1;
        let shift = 32 - test_bits;
        let stack_mapping = self.find_mapping_no_bias(stack_pointer);
        let mut last_hit_mapping: Option<&crate::freebsd::maps_reader::MappingInfo> = None;
        let small_int_magnitude: isize = 4096;

        let mut could_hit_mapping = vec![0u8; array_size];
        for mapping in &self.mappings {
            if !mapping.is_executable() {
                continue;
            }
            let mut start = mapping.start_address;
            let mut end = start + mapping.size;
            start >>= shift;
            end >>= shift;
            for bit in start..=end {
                could_hit_mapping[(bit >> 3) & array_mask] |= 1 << (bit & 7);
            }
        }

        let offset =
            (sp_offset + std::mem::size_of::<usize>() - 1) & !(std::mem::size_of::<usize>() - 1);
        for x in &mut stack_copy[0..offset] {
            *x = 0;
        }
        let mut chunks = stack_copy[offset..].chunks_exact_mut(std::mem::size_of::<usize>());

        for sp in &mut chunks {
            let addr = usize::from_ne_bytes(sp.to_vec().as_slice().try_into()?);
            let addr_signed = isize::from_ne_bytes(sp.to_vec().as_slice().try_into()?);

            if addr <= small_int_magnitude as usize && addr_signed >= -small_int_magnitude {
                continue;
            }

            #[allow(clippy::collapsible_if)]
            if let Some(stack_map) = stack_mapping {
                if stack_map.contains_address(addr) {
                    continue;
                }
            }

            #[allow(clippy::collapsible_if)]
            if let Some(last_hit) = last_hit_mapping {
                if last_hit.contains_address(addr) {
                    continue;
                }
            }

            let test = addr >> shift;
            #[allow(clippy::collapsible_if)]
            if could_hit_mapping[(test >> 3) & array_mask] & (1 << (test & 7)) != 0 {
                #[allow(clippy::collapsible_if)]
                if let Some(hit_mapping) = self.find_mapping_no_bias(addr) {
                    if hit_mapping.is_executable() {
                        last_hit_mapping = Some(hit_mapping);
                        continue;
                    }
                }
            }

            #[allow(clippy::collapsible_if)]
            if let Some(last_hit) = last_hit_mapping {
                if last_hit.contains_address(addr) {
                    continue;
                }
            }

            let test = addr >> shift;
            #[allow(clippy::collapsible_if)]
            if could_hit_mapping[(test >> 3) & array_mask] & (1 << (test & 7)) != 0 {
                #[allow(clippy::collapsible_if)]
                if let Some(hit_mapping) = self.find_mapping_no_bias(addr) {
                    if hit_mapping.is_executable() {
                        last_hit_mapping = Some(hit_mapping);
                        continue;
                    }
                }
            }

            sp.copy_from_slice(&defaced);
        }

        for sp in chunks.into_remainder() {
            *sp = 0;
        }
        Ok(())
    }

    fn crash_thread_references_principal_mapping(&self) -> bool {
        let principal_mapping = match self.principal_mapping.as_ref() {
            Some(m) => m,
            None => return false,
        };

        let crash_context = match self.crash_context.as_ref() {
            Some(ctx) => ctx,
            None => return true,
        };

        let instruction_pointer = crash_context.get_instruction_pointer();
        if principal_mapping.contains_address(instruction_pointer) {
            return true;
        }

        let stack_pointer = crash_context.get_stack_pointer();

        #[allow(clippy::collapsible_if)]
        if let Ok((valid_sp, stack_len)) = self.get_stack_info(stack_pointer) {
            if let Ok(stack_copy) = Self::copy_from_process(self.process_id, valid_sp, stack_len) {
                let sp_offset = stack_pointer.saturating_sub(valid_sp);
                return principal_mapping.stack_has_pointer_to_mapping(&stack_copy, sp_offset);
            }
        }

        false
    }

    pub fn from_process_memory_for_index<T: crate::module_reader::ReadFromModule>(
        &mut self,
        idx: usize,
    ) -> Result<T, WriterError> {
        assert!(idx < self.mappings.len());
        Self::from_process_memory_for_mapping(&self.mappings[idx], self.process_id)
    }

    pub fn from_process_memory_for_mapping<T: crate::module_reader::ReadFromModule>(
        mapping: &crate::freebsd::maps_reader::MappingInfo,
        pid: Pid,
    ) -> Result<T, WriterError> {
        let reader = crate::freebsd::process_reader::ProcessReader::new(pid);
        Ok(T::read_from_module(
            crate::module_reader::ModuleMemory::from_process(&reader, mapping.start_address),
        )?)
    }

    fn write_dump(
        &mut self,
        buffer: &mut DumpBuf,
        destination: &mut (impl Write + Seek),
        mut soft_errors: ErrorList<WriterError>,
    ) -> Result<(), WriterError> {
        let num_writers = 9u32;

        let mut header_section = MemoryWriter::<MDRawHeader>::alloc(buffer)?;

        let mut dir_section = DirSection::new(buffer, num_writers, destination)?;

        let header = MDRawHeader {
            signature: MD_HEADER_SIGNATURE,
            version: MD_HEADER_VERSION,
            stream_count: num_writers,
            stream_directory_rva: dir_section.position(),
            checksum: 0,
            time_date_stamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs() as u32,
            flags: 0,
        };
        header_section.set_value(buffer, header)?;

        dir_section.write_to_file(buffer, None)?;

        let dirent = self.write_thread_list_stream(buffer)?;
        dir_section.write_to_file(buffer, Some(dirent))?;

        let dirent = self.write_mappings(buffer)?;
        dir_section.write_to_file(buffer, Some(dirent))?;

        self.write_app_memory(buffer)?;
        dir_section.write_to_file(buffer, None)?;

        let dirent = self.write_memory_list_stream(buffer)?;
        dir_section.write_to_file(buffer, Some(dirent))?;

        let dirent = self.write_exception_stream(buffer)?;
        dir_section.write_to_file(buffer, Some(dirent))?;

        let dirent = systeminfo_stream::write_systeminfo_stream(
            buffer,
            soft_errors.subwriter(WriterError::WriteSystemInfoErrors),
        )?;
        dir_section.write_to_file(buffer, Some(dirent))?;

        let dirent = self.write_thread_names_stream(buffer)?;
        dir_section.write_to_file(buffer, Some(dirent))?;

        let dirent = match self.write_handle_data_stream(buffer) {
            Ok(dirent) => dirent,
            Err(e) => {
                soft_errors.push(WriterError::WriteHandleDataStreamFailed(e));
                Default::default()
            }
        };
        dir_section.write_to_file(buffer, Some(dirent))?;

        let dirent = self.write_memory_info_list_stream(buffer)?;
        dir_section.write_to_file(buffer, Some(dirent))?;

        let dirent = write_soft_errors(buffer, &soft_errors)?;
        dir_section.write_to_file(buffer, Some(dirent))?;

        Ok(())
    }
}

fn write_soft_errors(
    buffer: &mut DumpBuf,
    soft_errors: &ErrorList<WriterError>,
) -> Result<MDRawDirectory, WriterError> {
    let soft_errors_json_str =
        serde_json::to_string_pretty(soft_errors).map_err(WriterError::ConvertToJsonFailed)?;
    let section = MemoryArrayWriter::write_bytes(buffer, soft_errors_json_str.as_bytes());
    Ok(MDRawDirectory {
        stream_type: MDStreamType::MozSoftErrors as u32,
        location: section.location(),
    })
}

impl Drop for MinidumpWriter {
    fn drop(&mut self) {
        self.resume_threads(error_graph::strategy::DontCare);
        if self.process_attached {
            let _ = Self::ptrace_detach_inner(self.process_id);
            self.process_attached = false;
        }
        let _ = self.continue_process();
    }
}
