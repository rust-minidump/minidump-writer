use {
    super::{
        Pid,
        auxv::AuxvDumpInfo,
        crash_context::CrashContext,
        maps_reader::{MappingEntry, MappingInfo},
        process_inspection::{self, ProcessInspector, process_reader::CopyFromProcessError},
        thread_info::{ThreadInfo, ThreadInfoError},
        vm_permissions::VmPermissions,
    },
    crate::{
        dir_section::{DirSection, DumpBuf},
        mem_writer::{Buffer, MemoryArrayWriter, MemoryWriter},
        minidump_format::*,
    },
    error_graph::{ErrorList, WriteErrorList},
    std::io::{Seek, Write},
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
pub use super::auxv::{AuxvType, DirectAuxvDumpInfo};

pub type AppMemoryList = Vec<super::app_memory::AppMemory>;

#[derive(Debug)]
pub struct MinidumpWriterConfig {
    process_id: Pid,
    blamed_thread: Pid,
    minidump_size_limit: Option<u64>,
    skip_stacks_if_mapping_unreferenced: bool,
    principal_mapping_address: Option<usize>,
    user_mapping_list: Vec<MappingEntry>,
    app_memory: AppMemoryList,
    sanitize_stack: bool,
    crash_context: Option<CrashContext>,
    direct_auxv_dump_info: Option<DirectAuxvDumpInfo>,
    process_inspector: Box<dyn ProcessInspector>,
}

#[derive(Debug)]
pub struct MinidumpWriter {
    pub process_id: Pid,
    process_attached: bool,
    threads_suspended: bool,
    pub threads: Vec<Thread>,
    pub auxv: AuxvDumpInfo,
    pub mappings: Vec<MappingInfo>,
    pub page_size: usize,
    pub sanitize_stack: bool,
    pub minidump_size_limit: Option<u64>,
    pub user_mapping_list: Vec<MappingEntry>,
    pub crashing_thread_context: CrashingThreadContext,
    pub skip_stacks_if_mapping_unreferenced: bool,
    pub principal_mapping_address: Option<usize>,
    pub principal_mapping: Option<MappingInfo>,
    pub blamed_thread: Pid,
    pub crash_context: Option<CrashContext>,
    pub app_memory: AppMemoryList,
    pub memory_blocks: Vec<MDMemoryDescriptor>,
    pub process_inspector: Box<dyn ProcessInspector>,
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
            sanitize_stack: Default::default(),
            crash_context: Default::default(),
            direct_auxv_dump_info: Default::default(),
            process_inspector: process_inspection::local(process_id),
        }
    }

    pub fn set_minidump_size_limit(&mut self, limit: u64) -> &mut Self {
        self.minidump_size_limit = Some(limit);
        self
    }

    pub fn set_crash_context(&mut self, crash_context: CrashContext) -> &mut Self {
        self.crash_context = Some(crash_context);
        self
    }

    pub fn set_user_mapping_list(&mut self, list: Vec<MappingEntry>) -> &mut Self {
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
            crashing_thread_context: Default::default(),
            skip_stacks_if_mapping_unreferenced: self.skip_stacks_if_mapping_unreferenced,
            principal_mapping_address: self.principal_mapping_address,
            principal_mapping: Default::default(),
            blamed_thread: self.blamed_thread,
            crash_context: self.crash_context,
            app_memory: self.app_memory,
            memory_blocks: Default::default(),
            process_inspector: self.process_inspector,
        }
    }
}

impl MinidumpWriter {
    fn init(&mut self, mut soft_errors: impl WriteErrorList<InitError>) -> Result<(), InitError> {
        if self.process_id == std::process::id() as i32 {
            return Err(InitError::CannotPtraceSameProcess);
        }

        if let Err(e) = self.attach_process() {
            soft_errors.push(InitError::IOError(
                format!("Failed to attach to PID {}", self.process_id),
                e,
            ));
            // Fall back to a plain stop so non-ptrace data collection can
            // still proceed where possible.
            if let Err(e) = self.stop_process() {
                soft_errors.push(InitError::StopProcessFailed(e));
            }
        }

        if let Err(e) = self
            .auxv
            .try_filling_missing_info(self.process_inspector.as_ref())
        {
            soft_errors.push(InitError::FillMissingAuxvInfoFailed(e));
        }

        if let Err(e) = self.enumerate_threads() {
            soft_errors.push(InitError::EnumerateThreadsFailed(Box::new(e)));
        }

        if let Err(e) = self.enumerate_mappings() {
            soft_errors.push(InitError::EnumerateMappingsFailed(Box::new(e)));
        }

        // SAFETY: sysconf is a well-defined POSIX function.
        let page_size_raw = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        if page_size_raw <= 0 {
            return Err(InitError::PageSizeError(std::io::Error::other(
                "sysconf(_SC_PAGESIZE) failed",
            )));
        }
        self.page_size = page_size_raw as usize;

        let threads_count = self.threads.len();
        self.suspend_threads(soft_errors.subwriter(InitError::SuspendThreadsErrors));

        if self.threads.is_empty() {
            soft_errors.push(InitError::SuspendNoThreadsLeft(threads_count));
        }

        if self.skip_stacks_if_mapping_unreferenced {
            if let Some(address) = self.principal_mapping_address {
                self.principal_mapping = self.find_mapping(address).cloned();
            }
            if !self.crash_thread_references_principal_mapping() {
                soft_errors.push(InitError::PrincipalMappingNotReferenced);
            }
        }

        Ok(())
    }

    fn enumerate_threads(&mut self) -> Result<(), InitError> {
        let tids = self
            .process_inspector
            .get_thread_list()
            .map_err(InitError::ThreadEnumFailed)?;

        // One sysctl for all names; a missing name is fine.
        let names: std::collections::HashMap<libc::pid_t, String> = self
            .process_inspector
            .get_thread_names()
            .map(|names| names.into_iter().collect())
            .unwrap_or_default();

        for tid in tids {
            let name = names.get(&tid).cloned();
            self.threads.push(Thread { tid, name });
        }

        Ok(())
    }

    fn enumerate_mappings(&mut self) -> Result<(), InitError> {
        self.mappings = MappingInfo::from_inspector(self.process_inspector.as_ref())
            .map_err(InitError::AggregateMappingsFailed)?;

        self.name_main_executable();

        // Move the mapping containing the entry point to the front so it is
        // recognized as the main module.
        if let Some(entry) = self.auxv.get_entry_address()
            && let Some(idx) = self
                .mappings
                .iter()
                .position(|m| m.contains_address(entry as usize))
        {
            self.mappings.swap(0, idx);
        }

        Ok(())
    }

    /// Names the main executable's mapping.
    ///
    /// `kinfo_getvmmap` reports no path for mappings whose backing file has
    /// been deleted. For the main executable the name can be recovered from
    /// the `AT_EXECPATH` auxv entry, which points to a path string that still
    /// lives in the process's memory.
    fn name_main_executable(&mut self) {
        let Some(phdr) = self.auxv.get_program_header_address() else {
            return;
        };
        let Some(idx) = self
            .mappings
            .iter()
            .position(|m| m.contains_address(phdr as usize))
        else {
            return;
        };
        if self.mappings[idx].name.is_some() {
            return;
        }
        let Some(path_addr) = self.auxv.get_exec_path_address() else {
            return;
        };

        let reader = self.process_inspector.process_reader();
        if let Ok(path) = reader.copy_nul_terminated_string(path_addr as usize) {
            self.mappings[idx].name = Some(std::ffi::OsString::from(
                path.to_string_lossy().into_owned(),
            ));
        }
    }

    /// Stops the process via the inspector (SIGSTOP + wait) so that we can
    /// get a consistent state.
    fn stop_process(&mut self) -> Result<(), StopProcessError> {
        self.process_inspector
            .stop_process()
            .map_err(|e| StopProcessError::Stop(std::io::Error::other(e)))
    }

    /// Resumes a process stopped with [`stop_process`](Self::stop_process).
    fn continue_process(&mut self) -> Result<(), ContinueProcessError> {
        self.process_inspector
            .continue_process()
            .map_err(|e| ContinueProcessError::Continue(std::io::Error::other(e)))
    }

    /// Attaches to the process with `PT_ATTACH`, which also stops it.
    ///
    /// All further inspection (`PT_IO` reads, registers, thread enumeration)
    /// requires an established trace relationship.
    fn attach_process(&mut self) -> std::io::Result<()> {
        self.process_inspector
            .attach()
            .map_err(std::io::Error::other)?;
        self.process_attached = true;
        Ok(())
    }

    /// Suspends a thread and returns an error if its register state is not
    /// useful for a dump (registers unreadable, or a zeroed stack pointer);
    /// the caller then drops it from the thread list.
    fn suspend_thread(
        process_inspector: &dyn ProcessInspector,
        tid: Pid,
    ) -> Result<(), WriterError> {
        process_inspector
            .suspend_thread(tid)
            .map_err(WriterError::SuspendThreadFailed)?;

        #[cfg(target_arch = "x86_64")]
        {
            let skip_thread = match process_inspector.get_gen_regs(tid) {
                Ok(regs) => regs.0.r_rsp == 0,
                Err(_) => true,
            };
            if skip_thread {
                process_inspector
                    .resume_thread(tid)
                    .map_err(WriterError::ResumeThreadFailed)?;
                return Err(WriterError::DetachSkippedThread(tid));
            }
        }

        Ok(())
    }

    /// Resumes a suspended thread with `PT_RESUME`.
    fn resume_thread(
        process_inspector: &dyn ProcessInspector,
        tid: Pid,
    ) -> Result<(), WriterError> {
        process_inspector
            .resume_thread(tid)
            .map_err(WriterError::ResumeThreadFailed)
    }

    fn suspend_threads(&mut self, mut soft_errors: impl WriteErrorList<WriterError>) {
        // Iterate over all threads and try to suspend them. If a thread
        // disappeared before we could suspend it, or its register state is
        // not useful, it is OK to silently drop it from the minidump.
        self.threads.retain(|x| {
            match Self::suspend_thread(self.process_inspector.as_ref(), x.tid) {
                Ok(()) => true,
                Err(e) => {
                    soft_errors.push(e);
                    false
                }
            }
        });
        self.threads_suspended = true;
    }

    fn resume_threads(&mut self, mut soft_errors: impl WriteErrorList<WriterError>) {
        if self.threads_suspended {
            for thread in &self.threads {
                if let Err(e) = Self::resume_thread(self.process_inspector.as_ref(), thread.tid) {
                    soft_errors.push(e);
                }
            }
        }
        self.threads_suspended = false;
    }

    /// Copies a block of bytes from the target process, returning the heap
    /// allocated copy.
    pub fn copy_from_process(
        process_inspector: &dyn ProcessInspector,
        src: usize,
        length: usize,
    ) -> Result<Vec<u8>, CopyFromProcessError> {
        let length = std::num::NonZeroUsize::new(length).ok_or_else(|| CopyFromProcessError {
            child: process_inspector.pid().unwrap_or_default(),
            src,
            length,
            source: std::io::Error::other("length is zero"),
        })?;

        let mem = process_inspector.process_reader();
        mem.read_to_vec(src, length)
    }

    /// Copies up to `length` bytes from the target process, stopping at the
    /// first page that can't be read (typically a guard page). Fails only if
    /// nothing could be read at all.
    fn read_until_guard(
        process_inspector: &dyn ProcessInspector,
        page_size: usize,
        src: usize,
        length: usize,
    ) -> Result<Vec<u8>, CopyFromProcessError> {
        let mem = process_inspector.process_reader();
        let mut output = vec![0u8; length];
        let mut offset = 0;
        while offset < length {
            let chunk = (length - offset).min(page_size - (src + offset) % page_size);
            if let Err(e) = mem.read_all(src + offset, &mut output[offset..offset + chunk]) {
                if offset == 0 {
                    return Err(e);
                }
                break;
            }
            offset += chunk;
        }

        output.truncate(offset);
        Ok(output)
    }

    pub fn get_thread_info_by_index(
        &self,
        index: usize,
        soft_errors: impl WriteErrorList<ThreadInfoError>,
    ) -> Result<ThreadInfo, ThreadInfoError> {
        if index >= self.threads.len() {
            return Err(ThreadInfoError::IndexOutOfBounds(index, self.threads.len()));
        }
        ThreadInfo::create(
            self.process_inspector.as_ref(),
            self.threads[index].tid,
            soft_errors,
        )
    }

    pub fn find_mapping(&self, address: usize) -> Option<&MappingInfo> {
        self.mappings
            .iter()
            .find(|map| address >= map.start_address && address - map.start_address < map.size)
    }

    fn may_be_stack(mapping: Option<&MappingInfo>) -> bool {
        mapping.is_some_and(|m| {
            m.permissions
                .intersects(VmPermissions::READ | VmPermissions::WRITE)
        })
    }

    pub fn get_stack_info(&self, int_stack_pointer: usize) -> Result<(usize, usize), WriterError> {
        // Round the stack pointer to the nearest page, this will cause us to
        // capture data below the stack pointer which might still be relevant.
        let mut stack_pointer = int_stack_pointer & !(self.page_size - 1);
        let mut mapping = self.find_mapping(stack_pointer);

        // If the stack pointer doesn't land in a stack-looking mapping (e.g.
        // it is inside a guard region on stack overflow), scan page by page
        // upwards, but give up after 1 MiB.
        let max_scan_addr = stack_pointer.saturating_add(1024 * 1024);

        while !Self::may_be_stack(mapping) && stack_pointer <= max_scan_addr {
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
        // We optimize the search for containing mappings in three ways:
        // 1) We expect that pointers into the stack mapping will be common, so
        //    we cache that address range.
        // 2) The last referenced mapping is a reasonable predictor for the next
        //    referenced mapping, so we test that first.
        // 3) We precompute a bitfield based upon bits 32:32-n of the start and
        //    stop addresses, and use that to short circuit any values that can
        //    not be pointers. (n=11)
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
        let stack_mapping = self.find_mapping(stack_pointer);
        let mut last_hit_mapping: Option<&MappingInfo> = None;
        // The magnitude below which integers are considered to be 'small', and
        // not constitute a PII risk. These are included to avoid eliding
        // useful register values.
        let small_int_magnitude: isize = 4096;

        let mut could_hit_mapping = vec![0u8; array_size];
        // Initialize the bitfield such that if the (pointer >> shift)'th bit,
        // modulo the bitfield size, is not set then there does not exist a
        // mapping in mappings that would contain that pointer.
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

        // Zero memory that is below the current stack pointer.
        let offset =
            (sp_offset + std::mem::size_of::<usize>() - 1) & !(std::mem::size_of::<usize>() - 1);
        // A truncated copy (guard page in the middle of the stack) can be
        // shorter than the rounded offset; never index past the data.
        let offset = offset.min(stack_copy.len());
        for x in &mut stack_copy[0..offset] {
            *x = 0;
        }
        let (chunks, _remainder) =
            stack_copy[offset..].as_chunks_mut::<{ std::mem::size_of::<usize>() }>();

        // Apply sanitization over each complete pointer-aligned word in the
        // stack.
        for sp in chunks {
            let word: [u8; std::mem::size_of::<usize>()] =
                sp.as_slice().try_into().expect("complete chunk");
            let addr = usize::from_ne_bytes(word);
            let addr_signed = isize::from_ne_bytes(word);

            if addr <= small_int_magnitude as usize && addr_signed >= -small_int_magnitude {
                continue;
            }

            if let Some(stack_map) = stack_mapping
                && stack_map.contains_address(addr)
            {
                continue;
            }
            if let Some(last_hit) = last_hit_mapping
                && last_hit.contains_address(addr)
            {
                continue;
            }

            let test = addr >> shift;
            if (could_hit_mapping[(test >> 3) & array_mask] & (1 << (test & 7)) != 0)
                && let Some(hit_mapping) = self.find_mapping(addr)
                && hit_mapping.is_executable()
            {
                last_hit_mapping = Some(hit_mapping);
                continue;
            }

            sp.copy_from_slice(&defaced);
        }

        // Zero any partial word at the top of the stack, if alignment is such
        // that that is required.
        for sp in _remainder {
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

        if let Ok((valid_sp, stack_len)) = self.get_stack_info(stack_pointer)
            && let Ok(stack_copy) =
                Self::copy_from_process(self.process_inspector.as_ref(), valid_sp, stack_len)
        {
            let sp_offset = stack_pointer.saturating_sub(valid_sp);
            return principal_mapping.stack_has_pointer_to_mapping(&stack_copy, sp_offset);
        }

        false
    }

    /// Reads a type implementing [`ReadFromModule`] from the process memory
    /// backing the mapping at `idx`.
    pub fn from_process_memory_for_index<T: super::module_reader::ReadFromModule>(
        &self,
        idx: usize,
    ) -> Result<T, WriterError> {
        assert!(idx < self.mappings.len());
        self.from_process_memory_for_mapping(&self.mappings[idx])
    }

    /// Returns the address where the ELF header of the file backing
    /// `mapping` is mapped, or `None` if it isn't (e.g. an anonymous mapping).
    ///
    /// A file's first mapping has `offset == 0` and its start address is the
    /// ELF base. Subsequent mappings of the same file (`offset != 0`) must
    /// read the ELF header from that first mapping; if it is not visible
    /// (e.g. unmapped), fall back to `start - offset`.
    fn elf_base_for_mapping(&self, mapping: &MappingInfo) -> Option<usize> {
        if mapping.offset == 0 {
            return Some(mapping.start_address);
        }
        let name = mapping.name.as_ref()?;
        Some(
            self.mappings
                .iter()
                .find(|m| m.offset == 0 && m.name.as_ref() == Some(name))
                .map_or_else(
                    || mapping.start_address.saturating_sub(mapping.offset),
                    |base| base.start_address,
                ),
        )
    }

    /// Reads a type implementing [`ReadFromModule`] from the process memory
    /// backing the given mapping.
    pub fn from_process_memory_for_mapping<T: super::module_reader::ReadFromModule>(
        &self,
        mapping: &MappingInfo,
    ) -> Result<T, WriterError> {
        let elf_base = self
            .elf_base_for_mapping(mapping)
            .ok_or(WriterError::NotAModuleMapping)?;
        let reader = self.process_inspector.process_reader();
        Ok(T::read_from_module(
            super::module_reader::ModuleMemory::from_process(&reader, elf_base),
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

        let dirent = self.write_thread_list_stream(
            buffer,
            soft_errors.subwriter(WriterError::WriteThreadListErrors),
        )?;
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
    // A serialization failure must not fail the whole dump; emit an empty
    // stream instead (the errors are also still visible via the log).
    let soft_errors_json_str = match serde_json::to_string_pretty(soft_errors) {
        Ok(json) => json,
        Err(e) => {
            log::error!("failed to serialize soft errors: {e}");
            return Ok(MDRawDirectory {
                stream_type: MDStreamType::MozSoftErrors as u32,
                location: Default::default(),
            });
        }
    };
    let section = MemoryArrayWriter::write_bytes(buffer, soft_errors_json_str.as_bytes());
    Ok(MDRawDirectory {
        stream_type: MDStreamType::MozSoftErrors as u32,
        location: section.location(),
    })
}

impl Drop for MinidumpWriter {
    fn drop(&mut self) {
        // Always try to resume all threads (e.g. in case of error)
        self.resume_threads(error_graph::strategy::DontCare);
        // Always allow the process to run again.
        if self.process_attached {
            self.process_attached = false;
            let _ = self.process_inspector.detach();
        }
        let _ = self.continue_process();
    }
}
