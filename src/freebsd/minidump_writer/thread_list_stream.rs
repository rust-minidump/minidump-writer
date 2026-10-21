use {
    super::*,
    crate::{
        freebsd::{process_inspection::CopyFromProcessError, thread_info::ThreadInfoError},
        mem_writer::{MemoryArrayWriter, MemoryWriter},
        minidump_cpu::RawContextCPU,
    },
    error_graph::WriteErrorList,
    std::cmp::min,
};

const LIMIT_AVERAGE_THREAD_STACK_LENGTH: usize = 8 * 1024;
const LIMIT_BASE_THREAD_COUNT: usize = 20;
const LIMIT_MAX_EXTRA_THREAD_STACK_LEN: usize = 2 * 1024;
const LIMIT_MINIDUMP_FUDGE_FACTOR: u64 = 64 * 1024;

#[derive(Debug, thiserror::Error, serde::Serialize)]
pub enum SectionThreadListError {
    #[error("Failed to get thread info")]
    ThreadInfoError(#[from] ThreadInfoError),
    #[error("Failed to copy from process")]
    CopyFromProcessError(#[from] CopyFromProcessError),
    #[error("Failed to write to memory")]
    MemoryWriterError(#[from] crate::mem_writer::MemoryWriterError),
    #[error("Failed to sanitize stack copy")]
    SanitizeStackCopyFailed(#[source] Box<WriterError>),
    #[error("Failed to get stack info")]
    GetStackInfoFailed(#[source] Box<WriterError>),
    #[error("Non-essential thread info errors")]
    ThreadInfoSoftErrors(#[source] error_graph::ErrorList<ThreadInfoError>),
}

impl MinidumpWriter {
    pub fn write_thread_list_stream(
        &mut self,
        buffer: &mut DumpBuf,
        mut soft_errors: impl WriteErrorList<SectionThreadListError>,
    ) -> Result<MDRawDirectory, SectionThreadListError> {
        let num_threads = self.threads.len();

        let list_header = MemoryWriter::<u32>::alloc_with_val(buffer, num_threads as u32)?;

        let mut dirent = MDRawDirectory {
            stream_type: MDStreamType::ThreadListStream as u32,
            location: list_header.location(),
        };

        let mut thread_list = MemoryArrayWriter::<MDRawThread>::alloc_array(buffer, num_threads)?;
        dirent.location.data_size += thread_list.location().data_size;

        // When the size limit is in danger of being exceeded, cap the stack
        // size of threads beyond the base count.
        let mut extra_thread_stack_len = usize::MAX;
        if let Some(minidump_size_limit) = self.minidump_size_limit {
            let estimated_total_stack_size =
                (num_threads * LIMIT_AVERAGE_THREAD_STACK_LENGTH) as u64;
            let estimated_minidump_size =
                buffer.position() + estimated_total_stack_size + LIMIT_MINIDUMP_FUDGE_FACTOR;
            if estimated_minidump_size > minidump_size_limit {
                extra_thread_stack_len = LIMIT_MAX_EXTRA_THREAD_STACK_LEN;
            }
        }

        for idx in 0..num_threads {
            let tid = self.threads[idx].tid;
            let mut thread = MDRawThread {
                thread_id: tid as u32,
                suspend_count: 0,
                priority_class: 0,
                priority: 0,
                teb: 0,
                stack: MDMemoryDescriptor::default(),
                thread_context: MDLocationDescriptor::default(),
            };

            if let Some(crash_context) = self
                .crash_context
                .as_ref()
                .filter(|_| tid == self.blamed_thread)
            {
                // We have different information for the crashing thread: its
                // actual state would be somewhere inside the signal handler,
                // which is deeply unhelpful.
                let instruction_ptr = crash_context.get_instruction_pointer();
                let stack_pointer = crash_context.get_stack_pointer();

                // Fill the register context first so the `crash_context`
                // borrow ends before the `&mut self` calls below.
                let mut cpu = RawContextCPU::default();
                crash_context.fill_cpu_context(&mut cpu);

                self.write_thread_stack(
                    buffer,
                    &mut thread,
                    instruction_ptr,
                    stack_pointer,
                    usize::MAX,
                    &mut soft_errors,
                )?;
                self.write_crashing_thread_ip_memory(buffer, instruction_ptr, &mut soft_errors)?;

                let cpu_section = MemoryWriter::alloc_with_val(buffer, cpu)?;
                thread.thread_context = cpu_section.location();
                self.crashing_thread_context =
                    CrashingThreadContext::CrashContext(cpu_section.location());
            } else {
                let info = self.get_thread_info_by_index(
                    idx,
                    soft_errors.subwriter(SectionThreadListError::ThreadInfoSoftErrors),
                )?;
                let instruction_ptr = info.get_instruction_pointer();
                let max_stack_len = if idx >= LIMIT_BASE_THREAD_COUNT {
                    extra_thread_stack_len
                } else {
                    usize::MAX
                };

                self.write_thread_stack(
                    buffer,
                    &mut thread,
                    instruction_ptr,
                    info.get_stack_pointer(),
                    max_stack_len,
                    &mut soft_errors,
                )?;

                let mut cpu = RawContextCPU::default();
                info.fill_cpu_context(&mut cpu);
                let cpu_section = MemoryWriter::alloc_with_val(buffer, cpu)?;
                thread.thread_context = cpu_section.location();

                // Without a crash context the blamed thread's registers are
                // the best guess for the crash location.
                if tid == self.blamed_thread {
                    self.crashing_thread_context = CrashingThreadContext::CrashContextPlusAddress(
                        (cpu_section.location(), instruction_ptr),
                    );
                }
            }

            thread_list.set_value_at(buffer, thread, idx)?;
        }

        Ok(dirent)
    }

    /// Copies 256 bytes around the crashing instruction pointer into the
    /// dump: stack walkers rely on this to resolve the faulting instruction.
    fn write_crashing_thread_ip_memory(
        &mut self,
        buffer: &mut DumpBuf,
        instruction_ptr: usize,
        soft_errors: &mut impl WriteErrorList<SectionThreadListError>,
    ) -> Result<(), SectionThreadListError> {
        let Some(mapping) = self.find_mapping(instruction_ptr) else {
            return Ok(());
        };

        // Try to get 128 bytes before and after the IP, bounded by the
        // mapping it's contained within.
        let start = mapping
            .start_address
            .max(instruction_ptr.saturating_sub(128));
        let end = (mapping.start_address + mapping.size).min(instruction_ptr + 128);

        let mut ip_memory = MDMemoryDescriptor {
            start_of_memory_range: start as u64,
            memory: Default::default(),
        };
        ip_memory.memory.data_size = (end - start) as u32;

        let memory_copy = match Self::copy_from_process(
            self.process_inspector.as_ref(),
            start,
            ip_memory.memory.data_size as usize,
        ) {
            Ok(copy) => copy,
            Err(e) => {
                soft_errors.push(SectionThreadListError::CopyFromProcessError(e));
                return Ok(());
            }
        };
        let section = MemoryArrayWriter::alloc_from_array(buffer, &memory_copy)?;
        ip_memory.memory = section.location();
        self.memory_blocks.push(ip_memory);

        Ok(())
    }

    /// Copies the stack of a thread into the dump, sanitizing it if enabled,
    /// and fills in `thread.stack`.
    ///
    /// Failures to locate or copy the stack are soft: the stack is simply
    /// omitted from the dump and recorded in the soft-error list.
    fn write_thread_stack(
        &mut self,
        buffer: &mut DumpBuf,
        thread: &mut MDRawThread,
        instruction_ptr: usize,
        stack_pointer: usize,
        max_stack_len: usize,
        soft_errors: &mut impl WriteErrorList<SectionThreadListError>,
    ) -> Result<(), SectionThreadListError> {
        let stack_info = self.get_stack_info(stack_pointer);
        let (valid_sp, stack_len) = match stack_info {
            Ok(x) => x,
            Err(e) => {
                soft_errors.push(SectionThreadListError::GetStackInfoFailed(Box::new(e)));
                return Ok(());
            }
        };
        let stack_len = min(stack_len, max_stack_len);

        let mut stack_copy = match Self::read_until_guard(
            self.process_inspector.as_ref(),
            self.page_size,
            valid_sp,
            stack_len,
        ) {
            Ok(copy) => copy,
            Err(e) => {
                soft_errors.push(SectionThreadListError::CopyFromProcessError(e));
                return Ok(());
            }
        };

        let sp_offset = stack_pointer.saturating_sub(valid_sp);
        if self.should_skip_stack_for_principal(instruction_ptr, &stack_copy, sp_offset) {
            return Ok(());
        }

        if self.sanitize_stack {
            self.sanitize_stack_copy(&mut stack_copy, stack_pointer, sp_offset)
                .map_err(|e| SectionThreadListError::SanitizeStackCopyFailed(Box::new(e)))?;
        }

        thread.stack = MDMemoryDescriptor {
            start_of_memory_range: valid_sp as u64,
            memory: MDLocationDescriptor {
                data_size: stack_copy.len() as u32,
                rva: buffer.position() as u32,
            },
        };
        buffer.write_all(&stack_copy);
        self.memory_blocks.push(thread.stack);

        Ok(())
    }

    fn should_skip_stack_for_principal(
        &self,
        instruction_ptr: usize,
        stack_copy: &[u8],
        sp_offset: usize,
    ) -> bool {
        if !self.skip_stacks_if_mapping_unreferenced {
            return false;
        }

        let Some(principal_mapping) = &self.principal_mapping else {
            return true;
        };

        !principal_mapping.contains_address(instruction_ptr)
            && !principal_mapping.stack_has_pointer_to_mapping(stack_copy, sp_offset)
    }
}
