use {
    super::*,
    crate::{
        mem_writer::{MemoryArrayWriter, MemoryWriter},
        minidump_cpu::RawContextCPU,
    },
    std::cmp::min,
};

const LIMIT_AVERAGE_THREAD_STACK_LENGTH: usize = 8 * 1024;
const LIMIT_BASE_THREAD_COUNT: usize = 20;
const LIMIT_MAX_EXTRA_THREAD_STACK_LEN: usize = 2 * 1024;
const LIMIT_MINIDUMP_FUDGE_FACTOR: u64 = 64 * 1024;

#[derive(Debug, Clone, Copy)]
enum MaxStackLen {
    None,
    Len(usize),
}

#[derive(Debug, thiserror::Error, serde::Serialize)]
pub enum SectionThreadListError {
    #[error("Failed to get thread info")]
    ThreadInfoError(#[from] crate::freebsd::thread_info::ThreadInfoError),
    #[error("Failed to copy from process")]
    CopyFromProcessError(#[from] crate::freebsd::process_reader::CopyFromProcessError),
    #[error("Failed to write to memory")]
    MemoryWriterError(#[from] crate::mem_writer::MemoryWriterError),
    #[error("Failed to sanitize stack copy")]
    SanitizeStackCopyFailed(#[source] Box<WriterError>),
}

impl MinidumpWriter {
    pub fn write_thread_list_stream(
        &mut self,
        buffer: &mut DumpBuf,
    ) -> Result<MDRawDirectory, SectionThreadListError> {
        let num_threads = self.threads.len();

        let list_header = MemoryWriter::<u32>::alloc_with_val(buffer, num_threads as u32)?;

        let mut dirent = MDRawDirectory {
            stream_type: MDStreamType::ThreadListStream as u32,
            location: list_header.location(),
        };

        let mut thread_list = MemoryArrayWriter::<MDRawThread>::alloc_array(buffer, num_threads)?;
        dirent.location.data_size += thread_list.location().data_size;

        let mut extra_thread_stack_len = MaxStackLen::None;
        if let Some(minidump_size_limit) = self.minidump_size_limit {
            let estimated_total_stack_size =
                (num_threads * LIMIT_AVERAGE_THREAD_STACK_LENGTH) as u64;
            let curr_pos = buffer.position();
            let estimated_minidump_size =
                curr_pos + estimated_total_stack_size + LIMIT_MINIDUMP_FUDGE_FACTOR;
            if estimated_minidump_size > minidump_size_limit {
                extra_thread_stack_len = MaxStackLen::Len(LIMIT_MAX_EXTRA_THREAD_STACK_LEN);
            }
        }

        for (idx, item) in self.threads.iter().enumerate() {
            let mut thread = MDRawThread {
                thread_id: item.tid as u32,
                suspend_count: 0,
                priority_class: 0,
                priority: 0,
                teb: 0,
                stack: MDMemoryDescriptor::default(),
                thread_context: MDLocationDescriptor::default(),
            };

            let is_crash_thread = item.tid == self.blamed_thread && self.crash_context.is_some();

            if is_crash_thread {
                if let Some(crash_context) = &self.crash_context {
                    let instruction_ptr = crash_context.get_instruction_pointer();
                    let stack_pointer = crash_context.get_stack_pointer();

                    #[allow(clippy::collapsible_if)]
                    if let Ok((valid_sp, stack_len)) = self.get_stack_info(stack_pointer) {
                        if let Ok(mut stack_copy) =
                            Self::copy_from_process(self.process_id, valid_sp, stack_len)
                        {
                            let sp_offset = stack_pointer.saturating_sub(valid_sp);
                            if !self.should_skip_stack_for_principal(
                                instruction_ptr,
                                &stack_copy,
                                sp_offset,
                            ) {
                                if self.sanitize_stack {
                                    self.sanitize_stack_copy(
                                        &mut stack_copy,
                                        stack_pointer,
                                        sp_offset,
                                    )
                                    .map_err(|e| {
                                        SectionThreadListError::SanitizeStackCopyFailed(Box::new(e))
                                    })?;
                                }

                                let stack_location = MDLocationDescriptor {
                                    data_size: stack_copy.len() as u32,
                                    rva: buffer.position() as u32,
                                };
                                buffer.write_all(&stack_copy);
                                thread.stack.start_of_memory_range = valid_sp as u64;
                                thread.stack.memory = stack_location;
                                self.memory_blocks.push(thread.stack);
                            }
                        } else {
                            log::warn!(
                                "Failed to copy stack for crash thread (tid={}): stack may be missing from dump",
                                item.tid
                            );
                        }
                    }

                    let mut cpu: RawContextCPU = Default::default();
                    crash_context.fill_cpu_context(&mut cpu);
                    let cpu_section = MemoryWriter::alloc_with_val(buffer, cpu)?;
                    thread.thread_context = cpu_section.location();
                    self.crashing_thread_context =
                        CrashingThreadContext::CrashContext(cpu_section.location());
                }
            } else {
                let info = self.get_thread_info_by_index(idx)?;
                let instruction_ptr = info.get_instruction_pointer();
                let stack_pointer = info.get_stack_pointer();
                let max_stack_len =
                    if self.minidump_size_limit.is_some() && idx >= LIMIT_BASE_THREAD_COUNT {
                        extra_thread_stack_len
                    } else {
                        MaxStackLen::None
                    };

                #[allow(clippy::collapsible_if)]
                if let Ok((valid_sp, stack_len)) = self.get_stack_info(stack_pointer) {
                    let stack_len = if let MaxStackLen::Len(max_len) = max_stack_len {
                        min(stack_len, max_len)
                    } else {
                        stack_len
                    };
                    if let Ok(mut stack_copy) =
                        Self::copy_from_process(self.process_id, valid_sp, stack_len)
                    {
                        let sp_offset = stack_pointer.saturating_sub(valid_sp);
                        if !self.should_skip_stack_for_principal(
                            instruction_ptr,
                            &stack_copy,
                            sp_offset,
                        ) {
                            if self.sanitize_stack {
                                self.sanitize_stack_copy(&mut stack_copy, stack_pointer, sp_offset)
                                    .map_err(|e| {
                                        SectionThreadListError::SanitizeStackCopyFailed(Box::new(e))
                                    })?;
                            }

                            let stack_location = MDLocationDescriptor {
                                data_size: stack_copy.len() as u32,
                                rva: buffer.position() as u32,
                            };
                            buffer.write_all(&stack_copy);
                            thread.stack.start_of_memory_range = valid_sp as u64;
                            thread.stack.memory = stack_location;
                            self.memory_blocks.push(thread.stack);
                        }
                    } else {
                        log::warn!(
                            "Failed to copy stack for thread (tid={}): stack may be missing from dump",
                            item.tid
                        );
                    }
                }

                let cpu_section = MemoryWriter::alloc_with_val(buffer, info.registers)?;
                thread.thread_context = cpu_section.location();

                if item.tid == self.blamed_thread {
                    self.crashing_thread_context = CrashingThreadContext::CrashContextPlusAddress(
                        (cpu_section.location(), instruction_ptr),
                    );
                }
            }

            thread_list.set_value_at(buffer, thread, idx)?;
        }

        Ok(dirent)
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
