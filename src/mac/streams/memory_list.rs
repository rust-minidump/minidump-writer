use super::*;

impl MiniDumpWriter {
    fn write_memory_list(&mut self, buffer: &mut DumpBuf) -> Result<MDRawDirectory, WriterError> {
        // Include some memory around the instruction pointer if the crash was
        // due to an exception
        const IP_MEM_SIZE: usize = 256;

        if self.crash_context.exc_info.is_some() {
            let mut thread_state = thread_list_stream::ThreadState::default();
            // SAFETY: syscall
            if unsafe {
                mach2::thread_act::thread_get_state(
                    tid,
                    THREAD_STATE_FLAVOR,
                    thread_state.state.as_mut_ptr(),
                    &mut thread_state.state_size,
                )
            } == mach2::kern_return::KERN_SUCCESS
            {
            } else {
                None
            }

            let get_ip_block = |task, tid| -> Option<std::ops::Range> {
                let thread_state = Self::get_thread_state(tid).ok()?;

                let ip = thread_state.pc();

                // Bound it to the upper and lower bounds of the region
                // it's contained within. If it's not in a known memory region,
                // don't bother trying to write it.
                let region = self.get_vm_region(ip).ok()?;

                if ip < region.start || ip > region.end {
                    return None;
                }

                // Try to get IP_MEM_SIZE / 2 bytes before and after the IP, but
                // settle for whatever's available.
                let start = std::cmp::max(region.start, ip - IP_MEM_SIZE / 2);
                let end = std::cmp::min(ip + IP_MEM_SIZE / 2, region.end);

                Some(start..end)
            };

            if let Some(ip_range) = get_ip_block() {
                let size = ip_range.end - ip_range.start;
                let stack_buffer = self.read_task_memory(ip_range.start as _, size)?;
                let ip_location = MDLocationDescriptor {
                    data_size: size as u32,
                    rva: buffer.position() as u32,
                };
                buffer.write_all(&stack_buffer)?;

                self.memory_blocks.push(MDMemoryDescriptor {
                    start_of_memory_range: ip_range.start,
                    memory: ip_location,
                });
            }
        }

        let list_header =
            MemoryWriter::<u32>::alloc_with_val(buffer, self.memory_blocks.len() as u32)?;

        let mut dirent = MDRawDirectory {
            stream_type: MDStreamType::MemoryListStream as u32,
            location: list_header.location(),
        };

        let block_list =
            MemoryArrayWriter::<MDMemoryDescriptor>::alloc_from_array(buffer, &self.memory_blocks)?;

        dirent.location.data_size += block_list.location().data_size;
    }
}
