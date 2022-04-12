use super::*;

// From /usr/include/mach/machine/thread_state.h
const THREAD_STATE_MAX: usize = 1296;

cfg_if::cfg_if! {
    if #[cfg(target_arch = "x86_64")] {
        /// x86_THREAD_STATE64 in /usr/include/mach/i386/thread_status.h
        const THREAD_STATE_FLAVOR: u32 = 4;
    } else if #[cfg(target_arch = "aarch64")] {
        /// ARM_THREAD_STATE64 in /usr/include/mach/arm/thread_status.h
        const THREAD_STATE_FLAVOR: u32 = 6;

        // Missing from mach2 atm
        // _STRUCT_ARM_THREAD_STATE64 from /usr/include/mach/arm/_structs.h
        #[repr(C)]
        struct Arm64ThreadState {
            x: [u64; 29],
            fp: u64,
            lr: u64,
            sp: u64,
            pc: u64,
            cpsr: u32,
            __pad: u32,
        }
    }
}

struct ThreadState {
    state: [u32; THREAD_STATE_MAX],
    state_size: u32,
}

impl Default for ThreadState {
    fn default() -> Self {
        Self {
            state: [0u32; THREAD_STATE_MAX],
            state_size: THREAD_STATE_MAX * std::mem::size_of::<u32>() as u32,
        }
    }
}

impl ThreadState {
    pub fn pc(&self) -> u64 {
        cfg_if::cfg_if! {
            if #[cfg(target_arch = "x86_64")] {
                let x86_64_state: &mach2::structs::x86_thread_state64_t = &*(thread_state.state.as_ptr().cast());
                x86_64_state.__pc
            } else if #[cfg(target_arch = "aarch64")] {
                let aarch64_state: &Arm64ThreadState = &*(thread_state.state.as_ptr().cast());
                aarch64_state.pc
            }
        }
    }
}

pub(crate) struct VMRegionInfo {
    pub(crate) info: mach2::vm_region::vm_region_submap_info_64,
    pub(crate) range: std::ops::Range<u64>,
}

impl MinidumpWriter {
    fn write_thread_list(&mut self, buffer: &mut DumpBuf) -> Result<MDRawDirectory, WriterError> {
        // Retrieve the list of threads from the task that crashed.
        // SAFETY: syscall
        let mut threads = std::ptr::null_mut();
        let mut thread_count = 0;

        kern_ret(|| unsafe {
            mach2::task::task_threads(self.crash_context.task, &mut threads, &mut thread_count)
        })?;

        // Ignore the thread that handled the exception
        if self.crash_context.handler_thread != mach2::port::MACH_PORT_NULL {
            thread_count -= 1;
        }

        let list_header = MemoryWriter::<u32>::alloc_with_val(buffer, thread_count as u32)?;

        let mut dirent = MDRawDirectory {
            stream_type: MDStreamType::ThreadListStream as u32,
            location: list_header.location(),
        };

        let mut thread_list = MemoryArrayWriter::<MDRawThread>::alloc_array(buffer, num_threads)?;
        dirent.location.data_size += thread_list.location().data_size;

        let threads = unsafe { std::slice::from_raw_parts(threads, thread_count as usize) };

        for (i, tid) in threads.iter().enumerate() {
            let thread = self.write_thread(buffer, tid)?;
            thread_list.set_value_at(buffer, thread, i)?;
        }

        Ok(dirent)
    }

    fn write_thread(&mut self, buffer: &mut DumpBuf, tid: u32) -> Result<MDRawThread, WriterError> {
        let mut thread = MDRawThread {
            thread_id: tid,
            suspend_count: 0,
            priority_class: 0,
            priority: 0,
            teb: 0,
            stack: MDMemoryDescriptor::default(),
            thread_context: MDLocationDescriptor::default(),
        };

        let thread_state = Self::get_thread_state(tid)?;

        cfg_if::cfg_if! {
            if #[cfg(target_arch = "x86_64")] {
                let x86_64_state: &mach2::structs::x86_thread_state64_t = &*(thread_state.state.as_ptr().cast());

                self.write_stack_from_start_address(x86_64_state.__rsp, buffer, &mut thread)?;
            } else if #[cfg(target_arch = "aarch64")] {
                let aarch64_state: &Arm64ThreadState = &*(thread_state.state.as_ptr().cast());
                self.write_stack_from_start_address(aarch64_state.sp, buffer, &mut thread)?;
            } else {
                compile_error!("unsupported target arch");
            }
        }

        let mut cpu: RawContextCPU = Default::default();
        Self::fill_cpu_context(thread_state, &mut cpu);
        let cpu_section = MemoryWriter::alloc_with_val(buffer, cpu)?;
        thread.thread_context = cpu_section.location();
        Ok(thread)
    }

    fn get_thread_state(tid: u32) -> Result<ThreadState, WriterError> {
        let mut thread_state = ThreadState::default();

        // SAFETY: syscall
        kern_ret(|| unsafe {
            mach2::thread_act::thread_get_state(
                tid,
                THREAD_STATE_FLAVOR,
                thread_state.state.as_mut_ptr(),
                &mut thread_state.state_size,
            )
        })?;

        Ok(thread_state)
    }

    fn write_stack_from_start_address(
        &mut self,
        start: u64,
        buffer: &mut DumpBuf,
        thread: &mut MDRawThread,
    ) -> Result<(), WriterError> {
        thread.stack.start_of_memory_range = start.try_into()?;
        thread.stack.memory.data_size = 0;
        thread.stack.memory.rva = buffer.position() as u32;

        let stack_size = self.calculate_stack_size(start);

        let stack_location = if stack_size == 0 {
            // In some situations the stack address for the thread can come back 0.
            // In these cases we skip over the threads in question and stuff the
            // stack with a clearly borked value.
            thread.stack.start_of_memory_range = 0xdeadbeef;

            let stack_location = MDLocationDescriptor {
                data_size: 16,
                rva: buffer.position() as u32,
            };
            buffer.write_all(0xdeadbeefu64.as_ne_bytes())?;
            buffer.write_all(0xdeadbeefu64.as_ne_bytes())?;
            stack_location
        } else {
            let stack_buffer = self.read_task_memory(start, stack_size)?;
            let stack_location = MDLocationDescriptor {
                data_size: stack_buffer.len() as u32,
                rva: buffer.position() as u32,
            };
            buffer.write_all(&stack_buffer)?;
            stack_location
        };

        thread.stack.memory = stack_location;
        self.memory_blocks.push(thread.stack);
        Ok(())
    }

    fn calculate_stack_size(&self, start_address: u64) -> usize {
        if start_address == 0 {
            return 0;
        }

        let mut region = if let Ok(region) = self.get_vm_region(start_address) {
            region
        } else {
            return 0;
        };

        // Failure or stack corruption, since mach_vm_region had to go
        // higher in the process address space to find a valid region.
        if start_address < region.range.start {
            return 0;
        }

        // If the user tag is VM_MEMORY_STACK, look for more readable regions with
        // the same tag placed immediately above the computed stack region. Under
        // some circumstances, the stack for thread 0 winds up broken up into
        // multiple distinct abutting regions. This can happen for several reasons,
        // including user code that calls setrlimit(RLIMIT_STACK, ...) or changes
        // the access on stack pages by calling mprotect.
        if region.info.user_tag == mach2::vm_statistics::VM_MEMORY_STACK {
            loop {
                let proposed_next_region_base = region.range.end;

                region = if let Ok(reg) = self.get_vm_region(region.range.end) {
                    reg
                } else {
                    break;
                };

                if region.range.start != proposed_next_region_base
                    || region.info.user_tag != mach2::vm_statistics::VM_MEMORY_STACK
                    || (region.info.protection & mach2::vm_prot::VM_PROT_READ) == 0
                {
                    break;
                }

                stack_region_size += region.range.end - region.range.start;
            }
        }

        stack_region_base + stack_region_size - start_addr
    }

    fn read_task_memory(&self, address: u64, length: usize) -> Result<Vec<u8>, WriterError> {
        let sys_page_size = libc::getpagesize();

        // use the negative of the page size for the mask to find the page address
        let page_address = address & (-sys_page_size);
        let last_page_address = (address + length + (sys_page_size - 1)) & (-sys_page_size);

        let page_size = last_page_address - page_address;
        let mut local_start = std::ptr::null_mut();
        let mut local_length = 0;

        kern_ret(|| unsafe {
            mach2::vm::mach_vm_read(
                self.crash_context.task,
                page_address,
                page_size,
                &mut local_start,
                &mut local_length,
            )
        })?;

        let mut buffer = Vec::with_capacity(length);

        let task_buffer =
            std::slice::from_raw_parts(local_start.offset(address - page_address), length);
        buffer.extend_from_slice(task_buffer);

        // Don't worry about the return here, if something goes wrong there's probably
        // not much we can do about, and we have what we want anyways
        mach2::vm::mach_vm_deallocate(mach2::traps::mach_task_self(), local_start, local_length);

        Ok(buffer)
    }

    fn fill_cpu_context(thread_state: &ThreadState, out: &mut RawContextCPU) {
        cfg_if::cfg_if! {
            if #[cfg(target_arch = "x86_64")] {
                out.context_flags = format::ContextFlagsCpu::CONTEXT_AMD64.bits();

                let ts: &Arm64ThreadState = &*(thread_state.state.as_ptr().cast());

                out.rax = ts.__rax;
                out.rbx = ts.__rbx;
                out.rcx = ts.__rcx;
                out.rdx = ts.__rdx;
                out.rdi = ts.__rdi;
                out.rsi = ts.__rsi;
                out.rbp = ts.__rbp;
                out.rsp = ts.__rsp;
                out.r8 = ts.__r8;
                out.r9 = ts.__r9;
                out.r10 = ts.__r10;
                out.r11 = ts.__r11;
                out.r12 = ts.__r12;
                out.r13 = ts.__r13;
                out.r14 = ts.__r14;
                out.r15 = ts.__r15;
                out.rip = ts.__rip;
                // according to AMD's software developer guide, bits above 18 are
                // not used in the flags register.  Since the minidump format
                // specifies 32 bits for the flags register, we can truncate safely
                // with no loss.
                out.eflags = ts.__rflags as _;
                out.cs = ts.__cs;
                out.fs = ts.__fs;
                out.gs = ts.__gs;
            } else if #[cfg(target_arch = "aarch64")] {
                // This is kind of a lie as we don't actually include the full float state..?
                out.context_flags = format::ContextFlagsArm64Old::CONTEXT_ARM64_OLD_FULL.bits() as u64;

                let ts: &Arm64ThreadState = &*(thread_state.state.as_ptr().cast());

                out.cpsr = ts.cpsr;
                out.iregs[..28].copy_from_slice(&ts.x[..28]);
                out.iregs[29] = ts.fp;
                out.iregs[30] = ts.lr;
                out.sp = ts.sp;
                out.pc = ts.pc;
            } else {
                compile_error!("unsupported target arch");
            }
        }
    }

    fn get_vm_region(&self, addr: u64) -> Result<VMRegionInfo, WriterError> {
        let mut region_base = addr;
        let mut region_size = 0;
        let mut nesting_level = 0;
        let mut region_info = 0;
        let mut submap_info = std::mem::MaybeUninit::<vm_region_submap_info_64>::uninit();

        // mach/vm_region.h
        const VM_REGION_SUBMAP_INFO_COUNT_64: u32 =
            (std::mem::size_of::<vm_region_submap_info_data_64_t>()
                / std::mem::size_of::<mach2::natural_t>()) as u32;

        let mut info_count = VM_REGION_SUBMAP_INFO_COUNT_64;

        kern_ret(||
            // SAFETY: syscall
            unsafe {
                mach2::vm::mach_vm_region_recurse(
                self.crash_context.task,
                &mut region_base,
                &mut region_size,
                &mut nesting_level,
                submap_info.as_mut_ptr().cast(),
                &mut info_count,
            )
        })?;

        Ok(VMRegionInfo {
            // SAFETY: this will be valid if the syscall succeeded
            info: unsafe { submap_info.assume_init() },
            range: region_base..region_base + region_base,
        })
    }
}
