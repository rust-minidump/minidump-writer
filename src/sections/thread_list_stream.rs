use crate::linux_ptrace_dumper::LinuxPtraceDumper;
use crate::minidump_cpu::RawContextCPU;
use crate::minidump_format::*;
use crate::minidump_writer::{DumpBuf, MinidumpWriter};
use crate::sections::{MemoryArrayWriter, MemoryWriter};
use crate::thread_info::ThreadInfo;
use crate::Result;
use std::convert::TryInto;
use std::io::Write;

// The following kLimit* constants are for when minidump_size_limit_ is set
// and the minidump size might exceed it.
//
// Estimate for how big each thread's stack will be (in bytes).
const LIMIT_AVERAGE_THREAD_STACK_LENGTH: usize = 8 * 1024;
// Number of threads whose stack size we don't want to limit.  These base
// threads will simply be the first N threads returned by the dumper (although
// the crashing thread will never be limited).  Threads beyond this count are
// the extra threads.
const LIMIT_BASE_THREAD_COUNT: usize = 20;
// Maximum stack size to dump for any extra thread (in bytes).
const LIMIT_MAX_EXTRA_THREAD_STACK_LEN: i32 = 2 * 1024;
// Make sure this number of additional bytes can fit in the minidump
// (exclude the stack data).
const LIMIT_MINIDUMP_FUDGE_FACTOR: u64 = 64 * 1024;

pub fn write(
    config: &mut MinidumpWriter,
    buffer: &mut DumpBuf,
    dumper: &LinuxPtraceDumper,
) -> Result<MDRawDirectory> {
    let num_threads = dumper.threads.len();
    // Memory looks like this:
    // <num_threads><thread_1><thread_2>...

    let list_header = MemoryWriter::<u32>::alloc_with_val(buffer, num_threads as u32)?;

    let mut dirent = MDRawDirectory {
        stream_type: MDStreamType::ThreadListStream as u32,
        location: list_header.location(),
    };

    let mut thread_list = MemoryArrayWriter::<MDRawThread>::alloc_array(buffer, num_threads)?;
    dirent.location.data_size += thread_list.location().data_size;
    // If there's a minidump size limit, check if it might be exceeded.  Since
    // most of the space is filled with stack data, just check against that.
    // If this expects to exceed the limit, set extra_thread_stack_len such
    // that any thread beyond the first kLimitBaseThreadCount threads will
    // have only kLimitMaxExtraThreadStackLen bytes dumped.
    let mut extra_thread_stack_len = -1; // default to no maximum
    if let Some(minidump_size_limit) = config.minidump_size_limit {
        let estimated_total_stack_size = (num_threads * LIMIT_AVERAGE_THREAD_STACK_LENGTH) as u64;
        let curr_pos = buffer.position();
        let estimated_minidump_size =
            curr_pos + estimated_total_stack_size + LIMIT_MINIDUMP_FUDGE_FACTOR;
        if estimated_minidump_size > minidump_size_limit {
            extra_thread_stack_len = LIMIT_MAX_EXTRA_THREAD_STACK_LEN;
        }
    }

    for (idx, item) in dumper.threads.clone().iter().enumerate() {
        let mut thread = MDRawThread::default();
        thread.thread_id = (*item).try_into()?;

        // We have a different source of information for the crashing thread. If
        // we used the actual state of the thread we would find it running in the
        // signal handler with the alternative stack, which would be deeply
        // unhelpful.
        if false {
            // Currently, no support for ucontext yet, so this is always false:
            //       if (static_cast<pid_t>(thread.thread_id) == GetCrashThread() &&
            //           ucontext_ &&
            //           !dumper_->IsPostMortem())
        } else {
            let info = dumper.get_thread_info_by_index(idx)?;
            let max_stack_len =
                if config.minidump_size_limit.is_some() && idx >= LIMIT_BASE_THREAD_COUNT {
                    extra_thread_stack_len
                } else {
                    -1 // default to no maximum for this thread
                };

            fill_thread_stack(config, buffer, dumper, &mut thread, &info, max_stack_len)?;

            // let cpu = MemoryWriter::<RawContextCPU>::alloc(buffer)?;
            let mut cpu = RawContextCPU::default();
            info.fill_cpu_context(&mut cpu);
            let cpu_section = MemoryWriter::<RawContextCPU>::alloc_with_val(buffer, cpu)?;
            thread.thread_context = cpu_section.location();
            // if item == &self.blamed_thread {
            //     // This is the crashing thread of a live process, but
            //     // no context was provided, so set the crash address
            //     // while the instruction pointer is already here.
            //     self.crashing_thread_context = cpu_section.location();
            //     self.dumper
            //         .set_crash_address(info.get_instruction_pointer());
            // }
        }
        thread_list.set_value_at(buffer, thread, idx)?;
    }
    Ok(dirent)
}

fn fill_thread_stack(
    config: &mut MinidumpWriter,
    buffer: &mut DumpBuf,
    dumper: &LinuxPtraceDumper,
    thread: &mut MDRawThread,
    info: &ThreadInfo,
    max_stack_len: i32,
) -> Result<()> {
    let pc = info.get_instruction_pointer() as usize;

    thread.stack.start_of_memory_range = info.stack_pointer.try_into()?;
    thread.stack.memory.data_size = 0;
    thread.stack.memory.rva = buffer.position() as u32;

    if let Ok((mut stack, mut stack_len)) = dumper.get_stack_info(info.stack_pointer) {
        if max_stack_len >= 0 && stack_len > max_stack_len as usize {
            stack_len = max_stack_len as usize; // Casting is ok, as we checked that its positive

            // Skip empty chunks of length max_stack_len.
            // Meaning != 0
            if stack_len > 0 {
                while stack + stack_len < info.stack_pointer {
                    stack += stack_len;
                }
            }
        }
        let mut stack_bytes = LinuxPtraceDumper::copy_from_process(
            thread.thread_id.try_into()?,
            stack as *mut libc::c_void,
            stack_len.try_into()?,
        )?;
        let stack_pointer_offset = info.stack_pointer - stack;
        if config.skip_stacks_if_mapping_unreferenced {
            if let Some(principal_mapping) = &config.principal_mapping {
                let low_addr = principal_mapping.system_mapping_info.start_address;
                let high_addr = principal_mapping.system_mapping_info.end_address;
                if (pc < low_addr || pc > high_addr)
                    && !principal_mapping
                        .stack_has_pointer_to_mapping(&stack_bytes, stack_pointer_offset)
                {
                    return Ok(());
                }
            } else {
                return Ok(());
            }
        }

        if config.sanitize_stack {
            dumper.sanitize_stack_copy(
                &mut stack_bytes,
                info.stack_pointer,
                stack_pointer_offset,
            )?;
        }

        let stack_location = MDLocationDescriptor {
            data_size: stack_bytes.len() as u32,
            rva: buffer.position() as u32,
        };
        buffer.write_all(&stack_bytes)?;
        thread.stack.start_of_memory_range = stack as u64;
        thread.stack.memory = stack_location;
        config.memory_blocks.push(thread.stack.clone());
    }
    Ok(())
}
