use crate::linux_ptrace_dumper::LinuxPtraceDumper;
use crate::minidump_cpu::RawContextCPU;
use crate::minidump_format::*;
use crate::thread_info::Pid;
use crate::thread_info::ThreadInfo;
use crate::Result;
use std::convert::TryInto;
use std::io::Cursor;

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

#[derive(Debug)]
struct MinidumpWriter {
    dumper: LinuxPtraceDumper,
    minidump_path: String,
    minidump_size_limit: i64,
}

// This doesn't work yet:
// https://github.com/rust-lang/rust/issues/43408
// fn write<T: Sized, P: AsRef<Path>>(path: P, value: T) -> Result<()> {
//     let mut file = std::fs::File::open(path)?;
//     let bytes: [u8; size_of::<T>()] = unsafe { transmute(value) };
//     file.write_all(&bytes)?;
//     Ok(())
// }

impl MinidumpWriter {
    fn new(minidump_path: &str, dumper: LinuxPtraceDumper) -> Self {
        MinidumpWriter {
            dumper,
            minidump_path: minidump_path.to_string(),
            minidump_size_limit: -1,
        }
    }

    fn init(&mut self) -> Result<()> {
        self.dumper.suspend_threads()?;
        // TODO: Doesn't exist yet
        //self.dumper.late_init()?;

        Ok(())
    }

    fn dump(&self) -> Result<()> {
        // A minidump file contains a number of tagged streams. This is the number
        // of stream which we write.
        let num_writers = 13u32;

        // TypedMDRVA<MDRawDirectory> dir(&minidump_writer_);

        // let mut file = std::fs::File::open(&self.minidump_path)?;
        let mut buffer = Cursor::new(Vec::new());

        let mut dir_section =
            SectionArrayWriter::<MDRawDirectory>::alloc_array(&mut buffer, num_writers as usize)?;

        let mut header_section = SectionWriter::<MDRawHeader>::alloc(&mut buffer)?;

        let header = MDRawHeader {
            signature: MD_HEADER_SIGNATURE,
            version: MD_HEADER_VERSION,
            stream_count: num_writers,
            //   header.get()->stream_directory_rva = dir.position();
            stream_directory_rva: dir_section.position as u32,
            checksum: 0, /* Can be 0.  In fact, that's all that's
                          * been found in minidump files. */
            time_date_stamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs() as u32, // TODO: This is not Y2038 safe, but thats how its currently defined as
            flags: 0,
        };
        header_section.set_value(&mut buffer, header)?;

        // Ensure the header gets flushed. If we crash somewhere below,
        // we should have a mostly-intact dump
        // TODO: Write header_section to file here

        self.write_thread_list_stream(&mut buffer)?;

        Ok(())

        // unsigned dir_index = 0;
        // MDRawDirectory dirent;

        // if (!WriteThreadListStream(&dirent))
        //   return false;
        // dir.CopyIndex(dir_index++, &dirent);

        // if (!WriteMappings(&dirent))
        //   return false;
        // dir.CopyIndex(dir_index++, &dirent);

        // if (!WriteAppMemory())
        //   return false;

        // if (!WriteMemoryListStream(&dirent))
        //   return false;
        // dir.CopyIndex(dir_index++, &dirent);

        // if (!WriteExceptionStream(&dirent))
        //   return false;
        // dir.CopyIndex(dir_index++, &dirent);

        // if (!WriteSystemInfoStream(&dirent))
        //   return false;
        // dir.CopyIndex(dir_index++, &dirent);

        // dirent.stream_type = MD_LINUX_CPU_INFO;
        // if (!WriteFile(&dirent.location, "/proc/cpuinfo"))
        //   NullifyDirectoryEntry(&dirent);
        // dir.CopyIndex(dir_index++, &dirent);

        // dirent.stream_type = MD_LINUX_PROC_STATUS;
        // if (!WriteProcFile(&dirent.location, GetCrashThread(), "status"))
        //   NullifyDirectoryEntry(&dirent);
        // dir.CopyIndex(dir_index++, &dirent);

        // dirent.stream_type = MD_LINUX_LSB_RELEASE;
        // if (!WriteFile(&dirent.location, "/etc/lsb-release") &&
        //     !WriteFile(&dirent.location, "/etc/os-release")) {
        //   NullifyDirectoryEntry(&dirent);
        // }
        // dir.CopyIndex(dir_index++, &dirent);

        // dirent.stream_type = MD_LINUX_CMD_LINE;
        // if (!WriteProcFile(&dirent.location, GetCrashThread(), "cmdline"))
        //   NullifyDirectoryEntry(&dirent);
        // dir.CopyIndex(dir_index++, &dirent);

        // dirent.stream_type = MD_LINUX_ENVIRON;
        // if (!WriteProcFile(&dirent.location, GetCrashThread(), "environ"))
        //   NullifyDirectoryEntry(&dirent);
        // dir.CopyIndex(dir_index++, &dirent);

        // dirent.stream_type = MD_LINUX_AUXV;
        // if (!WriteProcFile(&dirent.location, GetCrashThread(), "auxv"))
        //   NullifyDirectoryEntry(&dirent);
        // dir.CopyIndex(dir_index++, &dirent);

        // dirent.stream_type = MD_LINUX_MAPS;
        // if (!WriteProcFile(&dirent.location, GetCrashThread(), "maps"))
        //   NullifyDirectoryEntry(&dirent);
        // dir.CopyIndex(dir_index++, &dirent);

        // dirent.stream_type = MD_LINUX_DSO_DEBUG;
        // if (!WriteDSODebugStream(&dirent))
        //   NullifyDirectoryEntry(&dirent);
        // dir.CopyIndex(dir_index++, &dirent);

        // // If you add more directory entries, don't forget to update kNumWriters,
        // // above.

        // dumper_->ThreadsResume();
        // return true;
    }

    fn write_thread_list_stream(&self, buffer: &mut Cursor<Vec<u8>>) -> Result<()> {
        let num_threads = self.dumper.threads.len();
        // Memory looks like this:
        // <num_threads><thread_1><thread_2>...

        let mut list_header = SectionWriter::<u32>::alloc(buffer)?;
        list_header.set_value(buffer, num_threads as u32)?;

        //     dirent.stream_type = MD_THREAD_LIST_STREAM;
        //     dirent.location = list.location();

        let mut thread_list = SectionArrayWriter::<MDRawThread>::alloc_array(buffer, num_threads)?;

        // dirent->stream_type = MD_THREAD_LIST_STREAM;
        // dirent->location = list.location();

        // *list.get() = num_threads;

        // If there's a minidump size limit, check if it might be exceeded.  Since
        // most of the space is filled with stack data, just check against that.
        // If this expects to exceed the limit, set extra_thread_stack_len such
        // that any thread beyond the first kLimitBaseThreadCount threads will
        // have only kLimitMaxExtraThreadStackLen bytes dumped.
        let mut extra_thread_stack_len = -1; // default to no maximum
        if self.minidump_size_limit >= 0 {
            let estimated_total_stack_size =
                (num_threads * LIMIT_AVERAGE_THREAD_STACK_LENGTH) as u64;
            let curr_pos = buffer.position();
            let estimated_minidump_size =
                curr_pos + estimated_total_stack_size + LIMIT_MINIDUMP_FUDGE_FACTOR;
            if estimated_minidump_size as i64 > self.minidump_size_limit {
                extra_thread_stack_len = LIMIT_MAX_EXTRA_THREAD_STACK_LEN;
            }
        }

        for (idx, item) in self.dumper.threads.iter().enumerate() {
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
                //           !dumper_->IsPostMortem()) {
            } else {
                let info = self.dumper.get_thread_info_by_index(idx)?;
                let max_stack_len =
                    if self.minidump_size_limit >= 0 && idx >= LIMIT_BASE_THREAD_COUNT {
                        extra_thread_stack_len
                    } else {
                        -1 // default to no maximum for this thread
                    };

                let stack_copy =
                    self.fill_thread_stack(buffer, &mut thread, &info, max_stack_len)?;

                // let cpu = SectionWriter::<RawContextCPU>::alloc(&mut buffer)?;
                let cpu = RawContextCPU::default();
                info.fill_cpu_context(&mut cpu);
                let cpu_section = SectionWriter::<RawContextCPU>::alloc_with_val(buffer, cpu)?;
                thread.thread_context = cpu_section.location();
                //         if (dumper_->threads()[i] == GetCrashThread()) {
                //           crashing_thread_context_ = cpu.location();
                //           if (!dumper_->IsPostMortem()) {
                //             // This is the crashing thread of a live process, but
                //             // no context was provided, so set the crash address
                //             // while the instruction pointer is already here.
                //             dumper_->set_crash_address(info.GetInstructionPointer());
                //           }
                //         }
                //       }
            }
            thread_list.set_value_at(buffer, thread, idx)?;
        }
        Ok(())
    }

    fn fill_thread_stack(
        &self,
        buffer: &mut Cursor<Vec<u8>>,
        thread: &mut MDRawThread,
        info: &ThreadInfo,
        max_stack_len: i32,
    ) -> Result<Vec<u8>> {
        let pc = info.get_instruction_pointer();

        thread.stack.start_of_memory_range = info.stack_pointer.try_into()?;
        thread.stack.memory.data_size = 0;
        thread.stack.memory.rva = buffer.position() as u32;

        if let Ok(stack) = self.dumper.get_stack_info(info.stack_pointer) {
            //     if (max_stack_len >= 0 &&
            //         stack_len > static_cast<unsigned int>(max_stack_len)) {
            //       stack_len = max_stack_len;
            //       // Skip empty chunks of length max_stack_len.
            //       uintptr_t int_stack = reinterpret_cast<uintptr_t>(stack);
            //       if (max_stack_len > 0) {
            //         while (int_stack + max_stack_len < stack_pointer) {
            //           int_stack += max_stack_len;
            //         }
            //       }
            //       stack = reinterpret_cast<const void*>(int_stack);
            //     }
            //     *stack_copy = reinterpret_cast<uint8_t*>(Alloc(stack_len));
            //     dumper_->CopyFromProcess(*stack_copy, thread->thread_id, stack,
            //                              stack_len);

            //     uintptr_t stack_pointer_offset =
            //         stack_pointer - reinterpret_cast<uintptr_t>(stack);
            //     if (skip_stacks_if_mapping_unreferenced_) {
            //       if (!principal_mapping_) {
            //         return true;
            //       }
            //       uintptr_t low_addr = principal_mapping_->system_mapping_info.start_addr;
            //       uintptr_t high_addr = principal_mapping_->system_mapping_info.end_addr;
            //       if ((pc < low_addr || pc > high_addr) &&
            //           !dumper_->StackHasPointerToMapping(*stack_copy, stack_len,
            //                                              stack_pointer_offset,
            //                                              *principal_mapping_)) {
            //         return true;
            //       }
            //     }

            //     if (sanitize_stacks_) {
            //       dumper_->SanitizeStackCopy(*stack_copy, stack_len, stack_pointer,
            //                                  stack_pointer_offset);
            //     }

            //     UntypedMDRVA memory(&minidump_writer_);
            //     if (!memory.Allocate(stack_len))
            //       return false;
            //     memory.Copy(*stack_copy, stack_len);
            //     thread->stack.start_of_memory_range = reinterpret_cast<uintptr_t>(stack);
            //     thread->stack.memory = memory.location();
            //     memory_blocks_.push_back(thread->stack);
        }
        let res = Vec::new();
        Ok(res)
    }

    pub fn set_minidump_size_limit(&mut self, limit: i64) {
        self.minidump_size_limit = limit;
    }
}

//   // Write information about the threads.

//     for (unsigned i = 0; i < num_threads; ++i) {

//       if (static_cast<pid_t>(thread.thread_id) == GetCrashThread() &&
//           ucontext_ &&
//           !dumper_->IsPostMortem()) {
//         uint8_t* stack_copy;
//         const uintptr_t stack_ptr = UContextReader::GetStackPointer(ucontext_);
//         if (!FillThreadStack(&thread, stack_ptr,
//                              UContextReader::GetInstructionPointer(ucontext_),
//                              -1, &stack_copy))
//           return false;

//         // Copy 256 bytes around crashing instruction pointer to minidump.
//         const size_t kIPMemorySize = 256;
//         uint64_t ip = UContextReader::GetInstructionPointer(ucontext_);
//         // Bound it to the upper and lower bounds of the memory map
//         // it's contained within. If it's not in mapped memory,
//         // don't bother trying to write it.
//         bool ip_is_mapped = false;
//         MDMemoryDescriptor ip_memory_d;
//         for (unsigned j = 0; j < dumper_->mappings().size(); ++j) {
//           const MappingInfo& mapping = *dumper_->mappings()[j];
//           if (ip >= mapping.start_addr &&
//               ip < mapping.start_addr + mapping.size) {
//             ip_is_mapped = true;
//             // Try to get 128 bytes before and after the IP, but
//             // settle for whatever's available.
//             ip_memory_d.start_of_memory_range =
//               std::max(mapping.start_addr,
//                        uintptr_t(ip - (kIPMemorySize / 2)));
//             uintptr_t end_of_range =
//               std::min(uintptr_t(ip + (kIPMemorySize / 2)),
//                        uintptr_t(mapping.start_addr + mapping.size));
//             ip_memory_d.memory.data_size =
//               end_of_range - ip_memory_d.start_of_memory_range;
//             break;
//           }
//         }

//         if (ip_is_mapped) {
//           UntypedMDRVA ip_memory(&minidump_writer_);
//           if (!ip_memory.Allocate(ip_memory_d.memory.data_size))
//             return false;
//           uint8_t* memory_copy =
//               reinterpret_cast<uint8_t*>(Alloc(ip_memory_d.memory.data_size));
//           dumper_->CopyFromProcess(
//               memory_copy,
//               thread.thread_id,
//               reinterpret_cast<void*>(ip_memory_d.start_of_memory_range),
//               ip_memory_d.memory.data_size);
//           ip_memory.Copy(memory_copy, ip_memory_d.memory.data_size);
//           ip_memory_d.memory = ip_memory.location();
//           memory_blocks_.push_back(ip_memory_d);
//         }

//         TypedMDRVA<RawContextCPU> cpu(&minidump_writer_);
//         if (!cpu.Allocate())
//           return false;
//         my_memset(cpu.get(), 0, sizeof(RawContextCPU));
// #if !defined(__ARM_EABI__) && !defined(__mips__)
//         UContextReader::FillCPUContext(cpu.get(), ucontext_, float_state_);
// #else
//         UContextReader::FillCPUContext(cpu.get(), ucontext_);
// #endif
//         thread.thread_context = cpu.location();
//         crashing_thread_context_ = cpu.location();
//       } else {
//         ThreadInfo info;
//         if (!dumper_->GetThreadInfoByIndex(i, &info))
//           return false;

//         uint8_t* stack_copy;
//         int max_stack_len = -1;  // default to no maximum for this thread
//         if (minidump_size_limit_ >= 0 && i >= kLimitBaseThreadCount)
//           max_stack_len = extra_thread_stack_len;
//         if (!FillThreadStack(&thread, info.stack_pointer,
//                              info.GetInstructionPointer(), max_stack_len,
//                              &stack_copy))
//           return false;

//         TypedMDRVA<RawContextCPU> cpu(&minidump_writer_);
//         if (!cpu.Allocate())
//           return false;
//         my_memset(cpu.get(), 0, sizeof(RawContextCPU));
//         info.FillCPUContext(cpu.get());
//         thread.thread_context = cpu.location();
//         if (dumper_->threads()[i] == GetCrashThread()) {
//           crashing_thread_context_ = cpu.location();
//           if (!dumper_->IsPostMortem()) {
//             // This is the crashing thread of a live process, but
//             // no context was provided, so set the crash address
//             // while the instruction pointer is already here.
//             dumper_->set_crash_address(info.GetInstructionPointer());
//           }
//         }
//       }

//       list.CopyIndexAfterObject(i, &thread, sizeof(thread));
//     }

//     return true;
//   }

pub fn write_minidump(
    minidump_path: &str,
    process: Pid,
    _process_blamed_thread: Pid,
) -> Result<()> {
    let dumper = LinuxPtraceDumper::new(process)?;
    //   dumper.set_crash_signal(MD_EXCEPTION_CODE_LIN_DUMP_REQUESTED);
    //   dumper.set_crash_thread(process_blamed_thread);
    let mut writer = MinidumpWriter::new(minidump_path, dumper);
    writer.init()?;
    writer.dump()
}
// bool WriteMinidump(const char* minidump_path, pid_t process,
//                    pid_t process_blamed_thread) {
//   LinuxPtraceDumper dumper(process);
//   // MinidumpWriter will set crash address
//   dumper.set_crash_signal(MD_EXCEPTION_CODE_LIN_DUMP_REQUESTED);
//   dumper.set_crash_thread(process_blamed_thread);
//   MappingList mapping_list;
//   AppMemoryList app_memory_list;
//   MinidumpWriter writer(minidump_path, -1, NULL, mapping_list,
//                         app_memory_list, false, 0, false, &dumper);
//   if (!writer.Init())
//     return false;
//   return writer.Dump();
// }
