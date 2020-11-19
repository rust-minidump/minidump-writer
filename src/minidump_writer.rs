use crate::linux_ptrace_dumper::LinuxPtraceDumper;
use crate::maps_reader::{MappingInfo, MappingList};
use crate::minidump_cpu::RawContextCPU;
use crate::minidump_format::*;
use crate::thread_info::Pid;
use crate::thread_info::ThreadInfo;
use crate::Result;
use std::convert::TryInto;
use std::io::{Cursor, Write};

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
    skip_stacks_if_mapping_unreferenced: bool,
    principal_mapping: Option<MappingInfo>,
    user_mapping_list: MappingList,
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
            skip_stacks_if_mapping_unreferenced: false,
            principal_mapping: None,
            user_mapping_list: Vec::new(),
        }
    }

    fn init(&mut self) -> Result<()> {
        self.dumper.suspend_threads()?;
        // TODO: Doesn't exist yet
        //self.dumper.late_init()?;

        Ok(())
    }

    fn dump(&mut self) -> Result<()> {
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

        let mut dir_idx = 0;
        let mut dirent = self.write_thread_list_stream(&mut buffer)?;
        dir_section.set_value_at(&mut buffer, dirent, dir_idx)?;
        dir_idx += 1;

        dirent = self.write_mappings(&mut buffer)?;
        dir_section.set_value_at(&mut buffer, dirent, dir_idx)?;
        dir_idx += 1;

        Ok(())

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

    fn write_thread_list_stream(&self, buffer: &mut Cursor<Vec<u8>>) -> Result<MDRawDirectory> {
        let num_threads = self.dumper.threads.len();
        // Memory looks like this:
        // <num_threads><thread_1><thread_2>...

        let list_header = SectionWriter::<u32>::alloc_with_val(buffer, num_threads as u32)?;

        let dirent = MDRawDirectory {
            stream_type: MDStreamType::ThreadListStream as u32,
            location: list_header.location(), // TODO: WRONG, because location includes size, which should contain mapping_list as well!
        };

        let mut thread_list = SectionArrayWriter::<MDRawThread>::alloc_array(buffer, num_threads)?;

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
                //           !dumper_->IsPostMortem())
            } else {
                let info = self.dumper.get_thread_info_by_index(idx)?;
                let max_stack_len =
                    if self.minidump_size_limit >= 0 && idx >= LIMIT_BASE_THREAD_COUNT {
                        extra_thread_stack_len
                    } else {
                        -1 // default to no maximum for this thread
                    };

                self.fill_thread_stack(buffer, &mut thread, &info, max_stack_len)?;

                // let cpu = SectionWriter::<RawContextCPU>::alloc(&mut buffer)?;
                let mut cpu = RawContextCPU::default();
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
        Ok(dirent)
    }

    fn fill_thread_stack(
        &self,
        buffer: &mut Cursor<Vec<u8>>,
        thread: &mut MDRawThread,
        info: &ThreadInfo,
        max_stack_len: i32,
    ) -> Result<()> {
        let pc = info.get_instruction_pointer() as usize;

        thread.stack.start_of_memory_range = info.stack_pointer.try_into()?;
        thread.stack.memory.data_size = 0;
        thread.stack.memory.rva = buffer.position() as u32;

        if let Ok((mut stack, mut stack_len)) = self.dumper.get_stack_info(info.stack_pointer) {
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
            let stack_copy = LinuxPtraceDumper::copy_from_process(
                thread.thread_id.try_into()?,
                stack as *mut libc::c_void,
                stack_len.try_into()?,
            )?;
            let stack_pointer_offset = info.stack_pointer - stack;
            let stack_bytes = stack_copy
                .iter()
                .map(|x| x.to_ne_bytes().to_vec())
                .flatten()
                .collect::<Vec<u8>>();
            if self.skip_stacks_if_mapping_unreferenced {
                if let Some(principal_mapping) = &self.principal_mapping {
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

            //     if self.sanitize_stacks {
            //       self.dumper.SanitizeStackCopy(&stack_bytes, stack_pointer,
            //                                  stack_pointer_offset);
            //     }
            let stack_location = MDLocationDescriptor {
                data_size: stack_bytes.len() as u32,
                rva: buffer.position() as u32,
            };
            buffer.write_all(&stack_bytes)?;
            thread.stack.start_of_memory_range = stack as u64;
            thread.stack.memory = stack_location;
            //     memory_blocks_.push_back(thread->stack);
        }
        Ok(())
    }

    /// Write information about the mappings in effect. Because we are using the
    /// minidump format, the information about the mappings is pretty limited.
    /// Because of this, we also include the full, unparsed, /proc/$x/maps file in
    /// another stream in the file.
    fn write_mappings(&mut self, buffer: &mut Cursor<Vec<u8>>) -> Result<MDRawDirectory> {
        let mut num_output_mappings = self.user_mapping_list.len();

        for mapping in &self.dumper.mappings {
            // If the mapping is uninteresting, or if
            // there is caller-provided information about this mapping
            // in the user_mapping_list list, skip it
            if mapping.is_interesting() && !mapping.is_contained_in(&self.user_mapping_list) {
                num_output_mappings += 1;
            }
        }

        let list_header = SectionWriter::<u32>::alloc_with_val(buffer, num_output_mappings as u32)?;

        let dirent = MDRawDirectory {
            stream_type: MDStreamType::ModuleListStream as u32,
            location: list_header.location(), // TODO: WRONG, because location includes size, which should contain mapping_list as well!
        };

        // TODO: We currently ignore this and use size_of<MDRawModule>
        /* The inclusion of a 64-bit type in MINIDUMP_MODULE forces the struct to
         * be tail-padded out to a multiple of 64 bits under some ABIs (such as PPC).
         * This doesn't occur on systems that don't tail-pad in this manner.  Define
         * this macro to be the usable size of the MDRawModule struct, and use it in
         * place of sizeof(MDRawModule). */
        // #define MD_MODULE_SIZE 108
        // In case of num_output_mappings == 0, this call doesn't allocate any memory in the buffer
        let mut mapping_list =
            SectionArrayWriter::<MDRawModule>::alloc_array(buffer, num_output_mappings)?;

        // First write all the mappings from the dumper
        let mut idx = 0;
        for map_idx in 0..self.dumper.mappings.len() {
            if !self.dumper.mappings[map_idx].is_interesting()
                || self.dumper.mappings[map_idx].is_contained_in(&self.user_mapping_list)
            {
                continue;
            }
            // Note: elf_identifier_for_mapping_index() can manipulate the |mapping.name|.
            let identifier = self.dumper.elf_identifier_for_mapping_index(idx)?;
            let module = self.fill_raw_module(buffer, &self.dumper.mappings[idx], &identifier)?;
            mapping_list.set_value_at(buffer, module, idx)?;
            idx += 1;
        }

        // Next write all the mappings provided by the caller
        for user in &self.user_mapping_list {
            // GUID was provided by caller.
            let module = self.fill_raw_module(buffer, &user.mapping, &user.identifier)?;
            mapping_list.set_value_at(buffer, module, idx)?;
            idx += 1;
        }
        Ok(dirent)
    }

    fn fill_raw_module(
        &self,
        buffer: &mut Cursor<Vec<u8>>,
        mapping: &MappingInfo,
        identifier: &[u8],
    ) -> Result<MDRawModule> {
        let cv_record: MDLocationDescriptor;
        if identifier.is_empty() {
            // Just zeroes
            cv_record = Default::default();
        } else {
            let cv_signature = MD_CVINFOELF_SIGNATURE;
            let array_size = std::mem::size_of_val(&cv_signature) + identifier.len();

            let mut sig_section = SectionArrayWriter::<u8>::alloc_array(buffer, array_size)?;
            for (index, val) in cv_signature
                .to_ne_bytes()
                .iter()
                .chain(identifier.iter())
                .enumerate()
            {
                sig_section.set_value_at(buffer, *val, index)?;
            }
            cv_record = sig_section.location();
        }

        let (file_path, _) = mapping.get_mapping_effective_name_and_path()?;
        let letters: Vec<u16> = file_path.encode_utf16().collect();

        // First write size of the string (x letters in u16, times the size of u16)
        let name_header = SectionWriter::<u32>::alloc_with_val(
            buffer,
            (letters.len() * std::mem::size_of::<u16>()).try_into()?,
        )?;

        // Then write utf-16 letters after that
        let mut name_section = SectionArrayWriter::<u16>::alloc_array(buffer, letters.len())?;
        for (index, letter) in letters.iter().enumerate() {
            name_section.set_value_at(buffer, *letter, index)?;
        }

        Ok(MDRawModule {
            base_of_image: mapping.start_address as u64,
            size_of_image: mapping.size as u32,
            cv_record,
            module_name_rva: name_header.location().rva,
            ..Default::default()
        })
    }

    // pub fn set_minidump_size_limit(&mut self, limit: i64) {
    //     self.minidump_size_limit = limit;
    // }
}

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
