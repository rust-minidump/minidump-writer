use crate::{
    dir_section::{DirSection, DumpBuf},
    mac::{errors::WriterError, task_dumper::TaskDumper},
    mem_writer::*,
    minidump_format::{self, MDMemoryDescriptor, MDRawDirectory, MDRawHeader},
};
use std::io::{Seek, Write};

type Result<T> = std::result::Result<T, WriterError>;

pub struct MinidumpWriter {
    /// The crash context as captured by an exception handler
    pub(crate) crash_context: crash_context::CrashContext,
    /// List of raw blocks of memory we've written into the stream. These are
    /// referenced by other streams (eg thread list)
    pub(crate) memory_blocks: Vec<MDMemoryDescriptor>,
}

impl MinidumpWriter {
    /// Creates a minidump writer
    pub fn new(crash_context: crash_context::CrashContext) -> Self {
        Self {
            crash_context,
            memory_blocks: Vec::new(),
        }
    }

    pub fn dump(&mut self, destination: &mut (impl Write + Seek)) -> Result<Vec<u8>> {
        let writers = {
            #[allow(clippy::type_complexity)]
            let mut writers: Vec<
                Box<dyn FnMut(&mut Self, &mut DumpBuf, &TaskDumper) -> Result<MDRawDirectory>>,
            > = vec![
                Box::new(|mw, buffer, dumper| mw.write_thread_list(buffer, dumper)),
                Box::new(|mw, buffer, dumper| mw.write_memory_list(buffer, dumper)),
                Box::new(|mw, buffer, dumper| mw.write_system_info(buffer, dumper)),
                Box::new(|mw, buffer, dumper| mw.write_module_list(buffer, dumper)),
                Box::new(|mw, buffer, dumper| mw.write_misc_info(buffer, dumper)),
                Box::new(|mw, buffer, dumper| mw.write_breakpad_info(buffer, dumper)),
                Box::new(|mw, buffer, dumper| mw.write_thread_names(buffer, dumper)),
            ];

            // Exception stream needs to be the last entry in this array as it may
            // be omitted in the case where the minidump is written without an
            // exception.
            if self.crash_context.exception.is_some() {
                writers.push(Box::new(|mw, buffer, dumper| {
                    mw.write_exception(buffer, dumper)
                }));
            }

            writers
        };

        let num_writers = writers.len() as u32;
        let mut buffer = Buffer::with_capacity(0);

        let mut header_section = MemoryWriter::<MDRawHeader>::alloc(&mut buffer)?;
        let mut dir_section = DirSection::new(&mut buffer, num_writers, destination)?;

        let header = MDRawHeader {
            signature: minidump_format::MD_HEADER_SIGNATURE,
            version: minidump_format::MD_HEADER_VERSION,
            stream_count: num_writers,
            stream_directory_rva: dir_section.position(),
            checksum: 0, /* Can be 0.  In fact, that's all that's
                          * been found in minidump files. */
            time_date_stamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as u32, // TODO: This is not Y2038 safe, but thats how its currently defined as
            flags: 0,
        };
        header_section.set_value(&mut buffer, header)?;

        // Ensure the header gets flushed. If we crash somewhere below,
        // we should have a mostly-intact dump
        dir_section.write_to_file(&mut buffer, None)?;

        let dumper = super::task_dumper::TaskDumper::new(self.crash_context.task);

        for mut writer in writers {
            let dirent = writer(self, &mut buffer, &dumper)?;
            dir_section.write_to_file(&mut buffer, Some(dirent))?;
        }

        Ok(buffer.into())
    }

    /// Retrieves the list of active threads in the target process, except
    /// the handler thread if it is known, to simplify dump analysis
    #[inline]
    pub(crate) fn threads(&self, dumper: &TaskDumper) -> ActiveThreads {
        ActiveThreads {
            threads: dumper.read_threads().unwrap_or_default(),
            handler_thread: self.crash_context.handler_thread,
            i: 0,
        }
    }
}

pub(crate) struct ActiveThreads {
    threads: &'static [u32],
    handler_thread: u32,
    i: usize,
}

impl ActiveThreads {
    #[inline]
    pub(crate) fn len(&self) -> usize {
        let mut len = self.threads.len();

        if self.handler_thread != mach2::port::MACH_PORT_NULL {
            len -= 1;
        }

        len
    }
}

impl Iterator for ActiveThreads {
    type Item = u32;

    fn next(&mut self) -> Option<Self::Item> {
        while self.i < self.threads.len() {
            let i = self.i;
            self.i += 1;

            if self.threads[i] != self.handler_thread {
                return Some(self.threads[i]);
            }
        }

        None
    }
}
