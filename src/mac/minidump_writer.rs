use crate::mac::errors::WriterError;
use crash_context::CrashContext;
use std::io::{Seek, Write};

pub type DumpBuf = Buffer;
type Result<T> = std::result::Result<T, WriterError>;

pub struct MinidumpWriter {
    /// The crash context as captured by an exception handler
    crash_context: crash_context::CrashContext,
    /// List of raw blocks of memory we've written into the stream. These are
    /// referenced by other streams (eg thread list)
    memory_blocks: Vec<MDMemoryDescriptor>,
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
            let mut writers = vec![
                Self::write_thread_list,
                Self::write_memory_list,
                Self::write_system_info,
                Self::write_module_list,
                Self::write_misc_info,
                Self::write_breakpad_info,
            ];

            // Exception stream needs to be the last entry in this array as it may
            // be omitted in the case where the minidump is written without an
            // exception.
            if self.crash_context.exception.is_some() {
                writers.push_back(Self::write_exception);
            }

            writers
        };

        let num_writers = writers.len() as u32;
        let mut buffer = Buffer::with_capacity(0);

        let mut header_section = MemoryWriter::<MDRawHeader>::alloc(buffer)?;
        let mut dir_section = DirSection::new(buffer, num_writers, destination)?;

        let header = MDRawHeader {
            signature: MD_HEADER_SIGNATURE,
            version: MD_HEADER_VERSION,
            stream_count: num_writers,
            stream_directory_rva: dir_section.position(),
            checksum: 0, /* Can be 0.  In fact, that's all that's
                          * been found in minidump files. */
            time_date_stamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs() as u32, // TODO: This is not Y2038 safe, but thats how its currently defined as
            flags: 0,
        };
        header_section.set_value(buffer, header)?;

        // Ensure the header gets flushed. If we crash somewhere below,
        // we should have a mostly-intact dump
        dir_section.write_to_file(buffer, None)?;

        for writer in writers {
            let dirent = writer(self, buffer, dumper)?;
            dir_section.write_to_file(buffer, Some(dirent))?;
        }

        Ok(buffer)
    }
}
