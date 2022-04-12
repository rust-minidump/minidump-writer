use crate::mac::errors::WriterError;
use crash_context::CrashContext;
use std::io::{Seek, Write};

pub type DumpBuf = Buffer;
type Result<T> = std::result::Result<T, WriterError>;

#[derive(Debug)]
pub struct DirSection<'a, W>
where
    W: Write + Seek,
{
    curr_idx: usize,
    section: MemoryArrayWriter<MDRawDirectory>,
    /// If we have to append to some file, we have to know where we currently are
    destination_start_offset: u64,
    destination: &'a mut W,
    last_position_written_to_file: u64,
}

impl<'a, W> DirSection<'a, W>
where
    W: Write + Seek,
{
    fn new(
        buffer: &mut DumpBuf,
        index_length: u32,
        destination: &'a mut W,
    ) -> std::result::Result<Self, FileWriterError> {
        let dir_section =
            MemoryArrayWriter::<MDRawDirectory>::alloc_array(buffer, index_length as usize)?;
        Ok(DirSection {
            curr_idx: 0,
            section: dir_section,
            destination_start_offset: destination.seek(SeekFrom::Current(0))?,
            destination,
            last_position_written_to_file: 0,
        })
    }

    fn position(&self) -> u32 {
        self.section.position
    }

    fn dump_dir_entry(
        &mut self,
        buffer: &mut DumpBuf,
        dirent: MDRawDirectory,
    ) -> std::result::Result<(), FileWriterError> {
        self.section.set_value_at(buffer, dirent, self.curr_idx)?;

        // Now write it to file

        // First get all the positions
        let curr_file_pos = self.destination.seek(SeekFrom::Current(0))?;
        let idx_pos = self.section.location_of_index(self.curr_idx);
        self.curr_idx += 1;

        self.destination.seek(std::io::SeekFrom::Start(
            self.destination_start_offset + idx_pos.rva as u64,
        ))?;
        let start = idx_pos.rva as usize;
        let end = (idx_pos.rva + idx_pos.data_size) as usize;
        self.destination.write_all(&buffer[start..end])?;

        // Reset file-position
        self.destination
            .seek(std::io::SeekFrom::Start(curr_file_pos))?;

        Ok(())
    }

    /// Writes 2 things to file:
    /// 1. The given dirent into the dir section in the header (if any is given)
    /// 2. Everything in the in-memory buffer that was added since the last call to this function
    fn write_to_file(
        &mut self,
        buffer: &mut DumpBuf,
        dirent: Option<MDRawDirectory>,
    ) -> std::result::Result<(), FileWriterError> {
        if let Some(dirent) = dirent {
            self.dump_dir_entry(buffer, dirent)?;
        }

        let start_pos = self.last_position_written_to_file as usize;
        self.destination.write_all(&buffer[start_pos..])?;
        self.last_position_written_to_file = buffer.position();
        Ok(())
    }
}

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
