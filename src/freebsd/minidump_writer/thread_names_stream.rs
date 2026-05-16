use {
    super::*,
    crate::mem_writer::{MemoryWriterError, write_string_to_location},
};

#[derive(Debug, thiserror::Error, serde::Serialize)]
pub enum SectionThreadNamesError {
    #[error("Failed integer conversion")]
    TryFromIntError(
        #[from]
        #[serde(skip)]
        std::num::TryFromIntError,
    ),
    #[error("Failed to write to memory")]
    MemoryWriterError(#[from] MemoryWriterError),
}

impl MinidumpWriter {
    pub fn write_thread_names_stream(
        &self,
        buffer: &mut DumpBuf,
    ) -> Result<MDRawDirectory, SectionThreadNamesError> {
        let num_threads = self.threads.iter().filter(|t| t.name.is_some()).count();

        let list_header = MemoryWriter::<u32>::alloc_with_val(buffer, num_threads as u32)?;

        let mut dirent = MDRawDirectory {
            stream_type: MDStreamType::ThreadNamesStream as u32,
            location: list_header.location(),
        };

        let mut thread_list =
            MemoryArrayWriter::<MDRawThreadName>::alloc_array(buffer, num_threads)?;
        dirent.location.data_size += thread_list.location().data_size;

        let mut idx = 0;
        for item in &self.threads {
            if let Some(name) = &item.name {
                let pos = write_string_to_location(buffer, name)?;
                let thread = MDRawThreadName {
                    thread_id: item.tid as u32,
                    thread_name_rva: pos.rva.into(),
                };
                thread_list.set_value_at(buffer, thread, idx)?;
                idx += 1;
            }
        }
        Ok(dirent)
    }
}
