use {
    super::*,
    crate::mem_writer::{MemoryArrayWriter, MemoryWriter},
};

#[derive(Debug, thiserror::Error, serde::Serialize)]
pub enum SectionMemListError {
    #[error("Failed to write to memory")]
    MemoryWriterError(#[from] crate::mem_writer::MemoryWriterError),
}

impl MinidumpWriter {
    pub fn write_memory_list_stream(
        &mut self,
        buffer: &mut DumpBuf,
    ) -> Result<MDRawDirectory, SectionMemListError> {
        let list_header =
            MemoryWriter::<u32>::alloc_with_val(buffer, self.memory_blocks.len() as u32)?;

        let mut dirent = MDRawDirectory {
            stream_type: MDStreamType::MemoryListStream as u32,
            location: list_header.location(),
        };

        let block_list =
            MemoryArrayWriter::<MDMemoryDescriptor>::alloc_from_array(buffer, &self.memory_blocks)?;

        dirent.location.data_size += block_list.location().data_size;

        Ok(dirent)
    }
}
