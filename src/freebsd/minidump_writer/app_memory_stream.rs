use {super::*, crate::mem_writer::MemoryArrayWriter};

#[derive(Debug, thiserror::Error, serde::Serialize)]
pub enum SectionAppMemoryError {
    #[error("Failed to copy memory from process")]
    CopyFromProcessError(#[from] crate::freebsd::process_reader::CopyFromProcessError),
    #[error("Failed to write to memory")]
    MemoryWriterError(#[from] crate::mem_writer::MemoryWriterError),
}

impl MinidumpWriter {
    pub fn write_app_memory(&mut self, buffer: &mut DumpBuf) -> Result<(), SectionAppMemoryError> {
        for app_memory in &self.app_memory {
            let data_copy = self.copy_from_process(app_memory.ptr, app_memory.length)?;

            let section = MemoryArrayWriter::write_bytes(buffer, &data_copy);
            let desc = MDMemoryDescriptor {
                start_of_memory_range: app_memory.ptr as u64,
                memory: section.location(),
            };
            self.memory_blocks.push(desc);
        }
        Ok(())
    }
}
