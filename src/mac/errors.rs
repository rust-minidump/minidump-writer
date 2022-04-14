use thiserror::Error;

#[derive(Debug, Error)]
pub enum WriterError {
    #[error(transparent)]
    TaskDumpError(#[from] crate::mac::task_dumper::TaskDumpError),
    #[error("Failed to write to memory")]
    MemoryWriterError(#[from] crate::mem_writer::MemoryWriterError),
    #[error("Failed to write to file")]
    FileWriterError(#[from] crate::dir_section::FileWriterError),
}
