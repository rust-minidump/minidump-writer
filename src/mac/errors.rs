use thiserror::Error;

#[derive(Debug, Error)]
pub enum WriterError {
    #[error("unable to find a UUID for a module")]
    UnknownUuid,
    #[error("unable to find the main executable image for the process")]
    NoExecutableImage,
    #[error(transparent)]
    TaskDumpError(#[from] crate::mac::task_dumper::TaskDumpError),
}
