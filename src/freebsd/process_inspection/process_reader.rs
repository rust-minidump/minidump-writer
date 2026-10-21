//! Process memory reading on FreeBSD.
//!
//! A [`ProcessReader`] is obtained from a
//! [`ProcessInspector`](super::ProcessInspector) and routes every read through
//! it; this type never issues syscalls itself.

use super::ProcessInspector;
use crate::serializers::serialize_io_error;

/// A handle to a process, which on FreeBSD is simply the process id.
pub type ProcessHandle = libc::pid_t;

/// Error returned when reading memory from a traced process fails.
#[derive(Debug, thiserror::Error, serde::Serialize)]
#[error("copy from process {child} failed (source {src}, length {length})")]
pub struct CopyFromProcessError {
    pub child: ProcessHandle,
    pub src: usize,
    pub length: usize,
    #[source]
    #[serde(serialize_with = "serialize_io_error")]
    pub source: std::io::Error,
}

/// Reads memory from a process.
#[derive(Debug)]
pub struct ProcessReader<'a>(&'a dyn ProcessInspector);

impl<'a> ProcessReader<'a> {
    pub(crate) fn new(inspector: &'a dyn ProcessInspector) -> Self {
        Self(inspector)
    }

    /// Reads memory from the process into the given buffer.
    ///
    /// The process must have been attached to the inspector beforehand, see
    /// [`ProcessInspector::attach`](super::ProcessInspector::attach).
    ///
    /// Returns the number of bytes read.
    pub fn read(&self, src: usize, dst: &mut [u8]) -> Result<usize, CopyFromProcessError> {
        self.0.read_at(src, dst)
    }
}
