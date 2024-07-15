pub use reader::ProcfsAuxvIter;
use {
    crate::linux::thread_info::Pid,
    std::{collections::HashMap, fs::File, io::BufReader},
    thiserror::Error,
};

mod reader;

/// The type used in auxv keys and values.
#[cfg(target_pointer_width = "32")]
pub type AuxvType = u32;
/// The type used in auxv keys and values.
#[cfg(target_pointer_width = "64")]
pub type AuxvType = u64;

/// An auxv key-value pair.
#[derive(Debug, PartialEq, Eq)]
pub struct AuxvPair {
    pub key: AuxvType,
    pub value: AuxvType,
}

pub fn read_auxv(pid: Pid) -> Result<HashMap<AuxvType, AuxvType>, AuxvError> {
    let auxv_path = format!("/proc/{pid}/auxv");
    let auxv_file = File::open(&auxv_path).map_err(|e| AuxvError::OpenError(auxv_path, e))?;
    let auxv: HashMap<AuxvType, AuxvType> = ProcfsAuxvIter::new(BufReader::new(auxv_file))
        .filter_map(Result::ok)
        .map(|x| (x.key, x.value))
        .collect();
    if auxv.is_empty() {
        Err(AuxvError::NoAuxvEntryFound(pid))
    } else {
        Ok(auxv)
    }
}

#[derive(Debug, Error)]
pub enum AuxvError {
    #[error("Failed to open file {0}")]
    OpenError(String, #[source] std::io::Error),
    #[error("No auxv entry found for PID {0}")]
    NoAuxvEntryFound(Pid),
    #[error("Invalid auxv format (should not hit EOF before AT_NULL)")]
    InvalidFormat,
    #[error("IO Error")]
    IOError(#[from] std::io::Error),
}
