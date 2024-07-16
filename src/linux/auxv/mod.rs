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

#[cfg(any(target_arch = "arm", all(target_os = "android", target_arch = "x86")))]
mod consts {
    use super::AuxvType;
    pub const AT_PHDR: AuxvType = 3;
    pub const AT_PHNUM: AuxvType = 5;
    pub const AT_ENTRY: AuxvType = 9;
    pub const AT_SYSINFO_EHDR: AuxvType = 33;
}
#[cfg(not(any(target_arch = "arm", all(target_os = "android", target_arch = "x86"))))]
mod consts {
    use super::AuxvType;
    pub const AT_PHDR: AuxvType = libc::AT_PHDR;
    pub const AT_PHNUM: AuxvType = libc::AT_PHNUM;
    pub const AT_ENTRY: AuxvType = libc::AT_ENTRY;
    pub const AT_SYSINFO_EHDR: AuxvType = libc::AT_SYSINFO_EHDR;
}

/// An auxv key-value pair.
#[derive(Debug, PartialEq, Eq)]
pub struct AuxvPair {
    pub key: AuxvType,
    pub value: AuxvType,
}

#[derive(Debug, Default)]
pub struct AuxvDumpInfo {
    map: HashMap<AuxvType, AuxvType>,
}

impl AuxvDumpInfo {
    pub fn get_program_header_count(&self) -> Option<AuxvType> {
        self.map.get(&consts::AT_PHNUM).copied()
    }
    pub fn get_program_header_address(&self) -> Option<AuxvType> {
        self.map.get(&consts::AT_PHDR).copied()
    }
    pub fn get_linux_gate_address(&self) -> Option<AuxvType> {
        self.map.get(&consts::AT_SYSINFO_EHDR).copied()
    }
    pub fn get_entry_address(&self) -> Option<AuxvType> {
        self.map.get(&consts::AT_ENTRY).copied()
    }
}

pub fn read_auxv(pid: Pid) -> Result<AuxvDumpInfo, AuxvError> {
    let auxv_path = format!("/proc/{pid}/auxv");
    let auxv_file = File::open(&auxv_path).map_err(|e| AuxvError::OpenError(auxv_path, e))?;
    let auxv: HashMap<AuxvType, AuxvType> = ProcfsAuxvIter::new(BufReader::new(auxv_file))
        .filter_map(Result::ok)
        .map(|x| (x.key, x.value))
        .collect();
    if auxv.is_empty() {
        Err(AuxvError::NoAuxvEntryFound(pid))
    } else {
        Ok(AuxvDumpInfo { map: auxv })
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
