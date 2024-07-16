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

#[repr(C)]
#[derive(Clone, Debug)]
pub struct DirectAuxvDumpInfo {
    program_header_count: AuxvType,
    program_header_address: AuxvType,
    linux_gate_address: AuxvType,
    entry_address: AuxvType,
}

impl From<DirectAuxvDumpInfo> for AuxvDumpInfo {
    fn from(f: DirectAuxvDumpInfo) -> AuxvDumpInfo {
        AuxvDumpInfo {
            program_header_count: (f.program_header_count > 0).then_some(f.program_header_count),
            program_header_address: (f.program_header_address > 0)
                .then_some(f.program_header_address),
            linux_gate_address: (f.linux_gate_address > 0).then_some(f.linux_gate_address),
            entry_address: (f.entry_address > 0).then_some(f.entry_address),
        }
    }
}

#[derive(Debug, Default)]
pub struct AuxvDumpInfo {
    program_header_count: Option<AuxvType>,
    program_header_address: Option<AuxvType>,
    linux_gate_address: Option<AuxvType>,
    entry_address: Option<AuxvType>,
}

impl AuxvDumpInfo {
    pub fn try_filling_missing_info(&mut self, pid: Pid) -> Result<(), AuxvError> {
        if self.is_complete() {
            return Ok(());
        }

        let auxv_path = format!("/proc/{pid}/auxv");
        let auxv_file = File::open(&auxv_path).map_err(|e| AuxvError::OpenError(auxv_path, e))?;
        let auxv: HashMap<AuxvType, AuxvType> = ProcfsAuxvIter::new(BufReader::new(auxv_file))
            .filter_map(Result::ok)
            .map(|x| (x.key, x.value))
            .collect();

        if auxv.is_empty() {
            return Err(AuxvError::NoAuxvEntryFound(pid));
        }

        if self.program_header_count.is_none() {
            self.program_header_count = auxv.get(&consts::AT_PHNUM).copied();
        }

        if self.program_header_address.is_none() {
            self.program_header_address = auxv.get(&consts::AT_PHDR).copied();
        }

        if self.linux_gate_address.is_none() {
            self.linux_gate_address = auxv.get(&consts::AT_SYSINFO_EHDR).copied();
        }

        if self.entry_address.is_none() {
            self.entry_address = auxv.get(&consts::AT_ENTRY).copied();
        }

        Ok(())
    }
    pub fn get_program_header_count(&self) -> Option<AuxvType> {
        self.program_header_count
    }
    pub fn get_program_header_address(&self) -> Option<AuxvType> {
        self.program_header_address
    }
    pub fn get_linux_gate_address(&self) -> Option<AuxvType> {
        self.linux_gate_address
    }
    pub fn get_entry_address(&self) -> Option<AuxvType> {
        self.entry_address
    }
    pub fn is_complete(&self) -> bool {
        self.program_header_count.is_some()
            && self.program_header_address.is_some()
            && self.linux_gate_address.is_some()
            && self.entry_address.is_some()
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
