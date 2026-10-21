//! Auxiliary vector handling on FreeBSD.
//!
//! The auxv of the inspected process is obtained through the
//! [`ProcessInspector`](crate::freebsd::process_inspection::ProcessInspector)
//! (backed by the `KERN_PROC_AUXV` sysctl in the local implementation).

use {crate::freebsd::process_inspection::ProcessInspector, thiserror::Error};

#[cfg(target_pointer_width = "32")]
pub type AuxvType = u32;
#[cfg(target_pointer_width = "64")]
pub type AuxvType = u64;

mod consts {
    use super::AuxvType;
    pub const AT_PHDR: AuxvType = libc::AT_PHDR as AuxvType;
    pub const AT_PHNUM: AuxvType = libc::AT_PHNUM as AuxvType;
    pub const AT_ENTRY: AuxvType = libc::AT_ENTRY as AuxvType;
    pub const AT_BASE: AuxvType = libc::AT_BASE as AuxvType;
    pub const AT_NULL: AuxvType = libc::AT_NULL as AuxvType;
    pub const AT_EXECPATH: AuxvType = libc::AT_EXECPATH as AuxvType;
}

#[repr(C)]
#[derive(Clone, Debug, Default)]
pub struct DirectAuxvDumpInfo {
    pub program_header_count: AuxvType,
    pub program_header_address: AuxvType,
    pub base_address: AuxvType,
    pub entry_address: AuxvType,
}

impl From<DirectAuxvDumpInfo> for AuxvDumpInfo {
    fn from(f: DirectAuxvDumpInfo) -> AuxvDumpInfo {
        AuxvDumpInfo {
            program_header_count: (f.program_header_count > 0).then_some(f.program_header_count),
            program_header_address: (f.program_header_address > 0)
                .then_some(f.program_header_address),
            base_address: (f.base_address > 0).then_some(f.base_address),
            entry_address: (f.entry_address > 0).then_some(f.entry_address),
            exec_path_address: None,
        }
    }
}

#[derive(Debug, Default)]
pub struct AuxvDumpInfo {
    program_header_count: Option<AuxvType>,
    program_header_address: Option<AuxvType>,
    base_address: Option<AuxvType>,
    entry_address: Option<AuxvType>,
    /// Address of the executable's path string (FreeBSD-specific
    /// `AT_EXECPATH`), which survives deletion of the underlying file.
    exec_path_address: Option<AuxvType>,
}

// The parsing below assumes the 64-bit `Elf_AuxInfo` layout.
const _: () = assert!(std::mem::size_of::<AuxvType>() == 8);

impl AuxvDumpInfo {
    /// Fills in missing entries by reading the auxv of the inspected process.
    pub fn try_filling_missing_info(
        &mut self,
        process_inspector: &dyn ProcessInspector,
    ) -> Result<(), AuxvError> {
        if self.is_complete() {
            return Ok(());
        }

        let auxv_data = process_inspector.get_auxv().map_err(AuxvError::ReadError)?;

        if auxv_data.is_empty() {
            return Err(AuxvError::NoAuxvEntryFound);
        }

        // Each `Elf_AuxInfo` entry is { int a_type; pad; u64 a_un; }.
        let (pairs, _) = auxv_data.as_chunks::<16>();
        for pair in pairs {
            let key = u32::from_ne_bytes(pair[..4].try_into().expect("fixed chunk"));
            let value = AuxvType::from_ne_bytes(pair[8..].try_into().expect("fixed chunk"));
            let key = AuxvType::from(key);

            if key == consts::AT_NULL {
                break;
            }

            let dest_field = match key {
                consts::AT_PHNUM => &mut self.program_header_count,
                consts::AT_PHDR => &mut self.program_header_address,
                consts::AT_BASE => &mut self.base_address,
                consts::AT_ENTRY => &mut self.entry_address,
                consts::AT_EXECPATH => &mut self.exec_path_address,
                _ => continue,
            };

            if dest_field.is_none() {
                *dest_field = Some(value);
            }
        }

        Ok(())
    }

    pub fn get_program_header_count(&self) -> Option<AuxvType> {
        self.program_header_count
    }

    pub fn get_program_header_address(&self) -> Option<AuxvType> {
        self.program_header_address
    }

    pub fn get_entry_address(&self) -> Option<AuxvType> {
        self.entry_address
    }

    /// Address of the NUL-terminated executable path string (`AT_EXECPATH`).
    pub fn get_exec_path_address(&self) -> Option<AuxvType> {
        self.exec_path_address
    }

    pub fn is_complete(&self) -> bool {
        self.program_header_count.is_some()
            && self.program_header_address.is_some()
            && self.entry_address.is_some()
    }
}

#[derive(Debug, Error, serde::Serialize)]
pub enum AuxvError {
    #[error("failed to read the auxv of the process")]
    ReadError(#[source] crate::freebsd::process_inspection::Error),
    #[error("no auxv entry found for the process")]
    NoAuxvEntryFound,
}
