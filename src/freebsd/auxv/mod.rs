use {
    self::reader::AuxvIter, super::process_inspection::ProcessInspector, crate::serializers::*,
    error_graph::WriteErrorList, std::io::Cursor, thiserror::Error,
};

mod reader;

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
}

#[derive(Debug, PartialEq, Eq)]
pub struct AuxvPair {
    pub key: AuxvType,
    pub value: AuxvType,
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
        }
    }
}

#[derive(Debug, Default)]
pub struct AuxvDumpInfo {
    program_header_count: Option<AuxvType>,
    program_header_address: Option<AuxvType>,
    base_address: Option<AuxvType>,
    entry_address: Option<AuxvType>,
}

impl AuxvDumpInfo {
    pub fn try_filling_missing_info(
        &mut self,
        process_inspector: &ProcessInspector,
        mut soft_errors: impl WriteErrorList<AuxvError>,
    ) -> Result<(), AuxvError> {
        if self.is_complete() {
            return Ok(());
        }

        let auxv_data = process_inspector.read_auxv()?;
        let cursor = Cursor::new(auxv_data);

        for pair_result in AuxvIter::new(cursor) {
            let AuxvPair { key, value } = match pair_result {
                Ok(pair) => pair,
                Err(e) => {
                    soft_errors.push(e);
                    continue;
                }
            };

            let dest_field = match key {
                consts::AT_PHNUM => &mut self.program_header_count,
                consts::AT_PHDR => &mut self.program_header_address,
                consts::AT_BASE => &mut self.base_address,
                consts::AT_ENTRY => &mut self.entry_address,
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

    pub fn get_base_address(&self) -> Option<AuxvType> {
        self.base_address
    }

    pub fn get_entry_address(&self) -> Option<AuxvType> {
        self.entry_address
    }

    pub fn is_complete(&self) -> bool {
        self.program_header_count.is_some()
            && self.program_header_address.is_some()
            && self.entry_address.is_some()
    }
}

#[derive(Debug, Error, serde::Serialize)]
pub enum AuxvError {
    #[error("Failed to read auxv")]
    ReadError(
        #[source]
        #[serde(serialize_with = "serialize_io_error")]
        std::io::Error,
    ),
    #[error("No auxv entry found")]
    NoAuxvEntryFound,
    #[error("Invalid auxv format (should not hit EOF before AT_NULL)")]
    InvalidFormat,
    #[error("IO Error")]
    IOError(
        #[from]
        #[serde(serialize_with = "serialize_io_error")]
        std::io::Error,
    ),
}
