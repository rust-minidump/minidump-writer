use {super::Pid, crate::serializers::*, thiserror::Error};

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
    pub fn try_filling_missing_info(&mut self, pid: Pid) -> Result<(), AuxvError> {
        if self.is_complete() {
            return Ok(());
        }

        let auxv_data = read_auxv_via_sysctl(pid)?;

        for pair in auxv_data.chunks(2 * std::mem::size_of::<AuxvType>()) {
            if pair.len() != 2 * std::mem::size_of::<AuxvType>() {
                continue;
            }

            let key = if std::mem::size_of::<AuxvType>() == 4 {
                AuxvType::from(u32::from_ne_bytes([pair[0], pair[1], pair[2], pair[3]]))
            } else {
                AuxvType::from(u64::from_ne_bytes([
                    pair[0], pair[1], pair[2], pair[3], pair[4], pair[5], pair[6], pair[7],
                ]))
            };

            let value = if std::mem::size_of::<AuxvType>() == 4 {
                AuxvType::from(u32::from_ne_bytes([pair[4], pair[5], pair[6], pair[7]]))
            } else {
                AuxvType::from(u64::from_ne_bytes([
                    pair[8], pair[9], pair[10], pair[11], pair[12], pair[13], pair[14], pair[15],
                ]))
            };

            if key == consts::AT_NULL {
                break;
            }

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
    #[error("Failed to read auxv for PID {0}")]
    ReadError(
        Pid,
        #[source]
        #[serde(serialize_with = "serialize_io_error")]
        std::io::Error,
    ),
    #[error("No auxv entry found for PID {0}")]
    NoAuxvEntryFound(Pid),
    #[error("Invalid auxv format")]
    InvalidFormat,
}

#[cfg(target_os = "freebsd")]
fn read_auxv_via_sysctl(pid: Pid) -> Result<Vec<u8>, AuxvError> {
    let mib = [libc::CTL_KERN, libc::KERN_PROC, libc::KERN_PROC_AUXV, pid];

    let mut len = 0;

    // SAFETY: sysctl is a well-defined kernel interface. We provide valid mib,
    // pointers, and check the return value. The kernel fills the buffer on success.
    unsafe {
        if libc::sysctl(
            mib.as_ptr(),
            mib.len() as libc::c_uint,
            std::ptr::null_mut(),
            &mut len,
            std::ptr::null(),
            0,
        ) != 0
        {
            return Err(AuxvError::ReadError(pid, std::io::Error::last_os_error()));
        }

        if len == 0 {
            return Err(AuxvError::NoAuxvEntryFound(pid));
        }

        let mut buffer = vec![0u8; len];

        if libc::sysctl(
            mib.as_ptr(),
            mib.len() as libc::c_uint,
            buffer.as_mut_ptr() as *mut libc::c_void,
            &mut len,
            std::ptr::null(),
            0,
        ) != 0
        {
            return Err(AuxvError::ReadError(pid, std::io::Error::last_os_error()));
        }

        buffer.truncate(len);

        Ok(buffer)
    }
}
