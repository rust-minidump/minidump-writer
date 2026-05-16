use {
    super::*,
    crate::freebsd::vm_permissions::VmPermissions,
    crate::mem_writer::MemoryWriterError,
    minidump_common::format::{MemoryProtection, MemoryState, MemoryType},
};

#[derive(Debug, thiserror::Error, serde::Serialize)]
pub enum SectionMemInfoListError {
    #[error("Failed to write to memory")]
    MemoryWriterError(#[from] MemoryWriterError),
}

impl MinidumpWriter {
    pub fn write_memory_info_list_stream(
        &mut self,
        buffer: &mut DumpBuf,
    ) -> Result<MDRawDirectory, SectionMemInfoListError> {
        let list_header = MemoryWriter::alloc_with_val(
            buffer,
            MDMemoryInfoList {
                size_of_header: std::mem::size_of::<MDMemoryInfoList>() as u32,
                size_of_entry: std::mem::size_of::<MDMemoryInfo>() as u32,
                number_of_entries: self.mappings.len() as u64,
            },
        )?;

        let mut dirent = MDRawDirectory {
            stream_type: MDStreamType::MemoryInfoListStream as u32,
            location: list_header.location(),
        };

        let block_list = MemoryArrayWriter::<MDMemoryInfo>::alloc_from_iter(
            buffer,
            self.mappings.iter().map(|mm| {
                let base = mm.start_address as u64;
                let end = mm.end_address() as u64;
                MDMemoryInfo {
                    base_address: base,
                    allocation_base: base,
                    allocation_protection: get_memory_protection(mm.permissions).bits(),
                    __alignment1: 0,
                    region_size: end - base,
                    state: MemoryState::MEM_COMMIT.bits(),
                    protection: get_memory_protection(mm.permissions).bits(),
                    _type: if mm.permissions.contains(VmPermissions::PRIVATE) {
                        MemoryType::MEM_PRIVATE
                    } else {
                        MemoryType::MEM_MAPPED
                    }
                    .bits(),
                    __alignment2: 0,
                }
            }),
        )?;

        dirent.location.data_size += block_list.location().data_size;
        Ok(dirent)
    }
}

fn get_memory_protection(permissions: VmPermissions) -> MemoryProtection {
    let read = permissions.contains(VmPermissions::READ);
    let write = permissions.contains(VmPermissions::WRITE);
    let exec = permissions.contains(VmPermissions::EXECUTE);
    match (read, write, exec) {
        (false, false, false) => MemoryProtection::PAGE_NOACCESS,
        (false, false, true) => MemoryProtection::PAGE_EXECUTE,
        (true, false, false) => MemoryProtection::PAGE_READONLY,
        (true, false, true) => MemoryProtection::PAGE_EXECUTE_READ,
        (true | false, true, false) => MemoryProtection::PAGE_READWRITE,
        (true | false, true, true) => MemoryProtection::PAGE_EXECUTE_READWRITE,
    }
}
