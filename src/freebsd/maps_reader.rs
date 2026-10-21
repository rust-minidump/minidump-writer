//! Memory mapping enumeration on FreeBSD.
//!
//! The mapping list is obtained through the
//! [`ProcessInspector`](crate::freebsd::process_inspection::ProcessInspector)
//! (backed by `kinfo_getvmmap` in the local implementation).

use {
    super::{
        process_inspection::{self, ProcessInspector},
        vm_permissions::VmPermissions,
    },
    std::{ffi::OsString, os::unix::ffi::OsStrExt},
};

type Result<T> = std::result::Result<T, MapsReaderError>;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SystemMappingInfo {
    pub start_address: usize,
    pub end_address: usize,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct MappingInfo {
    pub start_address: usize,
    pub size: usize,
    pub system_mapping_info: SystemMappingInfo,
    pub offset: usize,
    pub permissions: VmPermissions,
    pub name: Option<OsString>,
}

/// A user-supplied mapping, with an optional build id used for its CV record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MappingEntry {
    pub info: MappingInfo,
    pub identifier: Option<Vec<u8>>,
}

impl From<MappingInfo> for MappingEntry {
    fn from(info: MappingInfo) -> Self {
        Self {
            info,
            identifier: None,
        }
    }
}

#[derive(Debug, thiserror::Error, serde::Serialize)]
pub enum MapsReaderError {
    #[error("failed to read memory mappings")]
    ReadError(#[source] process_inspection::Error),
}

impl MappingInfo {
    /// Enumerates the memory mappings of the inspected process.
    ///
    /// Adjacent mappings of the same file are merged into a single entry,
    /// assuming they're a single library mapped by the dynamic linker.
    pub fn from_inspector(process_inspector: &dyn ProcessInspector) -> Result<Vec<Self>> {
        let entries = process_inspector
            .get_vm_map()
            .map_err(MapsReaderError::ReadError)?;

        let mut infos: Vec<Self> = Vec::new();

        for entry in &entries {
            let start_address = entry.start_address as usize;
            let end_address = entry.end_address as usize;
            let offset = entry.offset as usize;
            let name = entry.file_path.clone();

            // Merge adjacent mappings of the same file into a single entry,
            // assuming they're a single library mapped by the dynamic linker.
            if let Some(prev) = infos.last_mut()
                && start_address == prev.end_address()
                && name.is_some()
                && name == prev.name
            {
                prev.system_mapping_info.end_address = end_address;
                prev.size = end_address - prev.start_address;
                prev.permissions |= entry.permissions;
                continue;
            }
            // Also merge address ranges the linker reserved but a loaded
            // library didn't use: these appear as an anonymous private
            // mapping with no access flags directly following an executable
            // file mapping.
            if let Some(prev) = infos.last_mut()
                && start_address == prev.end_address()
                && prev.is_executable()
                && prev.name_is_path()
                && (offset == 0 || offset == prev.end_address())
                && entry.permissions == VmPermissions::PRIVATE
            {
                prev.system_mapping_info.end_address = end_address;
                prev.size = end_address - prev.start_address;
                continue;
            }
            // Unused reserved ranges can also appear inside a library: fold a
            // single empty page sandwiched between two mappings of the same
            // file into the surrounding module.
            if infos.len() >= 2
                && let [.., prev_prev, prev] = &mut infos[..]
                && prev_prev.name_is_path()
                && prev_prev.end_address() == prev.start_address
                && prev.is_empty_page()
                && prev.end_address() == start_address
                && name == prev_prev.name
            {
                prev_prev.system_mapping_info.end_address = end_address;
                prev_prev.size = end_address - prev_prev.start_address;
                prev_prev.permissions |= entry.permissions;
                infos.pop();
                continue;
            }

            infos.push(MappingInfo {
                start_address,
                size: end_address - start_address,
                system_mapping_info: SystemMappingInfo {
                    start_address,
                    end_address,
                },
                offset,
                permissions: entry.permissions,
                name,
            });
        }

        Ok(infos)
    }

    pub fn end_address(&self) -> usize {
        self.start_address + self.size
    }

    pub fn is_interesting(&self) -> bool {
        self.name.is_some() && (self.offset == 0 || self.is_executable()) && self.size >= 4096
    }

    pub fn contains_address(&self, address: usize) -> bool {
        self.system_mapping_info.start_address <= address
            && address < self.system_mapping_info.end_address
    }

    pub fn is_executable(&self) -> bool {
        self.permissions.contains(VmPermissions::EXECUTE)
    }

    /// An anonymous, unaccessible page, as reserved (but unused) by the
    /// dynamic linker.
    pub fn is_empty_page(&self) -> bool {
        self.offset == 0 && self.permissions == VmPermissions::PRIVATE && self.name.is_none()
    }

    pub fn name_is_path(&self) -> bool {
        self.name
            .as_ref()
            .is_some_and(|n| n.as_bytes().contains(&b'/'))
    }

    pub fn stack_has_pointer_to_mapping(&self, stack_copy: &[u8], sp_offset: usize) -> bool {
        let word_size = std::mem::size_of::<usize>();
        if stack_copy.len() < word_size {
            return false;
        }

        let mut offset = (sp_offset + word_size - 1) & !(word_size - 1);
        while offset + word_size <= stack_copy.len() {
            let word = usize::from_ne_bytes(
                stack_copy[offset..offset + word_size]
                    .try_into()
                    .expect("length checked above"),
            );
            if self.contains_address(word) {
                return true;
            }
            offset += word_size;
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stack_has_pointer_to_mapping_respects_stack_offset() {
        let mapping = MappingInfo {
            start_address: 0x1000,
            size: 0x1000,
            system_mapping_info: SystemMappingInfo {
                start_address: 0x1000,
                end_address: 0x2000,
            },
            ..Default::default()
        };

        let word_size = std::mem::size_of::<usize>();
        let mut stack = vec![0u8; word_size * 3];
        stack[word_size..word_size * 2].copy_from_slice(&0x1800usize.to_ne_bytes());
        stack[word_size * 2..word_size * 3].copy_from_slice(&0x3000usize.to_ne_bytes());

        assert!(mapping.stack_has_pointer_to_mapping(&stack, 1));
        assert!(!mapping.stack_has_pointer_to_mapping(&stack, word_size * 2));
    }
}
