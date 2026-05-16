use {
    super::vm_permissions::VmPermissions,
    goblin::elf,
    memmap2::{Mmap, MmapOptions},
    std::{
        ffi::OsString,
        fs::File,
        os::unix::ffi::{OsStrExt, OsStringExt},
        path::Path,
    },
};

pub const FREEBSD_GATE_LIBRARY_NAME: &str = "freebsd-gate.so";

type Result<T> = std::result::Result<T, MapsReaderError>;

const PATH_MAX: usize = 1024;

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

pub type MappingList = Vec<MappingInfo>;

#[derive(Debug, thiserror::Error, serde::Serialize)]
pub enum MapsReaderError {
    #[error("Failed to read memory mappings for process {0}")]
    ReadError(
        i32,
        #[source]
        #[serde(serialize_with = "crate::serializers::serialize_io_error")]
        std::io::Error,
    ),
    #[error("IO Error")]
    FileError(
        #[from]
        #[serde(serialize_with = "crate::serializers::serialize_io_error")]
        std::io::Error,
    ),
    #[error("Not safe to open mapping {}", .0.to_string_lossy())]
    NotSafeToOpenMapping(OsString),
    #[error("Mmapped file empty or not an ELF file")]
    MmapSanityCheckFailed,
}

#[repr(C)]
#[derive(Clone)]
struct KInfoVmEntry {
    kve_structsize: i32,
    kve_type: i32,
    kve_start: u64,
    kve_end: u64,
    kve_offset: u64,
    kve_vn_fileid: u64,
    kve_vn_fsid_freebsd11: u32,
    kve_flags: i32,
    kve_resident: i32,
    kve_private_resident: i32,
    kve_protection: i32,
    kve_ref_count: i32,
    kve_shadow_count: i32,
    kve_vn_type: i32,
    kve_vn_size: u64,
    kve_vn_rdev_freebsd11: u32,
    kve_vn_mode: u16,
    kve_status: u16,
    kve_type_spec: u64,
    kve_vn_rdev: u64,
    _kve_ispare: [i32; 8],
    kve_path: [u8; PATH_MAX],
}

const _: () = assert!(std::mem::size_of::<KInfoVmEntry>() == 1160);

#[link(name = "util")]
unsafe extern "C" {
    fn kinfo_getvmmap(pid: libc::pid_t, cntp: *mut libc::c_int) -> *mut KInfoVmEntry;
}

fn c_path_to_option(buf: &[u8; PATH_MAX]) -> Option<OsString> {
    let len = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    if len == 0 {
        return None;
    }
    Some(OsString::from_vec(buf[..len].to_vec()))
}

#[allow(unused)]
impl MappingInfo {
    pub fn for_pid(pid: i32, freebsd_gate_address: Option<u64>) -> Result<Vec<Self>> {
        let mut count: libc::c_int = 0;

        // SAFETY: kinfo_getvmmap is a well-defined libutil function that returns
        // a heap-allocated array via malloc. We check for null before use.
        // from_raw_parts is safe because the pointer is valid and count matches
        // the array length. free is correct because the pointer came from malloc.
        // The slice is copied to a Vec before freeing.
        let entries: Vec<KInfoVmEntry> = unsafe {
            let ptr = kinfo_getvmmap(pid as libc::pid_t, &mut count);
            if ptr.is_null() {
                return Err(MapsReaderError::ReadError(
                    pid,
                    std::io::Error::last_os_error(),
                ));
            }
            let slice = std::slice::from_raw_parts(ptr, count as usize);
            let vec = slice.to_vec();
            libc::free(ptr as *mut libc::c_void);
            vec
        };

        let mut infos: Vec<Self> = Vec::new();

        for entry in &entries {
            let start_address = entry.kve_start as usize;
            let end_address = entry.kve_end as usize;
            let mut offset = entry.kve_offset as usize;

            let mut permissions = VmPermissions::empty();
            if entry.kve_protection & libc::KVME_PROT_READ != 0 {
                permissions |= VmPermissions::READ;
            }
            if entry.kve_protection & libc::KVME_PROT_WRITE != 0 {
                permissions |= VmPermissions::WRITE;
            }
            if entry.kve_protection & libc::KVME_PROT_EXEC != 0 {
                permissions |= VmPermissions::EXECUTE;
            }
            if entry.kve_flags & libc::KVME_FLAG_COW != 0 {
                permissions |= VmPermissions::PRIVATE;
            }

            let mut name = c_path_to_option(&entry.kve_path);
            #[allow(clippy::unnecessary_map_or)]
            let is_path = name
                .as_ref()
                .map_or(false, |n| n.as_bytes().contains(&b'/'));

            #[allow(clippy::collapsible_if)]
            if let Some(gate_addr) = freebsd_gate_address {
                if !is_path && start_address == gate_addr as usize {
                    name = Some(OsString::from(FREEBSD_GATE_LIBRARY_NAME));
                    offset = 0;
                }
            }

            // Merge adjacent mappings with the same name into a single module,
            // assuming they're a single library mapped by the dynamic linker.
            #[allow(clippy::collapsible_if)]
            if let Some(prev) = infos.last_mut() {
                if start_address == prev.end_address() && name.is_some() && name == prev.name {
                    prev.system_mapping_info.end_address = end_address;
                    prev.size = end_address - prev.start_address;
                    prev.permissions |= permissions;
                    continue;
                }
            }

            infos.push(MappingInfo {
                start_address,
                size: end_address - start_address,
                system_mapping_info: SystemMappingInfo {
                    start_address,
                    end_address,
                },
                offset,
                permissions,
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

    pub fn system_mapping_info(&self) -> SystemMappingInfo {
        self.system_mapping_info.clone()
    }

    pub fn contains_address(&self, address: usize) -> bool {
        self.system_mapping_info.start_address <= address
            && address < self.system_mapping_info.end_address
    }

    pub fn is_executable(&self) -> bool {
        self.permissions.contains(VmPermissions::EXECUTE)
    }

    pub fn is_readable(&self) -> bool {
        self.permissions.contains(VmPermissions::READ)
    }

    pub fn is_writable(&self) -> bool {
        self.permissions.contains(VmPermissions::WRITE)
    }

    pub fn so_name(&self) -> Option<OsString> {
        self.name
            .as_ref()
            .and_then(|n| Path::new(n).file_name().map(|f| f.to_os_string()))
    }

    pub fn name_is_path(&self) -> bool {
        #[allow(clippy::unnecessary_map_or)]
        self.name
            .as_ref()
            .map_or(false, |n| n.as_bytes().contains(&b'/'))
    }

    pub fn is_mapped_file_safe_to_open(name: &Option<OsString>) -> bool {
        #[allow(clippy::unnecessary_map_or)]
        name.as_ref()
            .map_or(true, |n| !n.as_bytes().starts_with(b"/dev/"))
    }

    pub fn get_mmap(&self) -> Result<Mmap> {
        if !Self::is_mapped_file_safe_to_open(&self.name) {
            return Err(MapsReaderError::NotSafeToOpenMapping(
                self.name.clone().unwrap_or_default(),
            ));
        }

        let filename = self.name.clone().unwrap_or_default();
        // SAFETY: We request a valid file mapping with appropriate permissions.
        // The kernel validates the parameters and File::open ensures a valid fd.
        let mapped_file = unsafe {
            MmapOptions::new()
                .offset(self.offset as u64)
                .map(&File::open(filename)?)?
        };

        if mapped_file.is_empty() || mapped_file.len() < elf::header::SELFMAG {
            return Err(MapsReaderError::MmapSanityCheckFailed);
        }

        Ok(mapped_file)
    }

    pub fn stack_has_pointer_to_mapping(&self, stack_copy: &[u8], sp_offset: usize) -> bool {
        let word_size = std::mem::size_of::<usize>();
        if stack_copy.len() < word_size {
            return false;
        }

        let mut offset = (sp_offset + word_size - 1) & !(word_size - 1);
        while offset + word_size <= stack_copy.len() {
            let mut word = [0u8; std::mem::size_of::<usize>()];
            word.copy_from_slice(&stack_copy[offset..offset + word_size]);
            if self.contains_address(usize::from_ne_bytes(word)) {
                return true;
            }
            offset += word_size;
        }

        false
    }

    pub fn is_contained_in(&self, user_mapping_list: &MappingList) -> bool {
        for user in user_mapping_list {
            if self.start_address >= user.start_address
                && (self.start_address + self.size) <= (user.start_address + user.size)
            {
                return true;
            }
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
