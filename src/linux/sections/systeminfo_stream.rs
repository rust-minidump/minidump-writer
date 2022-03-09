use super::*;
use crate::linux::dumper_cpu_info::{os_information, write_cpu_information};

type Result<T> = std::result::Result<T, errors::SectionSystemInfoError>;

pub fn write(buffer: &mut DumpBuf) -> Result<MDRawDirectory> {
    let mut info_section = MemoryWriter::<MDRawSystemInfo>::alloc(buffer)?;
    let dirent = MDRawDirectory {
        stream_type: MDStreamType::SystemInfoStream as u32,
        location: info_section.location(),
    };

    let (platform_id, os_version) = os_information();
    let os_version_loc = write_string_to_location(buffer, &os_version)?;

    // SAFETY: POD
    let mut info = unsafe { std::mem::zeroed::<MDRawSystemInfo>() };
    info.platform_id = platform_id as u32;
    info.csd_version_rva = os_version_loc.rva;

    write_cpu_information(&mut info)?;

    info_section.set_value(buffer, info)?;
    Ok(dirent)
}
