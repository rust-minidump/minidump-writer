use super::*;
use crate::linux::dumper_cpu_info as dci;

pub fn write(buffer: &mut DumpBuf) -> Result<MDRawDirectory, errors::SectionSystemInfoError> {
    let mut info_section = MemoryWriter::<MDRawSystemInfo>::alloc(buffer)?;
    let dirent = MDRawDirectory {
        stream_type: MDStreamType::SystemInfoStream as u32,
        location: info_section.location(),
    };
    let mut info: MDRawSystemInfo = Default::default();
    dci::write_cpu_information(&mut info)?;
    dci::write_os_information(buffer, &mut info)?;

    info_section.set_value(buffer, info)?;
    Ok(dirent)
}
