use crate::dumper_cpu_info::{write_cpu_information, write_os_information};
use crate::minidump_writer::DumpBuf;
use crate::sections::MemoryWriter;
use crate::Result;
use minidump_common::format::*;

pub fn write(buffer: &mut DumpBuf) -> Result<MDRawDirectory> {
    let mut info_section = MemoryWriter::<MDRawSystemInfo>::alloc(buffer)?;
    let dirent = MDRawDirectory {
        stream_type: MD_SYSTEM_INFO_STREAM,
        location: info_section.location(),
    };
    let mut info: MDRawSystemInfo = Default::default();
    write_cpu_information(&mut info)?;
    write_os_information(buffer, &mut info)?;

    info_section.set_value(buffer, info)?;
    Ok(dirent)
}
