use crate::minidump_writer::{DumpBuf, MinidumpWriter};
use crate::sections::{MemoryArrayWriter, MemoryWriter};
use crate::Result;
use minidump_common::format::*;

pub fn write(config: &mut MinidumpWriter, buffer: &mut DumpBuf) -> Result<MDRawDirectory> {
    let list_header =
        MemoryWriter::<u32>::alloc_with_val(buffer, config.memory_blocks.len() as u32)?;

    let mut dirent = MDRawDirectory {
        stream_type: MD_MEMORY_LIST_STREAM,
        location: list_header.location(),
    };

    let block_list =
        MemoryArrayWriter::<MDMemoryDescriptor>::alloc_from_array(buffer, &config.memory_blocks)?;

    dirent.location.data_size += block_list.location().data_size;

    Ok(dirent)
}
