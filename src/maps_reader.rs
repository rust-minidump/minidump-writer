use crate::auxv_reader::AuxvType;
use crate::Result;
use std::convert::TryInto;

pub const LINUX_GATE_LIBRARY_NAME: &'static str = "linux-gate.so";
pub const DELETED_SUFFIX: &'static str = " (deleted)";
pub const MOZILLA_IPC_PREFIX: &'static str = "org.mozilla.ipc.";
pub const RESERVED_FLAGS: &'static str = " ---p";

#[derive(Debug)]
pub struct SystemMappingInfo {
    pub start_address: usize,
    pub end_address: usize,
}

// One of these is produced for each mapping in the process (i.e. line in
// /proc/$x/maps).
#[derive(Debug)]
pub struct MappingInfo {
    // On Android, relocation packing can mean that the reported start
    // address of the mapping must be adjusted by a bias in order to
    // compensate for the compression of the relocation section. The
    // following two members hold (after LateInit) the adjusted mapping
    // range. See crbug.com/606972 for more information.
    pub start_address: usize,
    pub size: usize,
    // When Android relocation packing causes |start_addr| and |size| to
    // be modified with a load bias, we need to remember the unbiased
    // address range. The following structure holds the original mapping
    // address range as reported by the operating system.
    pub system_mapping_info: SystemMappingInfo,
    pub offset: usize,    // offset into the backed file.
    pub executable: bool, // true if the mapping has the execute bit set.
    pub name: Option<String>,
}

#[derive(Debug)]
pub struct MappingEntry {
    first: MappingInfo,
    second: Vec<u8>,
}

// A list of <MappingInfo, GUID>
// type MappingList = Vec<MappingEntry>;
// Not sure if we need to use a linked list
//typedef std::list<MappingEntry> MappingList;

#[derive(Debug)]
pub enum MappingInfoParsingResult {
    SkipLine,
    Success(MappingInfo),
}

fn is_ipc_shared_memory_segment(pathname: Option<&str>) -> bool {
    if let Some(name) = pathname {
        name.contains(MOZILLA_IPC_PREFIX) && name.contains(DELETED_SUFFIX)
    } else {
        false
    }
}

fn is_mapping_a_path(pathname: Option<&str>) -> bool {
    match pathname {
        Some(x) => x.contains("/"),
        None => false,
    }
}

impl MappingInfo {
    pub fn parse_from_line(
        line: &str,
        linux_gate_loc: AuxvType,
        last_mapping: Option<&mut MappingInfo>,
    ) -> Result<MappingInfoParsingResult> {
        let mut splits = line.split_ascii_whitespace();
        let address = splits.next().ok_or("maps malformed: No address found")?;
        let perms = splits.next().ok_or("maps malformed: No perms found")?;
        let mut offset =
            usize::from_str_radix(splits.next().ok_or("maps malformed: No offset found")?, 16)?;
        let _dev = splits.next().ok_or("maps malformed: No dev found")?;
        let _inode = splits.next().ok_or("maps malformed: No inode found")?;
        let mut pathname = splits.next(); // Optional

        let mut addresses = address.split('-');
        let start_address = usize::from_str_radix(addresses.next().unwrap(), 16)?;
        let end_address = usize::from_str_radix(addresses.next().unwrap(), 16)?;

        let executable = perms.contains("x");

        // Only copy name if the name is a valid path name, or if
        // it's the VDSO image.
        let is_path = is_mapping_a_path(pathname);

        if !is_path && linux_gate_loc != 0 && start_address == linux_gate_loc.try_into()? {
            pathname = Some(LINUX_GATE_LIBRARY_NAME);
            offset = 0;
        }

        if is_ipc_shared_memory_segment(pathname) {
            // Skip shared memory segments used for IPC
            return Ok(MappingInfoParsingResult::SkipLine);
        }

        match (pathname, last_mapping) {
            (Some(_name), Some(module)) => {
                // Merge adjacent mappings into one module, assuming they're a single
                // library mapped by the dynamic linker.
                if (start_address == module.start_address + module.size)
                    && (pathname == module.name.as_deref())
                {
                    module.system_mapping_info.end_address = end_address;
                    module.size = end_address - module.start_address;
                    module.executable |= executable;
                    return Ok(MappingInfoParsingResult::SkipLine);
                }
            }
            (None, Some(module)) => {
                // Also merge mappings that result from address ranges that the
                // linker reserved but which a loaded library did not use. These
                // appear as an anonymous private mapping with no access flags set
                // and which directly follow an executable mapping.
                let module_end_address = module.start_address + module.size;
                if (start_address == module_end_address)
                    && module.executable
                    && is_mapping_a_path(module.name.as_deref())
                    && offset == 0
                    || offset == module_end_address && perms == RESERVED_FLAGS
                {
                    module.size = end_address - module.start_address;
                    return Ok(MappingInfoParsingResult::SkipLine);
                }
            }
            _ => (),
        }

        let info = MappingInfo {
            start_address,
            size: end_address - start_address,
            system_mapping_info: SystemMappingInfo {
                start_address,
                end_address,
            },
            offset,
            executable,
            name: pathname.map(ToOwned::to_owned),
        };

        Ok(MappingInfoParsingResult::Success(info))
    }
}
