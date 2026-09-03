//! The dynamic linker's debugger rendez-vous.
//!
//! This holds the `<link.h>` structures the linker publishes for debuggers, and
//! the `MD_LINUX_DSO_DEBUG` stream that is written straight from them.

use {
    super::{
        auxv::AuxvDumpInfo,
        minidump_writer::MinidumpWriter,
        process_inspection::ProcessInspector,
        process_reader::{CopyFromProcessError, ProcessReader},
        serializers::*,
    },
    crate::{
        mem_writer::{
            Buffer, MemoryArrayWriter, MemoryWriter, MemoryWriterError, write_string_to_location,
        },
        minidump_format::*,
    },
    plain::Plain,
};

type Result<T> = std::result::Result<T, SectionDsoDebugError>;
type RendezvousResult<T> = std::result::Result<T, RendezvousError>;

#[cfg(not(target_pointer_width = "64"))]
use goblin::elf32 as elf;
#[cfg(target_pointer_width = "64")]
use goblin::elf64 as elf;

use elf::{
    dynamic::Dyn,
    program_header::{PT_DYNAMIC, PT_PHDR, ProgramHeader},
};
use goblin::elf::dynamic::{DT_DEBUG, DT_NULL};

cfg_if::cfg_if! {
    if #[cfg(all(target_pointer_width = "64", target_arch = "arm"))] {
        type ElfAddr = u64;
    } else if #[cfg(all(target_pointer_width = "64", not(target_arch = "arm")))] {
        type ElfAddr = libc::Elf64_Addr;
    } else if #[cfg(all(target_pointer_width = "32", target_arch = "arm"))] {
        type ElfAddr = u32;
    } else if #[cfg(all(target_pointer_width = "32", not(target_arch = "arm")))] {
        type ElfAddr = libc::Elf32_Addr;
    }
}

#[derive(Debug, thiserror::Error, serde::Serialize)]
pub enum SectionDsoDebugError {
    #[error("Failed to write to memory")]
    MemoryWriterError(#[from] MemoryWriterError),
    #[error("Could not find: {0}")]
    CouldNotFind(&'static str),
    #[error("Failed to copy memory from process")]
    CopyFromProcessError(#[from] CopyFromProcessError),
    #[error("Failed to copy memory from process")]
    FromUTF8Error(
        #[from]
        #[serde(serialize_with = "serialize_from_utf8_error")]
        std::string::FromUtf8Error,
    ),
    #[error("Failed to reach the dynamic linker's rendez-vous")]
    Rendezvous(#[from] RendezvousError),
}

/// Errors on the way to the dynamic linker's rendez-vous.
#[derive(Debug, thiserror::Error, serde::Serialize)]
pub enum RendezvousError {
    #[error("failed to read program header table")]
    ReadProgramHeaderTableFailed(#[source] CopyFromProcessError),
    #[error("program header table missing self-pointer")]
    ProgramHeaderTableNoSelf,
    #[error("program header table missing dynamic section")]
    ProgramHeaderTableNoDynamic,
    #[error("unexpected size for dynamic section `{0}`")]
    InvalidDynamicSectionSize(usize),
    #[error("dynamic section missing NULL entry")]
    DynamicSectionMissingTerminator,
    #[error("failed to read dynamic section")]
    ReadDynamicSectionFailed(#[source] CopyFromProcessError),
    #[error("failed to find DT_DEBUG entry in dynamic section")]
    MissingDebugEntry,
}

/// Main executable description, as described by its own in-memory headers
#[derive(Debug)]
pub(crate) struct MainExecutable {
    /// How far the object moved from the addresses in its headers.
    pub(crate) load_bias: usize,
    program_headers: Vec<ProgramHeader>,
}

impl MainExecutable {
    /// Reads the program header table the kernel advertised through `AT_PHDR`
    /// and `AT_PHNUM`, and works out where the object owning it was loaded.
    pub(crate) fn read(
        memory_reader: &ProcessReader<'_>,
        program_header_table_address: usize,
        program_header_count: usize,
    ) -> RendezvousResult<Self> {
        let program_headers: Vec<ProgramHeader> = memory_reader
            .read_pod_vec(program_header_table_address, program_header_count)
            .map_err(RendezvousError::ReadProgramHeaderTableFailed)?;
        let load_bias = Self::compute_bias(&program_headers, program_header_table_address)?;

        Ok(Self {
            load_bias,
            program_headers,
        })
    }

    /// `PT_PHDR` describes the program header table itself, so the difference
    /// between the virtual address it claims and where it actually sits gives you
    /// the load bias.
    fn compute_bias(
        program_headers: &[ProgramHeader],
        program_header_table_address: usize,
    ) -> RendezvousResult<usize> {
        let table = program_headers
            .iter()
            .find(|hdr| hdr.p_type == PT_PHDR)
            .ok_or(RendezvousError::ProgramHeaderTableNoSelf)?;

        Ok(program_header_table_address - usize::try_from(table.p_vaddr).unwrap())
    }

    /// Where the first segment of the given type actually is in the target, and
    /// how big it is in memory.
    fn find_segment(&self, segment_type: u32) -> Option<(usize, usize)> {
        self.program_headers
            .iter()
            .find(|hdr| hdr.p_type == segment_type)
            .map(|hdr| {
                (
                    self.load_bias + usize::try_from(hdr.p_vaddr).unwrap(),
                    usize::try_from(hdr.p_memsz).unwrap(),
                )
            })
    }

    /// Copies the whole of `PT_DYNAMIC` out of the target.
    ///
    /// Returns the address it was read from alongside the entries.
    pub(crate) fn dynamic_section(
        &self,
        memory_reader: &ProcessReader<'_>,
    ) -> RendezvousResult<(usize, Vec<Dyn>)> {
        let (address, size) = self
            .find_segment(PT_DYNAMIC)
            .ok_or(RendezvousError::ProgramHeaderTableNoDynamic)?;

        // A partial trailing entry means we are not looking at a dynamic section.
        if !size.is_multiple_of(std::mem::size_of::<Dyn>()) {
            return Err(RendezvousError::InvalidDynamicSectionSize(size));
        }

        let entries: Vec<Dyn> = memory_reader
            .read_pod_vec(address, size / std::mem::size_of::<Dyn>())
            .map_err(RendezvousError::ReadDynamicSectionFailed)?;

        if entries.last() != Some(&Dyn::default()) {
            return Err(RendezvousError::DynamicSectionMissingTerminator);
        }

        Ok((address, entries))
    }
}

// Helper to isolate conversion noise
#[allow(clippy::useless_conversion)]
fn dtag(entry: &Dyn) -> u64 {
    u64::from(entry.d_tag)
}

/// Find the DT_DEBUG debugger rendezvous within a dynamic section,
/// typically gotten from `MainExecutable::dynamic_section`.
pub(crate) fn find_rendezvous_address(dynamic_section: &[Dyn]) -> RendezvousResult<usize> {
    dynamic_section
        .iter()
        .find_map(|entry| (dtag(entry) == DT_DEBUG).then_some(entry.d_val))
        .map(|address| usize::try_from(address).unwrap())
        .ok_or(RendezvousError::MissingDebugEntry)
}

/// How many bytes of the dynamic section actually say something: everything up
/// to and including the `DT_NULL` terminator.
fn dynamic_section_len(dynamic_section: &[Dyn]) -> usize {
    let entries = dynamic_section
        .iter()
        .position(|entry| dtag(entry) == DT_NULL)
        .map_or(dynamic_section.len(), |terminator| terminator + 1);

    entries * std::mem::size_of::<Dyn>()
}

/// Information for a single dynamically loaded module.
///
/// This structure contains important information about a dynamically-loaded
/// module, like its name and virtual address. It is also a node in a
/// doubly-linked list of such modules.
///
/// Only the leading members below are part of the protocol with the debugger —
/// the same format used in SVR4. The linker's own fields follow them, and we
/// never read those.
///
/// <https://sourceware.org/git/?p=glibc.git;a=blob;f=elf/link.h;h=b645760402514c4839686aaeade20dd5bb7725dd;hb=HEAD#l101>
#[derive(Debug, Clone, Default)]
#[repr(C)]
pub struct LinkMap {
    /// Difference between the addresses in the ELF file and the addresses in
    /// memory.
    pub(crate) l_addr: ElfAddr,
    /// Address of the absolute file name the object was found in.
    /// WAS: `char *`
    pub(crate) l_name: usize,
    /// Address of the dynamic section of the shared object.
    /// WAS: `ElfW(Dyn) *`
    pub(crate) l_ld: usize,
    /// Address of the next node in the chain of loaded objects.
    /// WAS: `struct link_map *`
    pub(crate) l_next: usize,
    /// Address of the previous node in the chain of loaded objects.
    /// WAS: `struct link_map *`
    pub(crate) l_prev: usize,
}

/// Shared object loading information for the debugger.
///
/// The Linux dynamic linker fills this in and points the main program's
/// `DT_DEBUG` dynamic entry at it. It is known as the "debugger rendez-vous"
/// point and is a legacy structure to assist debuggers in locating loaded
/// shared modules.
///
/// (But we're going to use it for minidump generation purposes.)
///
/// <https://sourceware.org/git/?p=glibc.git;a=blob;f=elf/link.h;h=b645760402514c4839686aaeade20dd5bb7725dd;hb=HEAD#l40>
#[derive(Debug, Clone, Default)]
#[repr(C)]
pub struct RDebug {
    /// Version number for this protocol.
    pub(crate) r_version: libc::c_int,
    /// Address of the head of the chain of loaded objects.
    /// WAS: `struct link_map *`
    pub(crate) r_map: usize,
    /// Address of a function internal to the run-time linker, that will always
    /// be called when the linker begins to map in a library or unmap it, and
    /// again when the mapping change is complete. The debugger can set a
    /// breakpoint at this address if it wants to notice shared object mapping
    /// changes.
    pub(crate) r_brk: ElfAddr,
    /// Which mapping change is taking place when `r_brk` is called: 0
    /// (`RT_CONSISTENT`, the change is complete), 1 (`RT_ADD`, beginning to add
    /// a new object) or 2 (`RT_DELETE`, beginning to remove an object mapping).
    pub(crate) r_state: libc::c_int,
    /// Base address the linker is loaded at.
    pub(crate) r_ldbase: ElfAddr,
}

// Safety: both are `repr(C)` aggregates of plain integers, so every bit pattern
// we could read out of the target process is a valid value.
unsafe impl Plain for LinkMap {}
unsafe impl Plain for RDebug {}

pub fn write_dso_debug_stream(
    process_inspector: &dyn ProcessInspector,
    buffer: &mut Buffer,
    auxv: &AuxvDumpInfo,
) -> Result<MDRawDirectory> {
    let phnum_max =
        auxv.get_program_header_count()
            .ok_or(SectionDsoDebugError::CouldNotFind("AT_PHNUM in auxv"))? as usize;
    let phdr = auxv
        .get_program_header_address()
        .ok_or(SectionDsoDebugError::CouldNotFind("AT_PHDR in auxv"))? as usize;

    let memory_reader = process_inspector.process_reader();
    let main_executable = MainExecutable::read(&memory_reader, phdr, phnum_max)?;

    let (dyn_addr, dynamic_section) = main_executable.dynamic_section(&memory_reader)?;
    let r_debug = find_rendezvous_address(&dynamic_section)?;

    // The "r_map" field of that r_debug struct contains a linked list of all
    // loaded DSOs.
    // Our list of DSOs potentially is different from the ones in the crashing
    // process. So, we have to be careful to never dereference pointers
    // directly. Instead, we copy every node out of the process.
    // See <link.h> for a more detailed discussion of the how the dynamic
    // loader communicates with debuggers.
    let debug_entry: RDebug = memory_reader.read_pod(r_debug)?;

    // Count the number of loaded DSOs
    let mut dso_vec = Vec::new();
    let mut curr_map = debug_entry.r_map;
    while curr_map != 0 {
        let map: LinkMap = memory_reader.read_pod(curr_map)?;
        curr_map = map.l_next;
        dso_vec.push(map);
    }

    let mut linkmap_rva = u32::MAX;
    if !dso_vec.is_empty() {
        // If we have at least one DSO, create an array of MDRawLinkMap
        // entries in the minidump file.
        let mut linkmap = MemoryArrayWriter::<MDRawLinkMap>::alloc_array(buffer, dso_vec.len())?;
        linkmap_rva = linkmap.location().rva;

        // Iterate over DSOs and write their information to mini dump
        for (idx, map) in dso_vec.iter().enumerate() {
            let mut filename = String::new();
            if map.l_name > 0 {
                let filename_data =
                    MinidumpWriter::copy_from_process(process_inspector, map.l_name, 256)?;

                // C - string is NULL-terminated
                if let Some(name) = filename_data.splitn(2, |x| *x == b'\0').next() {
                    filename = String::from_utf8(name.to_vec())?;
                }
            }
            let location = write_string_to_location(buffer, &filename)?;
            let entry = MDRawLinkMap {
                addr: map.l_addr,
                name: location.rva,
                ld: map.l_ld as ElfAddr,
            };

            linkmap.set_value_at(buffer, entry, idx)?;
        }
    }

    // Write MD_LINUX_DSO_DEBUG record
    let debug = MDRawDebug {
        version: debug_entry.r_version as u32,
        map: linkmap_rva,
        dso_count: dso_vec.len() as u32,
        brk: debug_entry.r_brk,
        ldbase: debug_entry.r_ldbase,
        dynamic: dyn_addr as ElfAddr,
    };
    let debug_loc = MemoryWriter::<MDRawDebug>::alloc_with_val(buffer, debug)?;

    let mut dirent = MDRawDirectory {
        stream_type: MDStreamType::LinuxDsoDebug as u32,
        location: debug_loc.location(),
    };

    // We'll want to copy *only* the dynamic section, not the entire segment.
    let dynamic_length = dynamic_section_len(&dynamic_section);
    dirent.location.data_size += dynamic_length as u32;
    let dso_debug_data =
        MinidumpWriter::copy_from_process(process_inspector, dyn_addr, dynamic_length)?;
    MemoryArrayWriter::write_bytes(buffer, &dso_debug_data);

    Ok(dirent)
}

#[cfg(test)]
// Every address below is 64 bit, and the header fields they go into are only
// that wide on a 64-bit target.
#[cfg(target_pointer_width = "64")]
mod tests {
    use super::*;
    use elf::program_header::PT_LOAD;

    /// Create a fake PT_PHDR with the given vaddr.
    fn program_header_table_at(virtual_address: u64) -> ProgramHeader {
        ProgramHeader {
            p_type: PT_PHDR,
            p_offset: 0x40,
            p_vaddr: virtual_address,
            ..Default::default()
        }
    }

    #[test]
    fn load_bias_pie() {
        let program_headers = [program_header_table_at(0x40)];

        let load_bias = MainExecutable::compute_bias(&program_headers, 0xaaaa_0040).unwrap();

        assert_eq!(load_bias, 0xaaaa_0000);
    }

    // No-PIE execs don't have a load bias
    #[test]
    fn load_bias_executable_non_pie() {
        let program_headers = [program_header_table_at(0x40_0040)];

        let load_bias = MainExecutable::compute_bias(&program_headers, 0x40_0040).unwrap();

        assert_eq!(load_bias, 0);
    }

    #[test]
    fn load_bias_no_pt_phdr() {
        let program_headers = [ProgramHeader {
            p_type: PT_LOAD,
            ..Default::default()
        }];

        assert!(matches!(
            MainExecutable::compute_bias(&program_headers, 0x40_0040),
            Err(RendezvousError::ProgramHeaderTableNoSelf)
        ));
    }
}
