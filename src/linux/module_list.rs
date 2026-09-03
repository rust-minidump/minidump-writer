//! Enumeration of the ELF modules loaded into the target process.

use std::{
    ffi::{OsStr, OsString},
    path::{Path, PathBuf},
};

use super::{
    Pid,
    dso_debug::{LinkMap, MainExecutable, RDebug, RendezvousError, find_rendezvous_address},
    process_inspection::process_reader::ProcessReader,
};
use goblin::elf::{
    dynamic::DT_LOOS,
    header::ET_DYN,
    program_header::{PF_X, PT_LOAD},
};

use crate::{
    linux::process_inspection::ProcessInspector,
    maps_reader::{MappingEntry, MappingList},
    module_reader::{ModuleReader, ModuleReaderError, ProcessModuleMemoryReader, ReadModuleMemory},
};
use error_graph::WriteErrorList;

use super::maps_reader::MappingInfo;

#[derive(thiserror::Error, Debug, serde::Serialize)]
pub enum ModuleListError {
    #[error("error reading soname from file")]
    ReadSoNameFromFileFailed(#[source] ModuleReaderError),
}

/// Errors that only cost us the accuracy of a single entry of the module list.
#[derive(thiserror::Error, Debug, serde::Serialize)]
pub enum ModuleResolveError {
    #[error(
        "user-supplied module `{}` starts at {base_address:#x}, where another \
         one already does, so only one of them can be written",
        name.to_string_lossy()
    )]
    DuplicateUserModule { name: OsString, base_address: usize },
    #[error(
        "module `{}` at {base_address:#x} was clamped at {clamped_to:#x} while \
         its last executable segment ends at {code_end:#x}",
        name.to_string_lossy()
    )]
    ModuleImageClamped {
        name: OsString,
        base_address: usize,
        code_end: usize,
        clamped_to: usize,
    },
}

/// Errors from walking the dynamic linker's debugger rendez-vous.
#[derive(Debug, thiserror::Error, serde::Serialize)]
pub enum FromRendezvousError {
    #[error("the main executable is not position-independent")]
    NonPieMainExecutable,
    #[error("failed to read the dynamic linker's rendez-vous")]
    Rendezvous(#[from] RendezvousError),
    #[error("an error occurred iterating the link_map linked list")]
    IterateLinkMapFailed(#[source] RendezvousError),
    #[error("skipping module `{}` at {address:#x}", name.to_string_lossy())]
    SkippedModule {
        name: OsString,
        address: usize,
        #[source]
        source: ModuleCandidateError,
    },
}

/// Errors that only cost us one entry of the module list.
#[derive(Debug, thiserror::Error, serde::Serialize)]
pub enum ModuleCandidateError {
    #[error("failed reading the name its `link_map` entry points at")]
    ReadNameFailed(#[source] RendezvousError),
    #[error("failed to read the module's ELF data")]
    ReadModuleFailed(#[source] ModuleReaderError),
    #[error("the module's program header table has no loadable segment")]
    NoLoadableSegment,
}

/// Where a module's information came from.
#[derive(Debug)]
pub enum ModuleSource {
    /// Read out of the process, be it from its memory map or from the dynamic
    /// linker's rendez-vous.
    Process,
    /// Supplied by the user, and taken at face value: they know things about it
    /// that we cannot derive, which is why it was supplied in the first place.
    User { identifier: Vec<u8> },
}

impl ModuleSource {
    fn is_user(&self) -> bool {
        matches!(self, Self::User { .. })
    }
}

/// An entry of the module list written to the `ModuleListStream`.
#[derive(Debug)]
pub struct ModuleInfo {
    /// Where the ELF object was loaded — the minidump's `base_of_image`.
    pub base_address: usize,
    pub size: usize,
    pub name: Option<OsString>,
    /// Offset of the object within its backing file; typically 0, but might
    /// not be, e.g. if loaded from an APK.
    pub file_offset: usize,
    /// Whether the object has an executable segment.
    /// It *is* possible to load data-only ELF objects!
    pub executable: bool,
    pub source: ModuleSource,
}

/// A module we may write, before its extent is final.
#[derive(Debug)]
pub struct ModuleCandidate {
    base_address: usize,
    end_address: usize,
    /// End of the object's last executable segment, or `base_address` if none.
    code_end: usize,
    name: Option<OsString>,
    file_offset: usize,
    source: ModuleSource,
}

impl ModuleCandidate {
    /// Builds a module from user-supplied information.
    fn from_user_entry(entry: &MappingEntry) -> Self {
        Self {
            base_address: entry.mapping.start_address,
            end_address: entry.mapping.start_address + entry.mapping.size,
            // Let's assume it's all executable.
            code_end: entry.mapping.start_address + entry.mapping.size,
            name: entry.mapping.name.clone(),
            file_offset: entry.mapping.offset,
            source: ModuleSource::User {
                identifier: entry.identifier.clone(),
            },
        }
    }

    /// Whether `address` falls within this module's extent.
    fn contains_address(&self, address: usize) -> bool {
        (self.base_address..self.end_address).contains(&address)
    }

    fn into_module(self) -> ModuleInfo {
        ModuleInfo {
            base_address: self.base_address,
            size: self.end_address - self.base_address,
            name: self.name,
            file_offset: self.file_offset,
            executable: self.code_end > self.base_address,
            source: self.source,
        }
    }
}

/// Any detected module that starts within a user-provided module must be dropped, as just keeping
/// the tail would make its addresses unresolvable anyway.
fn filter_out_user_overlap(
    process_candidates: &mut Vec<ModuleCandidate>,
    user_candidates: &[ModuleCandidate],
) {
    process_candidates.retain(|c| {
        !user_candidates
            .iter()
            .any(|uc| uc.contains_address(c.base_address))
    });
}

/// If a module contains the entry-point, and it's not already the first
/// one, then we need to make it be first. This is because the minidump
/// format assumes the first module is the one that corresponds to the main
/// executable (as codified in processor/minidump.cc:MinidumpModuleList::GetMainModule()).
fn ensure_entrypoint_is_first(candidates: &mut [ModuleCandidate], entry_point: Option<usize>) {
    if let Some(entry_point) = entry_point
        && let Some(index) = candidates
            .iter()
            .position(|c| c.contains_address(entry_point))
    {
        candidates.swap(0, index);
    }
}

/// Turns the candidates into the entries written to the `ModuleListStream`.
pub(crate) fn resolve(
    candidates: Vec<ModuleCandidate>,
    entry_point: Option<usize>,
    mut soft_errors: impl WriteErrorList<ModuleResolveError>,
) -> Vec<ModuleInfo> {
    let (user_candidates, mut process_candidates): (Vec<_>, Vec<_>) =
        candidates.into_iter().partition(|c| c.source.is_user());

    // Sanity check on the user-provided modules: if they happen to start at the same place,
    // log the error and keep them both, as we don't have enough data to prioritize one.
    for (index, candidate) in user_candidates.iter().enumerate() {
        if user_candidates[..index]
            .iter()
            .any(|earlier| earlier.base_address == candidate.base_address)
        {
            soft_errors.push(ModuleResolveError::DuplicateUserModule {
                name: candidate.name.clone().unwrap_or_default(),
                base_address: candidate.base_address,
            });
        }
    }

    filter_out_user_overlap(&mut process_candidates, &user_candidates);
    ensure_entrypoint_is_first(&mut process_candidates, entry_point);

    let mut candidates: Vec<ModuleCandidate> = process_candidates
        .into_iter()
        .chain(user_candidates)
        .collect();
    clamp_overlapping_modules(&mut candidates, &mut soft_errors);

    candidates
        .into_iter()
        .map(ModuleCandidate::into_module)
        .collect()
}

/// Shortens any module whose image overlaps another entry of the module list.
fn clamp_overlapping_modules(
    modules: &mut [ModuleCandidate],
    mut soft_errors: impl WriteErrorList<ModuleResolveError>,
) {
    let mut claims: Vec<usize> = modules.iter().map(|module| module.base_address).collect();
    claims.sort_unstable();

    for module in modules {
        let Some(&claim) = claims.iter().find(|&&claim| claim > module.base_address) else {
            continue;
        };
        if claim < module.end_address {
            // Clamping is typically harmless *unless* the stuff that's cut
            // out is executable code.
            if claim < module.code_end {
                soft_errors.push(ModuleResolveError::ModuleImageClamped {
                    name: module.name.clone().unwrap_or_default(),
                    base_address: module.base_address,
                    code_end: module.code_end,
                    clamped_to: claim,
                });
            }
            module.end_address = claim;
        }
    }
}

/// Where the object behind `mapping` was loaded.
///
/// `/proc/<pid>/maps` reports where a mapping *starts*, which for an Android
/// object with packed relocations is `min_vaddr` above where the object was
/// actually loaded. Everywhere else the two are the same address.
#[cfg(target_os = "android")]
fn loaded_at(process_inspector: &dyn ProcessInspector, mapping: &MappingInfo) -> usize {
    // Filter out unlikely candidates for libraries
    if mapping.is_executable() && mapping.name_is_path() {
        super::android::effective_load_base(process_inspector, mapping.start_address)
    } else {
        mapping.start_address
    }
}

#[cfg(not(target_os = "android"))]
fn loaded_at(_process_inspector: &dyn ProcessInspector, mapping: &MappingInfo) -> usize {
    mapping.start_address
}

impl ModuleCandidate {
    /// Builds a module from a memory mapping.
    fn from_mapping(process_inspector: &dyn ProcessInspector, mapping: &MappingInfo) -> Self {
        // Adjust the base address if needed.
        let base_address = loaded_at(process_inspector, mapping);

        Self {
            base_address,
            end_address: mapping.start_address + mapping.size,
            code_end: if mapping.is_executable() {
                mapping.start_address + mapping.size
            } else {
                mapping.start_address
            },
            name: mapping.name.clone(),
            file_offset: mapping.offset,
            source: ModuleSource::Process,
        }
    }
}

impl ModuleInfo {
    pub fn effective_path_name_and_version(
        &self,
        process_inspector: &dyn ProcessInspector,
        soname: Option<String>,
        soft_errors: impl WriteErrorList<ModuleListError>,
    ) -> (PathBuf, String, Option<SoVersion>) {
        let mut file_path = PathBuf::from(self.name.clone().unwrap_or_default());

        // Just use the filesystem name if no SONAME is present.
        let Some(file_name) = self.find_soname(soname, process_inspector, soft_errors) else {
            //   file_path := /path/to/libname.so
            //   file_name := libname.so
            let file_name = file_path
                .file_name()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_default();

            return (file_path, file_name, self.so_version());
        };

        self.fix_filename(&mut file_path, &file_name);
        (file_path, file_name, self.so_version())
    }

    /// Tools such as minidump_stackwalk use the name of the module to look up
    /// symbols produced by dump_syms. dump_syms will prefer to use a module's
    /// DT_SONAME as the module name, if one exists, and will fall back to the
    /// filesystem name of the module. For this reason, we try different approaches
    /// before giving up.
    ///
    /// We prefer the SONAME if it's available rather than parse the path.
    fn find_soname(
        &self,
        provided_soname: Option<String>,
        process_inspector: &dyn ProcessInspector,
        mut soft_errors: impl WriteErrorList<ModuleListError>,
    ) -> Option<String> {
        provided_soname.or_else(|| {
            // User supplied the filename, let's use that directly.
            if self.source.is_user() {
                return None;
            }
            match self.elf_so_name(process_inspector) {
                Ok(soname) => soname,
                Err(e) => {
                    // Log error and move on to fallback path.
                    soft_errors.push(e);
                    None
                }
            }
        })
    }

    /// Look in the module ELF metadata to find its soname if it has any.
    /// Typically, executables don't have one.
    fn elf_so_name(
        &self,
        process_inspector: &dyn ProcessInspector,
    ) -> Result<Option<String>, ModuleListError> {
        let path = Path::new(self.name.as_deref().unwrap_or_default());
        match super::module_reader::read_soname_from_file(process_inspector, path, self.file_offset)
        {
            Ok(soname) => Ok(Some(soname)),
            Err(ModuleReaderError::NoSoName { .. }) => Ok(None),
            Err(e) => Err(ModuleListError::ReadSoNameFromFileFailed(e)),
        }
    }

    #[inline]
    fn so_version(&self) -> Option<SoVersion> {
        SoVersion::parse(self.name.as_deref()?)
    }

    /// Handle edge-cases on filename, e.g. archive files.
    fn fix_filename(&self, path: &mut PathBuf, file_name: &str) {
        if self.executable && self.file_offset != 0 {
            // If an executable is mapped from a non-zero offset, this is likely because
            // the executable was loaded directly from inside an archive file (e.g., an
            // apk on Android).
            // In this case, we append the file_name to the mapped archive path:
            //   file_name := libname.so
            //   file_path := /path/to/ARCHIVE.APK/libname.so
            path.push(file_name);
        } else {
            // Otherwise, replace the basename with the SONAME.
            path.set_file_name(file_name);
        }
    }
}

/// Build module information out of kernel mapping data
///
/// Only requires access to /proc/pid/maps, but is ultimately just an approximation based on
/// observed behaviour of linkers.
pub(crate) fn from_mappings(
    process_inspector: &dyn ProcessInspector,
    mappings: &[MappingInfo],
) -> Vec<ModuleCandidate> {
    mappings
        .iter()
        .filter(|mapping| mapping.is_interesting())
        .map(|mapping| ModuleCandidate::from_mapping(process_inspector, mapping))
        .collect()
}

/// Builds the modules the user told us about.
pub(crate) fn from_user_mappings(user_mapping_list: &MappingList) -> Vec<ModuleCandidate> {
    user_mapping_list
        .iter()
        .map(ModuleCandidate::from_user_entry)
        .collect()
}

/// Version metadata retrieved from an .so filename
///
/// There is no standard for .so version numbers so this implementation just
/// does a best effort to pull as much data as it can based on real .so schemes
/// seen
///
/// That being said, the [libtool](https://www.gnu.org/software/libtool/manual/html_node/Libtool-versioning.html)
/// versioning scheme is fairly common
#[cfg_attr(test, derive(Debug))]
pub struct SoVersion {
    /// Might be non-zero if there is at least one non-zero numeric component after .so.
    ///
    /// Equivalent to `current` in libtool versions
    pub major: u32,
    /// The numeric component after the major version, if any
    ///
    /// Equivalent to `revision` in libtool versions
    pub minor: u32,
    /// The numeric component after the minor version, if any
    ///
    /// Equivalent to `age` in libtool versions
    pub patch: u32,
    /// The patch component may contain additional non-numeric metadata similar
    /// to a semver prelease, this is any numeric data that suffixes that prerelease
    /// string
    pub prerelease: u32,
}

impl SoVersion {
    /// Attempts to retrieve the .so version of the elf path via its filename
    fn parse(so_path: &OsStr) -> Option<Self> {
        let filename = std::path::Path::new(so_path).file_name()?;

        // Avoid an allocation unless the string contains non-utf8
        let filename = filename.to_string_lossy();

        let (_, version) = filename.split_once(".so.")?;

        let mut sov = Self {
            major: 0,
            minor: 0,
            patch: 0,
            prerelease: 0,
        };

        let comps = [
            &mut sov.major,
            &mut sov.minor,
            &mut sov.patch,
            &mut sov.prerelease,
        ];

        for (i, comp) in version.split('.').enumerate() {
            if i <= 1 {
                *comps[i] = comp.parse().unwrap_or_default();
            } else if i >= 4 {
                break;
            } else {
                // In some cases the release/patch version is alphanumeric (eg. '2rc5'),
                // so try to parse either a single or two numbers
                if let Some(pend) = comp.find(|c: char| !c.is_ascii_digit()) {
                    if let Ok(patch) = comp[..pend].parse() {
                        *comps[i] = patch;
                    }

                    if i >= comps.len() - 1 {
                        break;
                    }
                    if let Some(pre) = comp.rfind(|c: char| !c.is_ascii_digit())
                        && let Ok(pre) = comp[pre + 1..].parse()
                    {
                        *comps[i + 1] = pre;
                        break;
                    }
                } else {
                    *comps[i] = comp.parse().unwrap_or_default();
                }
            }
        }

        Some(sov)
    }
}

#[cfg(test)]
impl PartialEq<(u32, u32, u32, u32)> for SoVersion {
    fn eq(&self, o: &(u32, u32, u32, u32)) -> bool {
        self.major == o.0 && self.minor == o.1 && self.patch == o.2 && self.prerelease == o.3
    }
}

#[cfg(test)]
#[cfg(target_pointer_width = "64")] // All addresses are 64 bit and I'm currently too lazy to adjust it to work for both
mod tests {
    use super::*;
    use error_graph::ErrorList;
    use std::path::PathBuf;

    use crate::linux::{maps_reader::get_mappings_for, process_inspection};

    // All addresses below are 64 bit, and `MappingInfo::aggregate` drops any
    // mapping it can't fit into a `usize`.
    #[cfg(target_pointer_width = "64")]
    #[test]
    fn test_get_module_effective_name() {
        let mappings = get_mappings_for(
            "\
7f0b97b6f000-7f0b97b70000 r--p 00000000 00:3e 27136458                   /home/martin/Documents/mozilla/devel/mozilla-central/obj/widget/gtk/mozgtk/gtk3/libmozgtk.so
7f0b97b70000-7f0b97b71000 r-xp 00000000 00:3e 27136458                   /home/martin/Documents/mozilla/devel/mozilla-central/obj/widget/gtk/mozgtk/gtk3/libmozgtk.so
7f0b97b71000-7f0b97b73000 r--p 00000000 00:3e 27136458                   /home/martin/Documents/mozilla/devel/mozilla-central/obj/widget/gtk/mozgtk/gtk3/libmozgtk.so
7f0b97b73000-7f0b97b74000 rw-p 00001000 00:3e 27136458                   /home/martin/Documents/mozilla/devel/mozilla-central/obj/widget/gtk/mozgtk/gtk3/libmozgtk.so",
            0x7ffe091bf000,
        );
        assert_eq!(mappings.len(), 1);
        let process_inspector = process_inspection::local(0);
        let modules = resolve(
            from_mappings(process_inspector.as_ref(), &mappings),
            None,
            &mut ErrorList::default(),
        );

        // The path doesn't exist, so the SONAME read fails and we fall back to
        // the filesystem name -- which is the behaviour under test.
        let mut soft_errors = ErrorList::default();
        let (file_path, file_name, _version) = modules[0].effective_path_name_and_version(
            process_inspector.as_ref(),
            None,
            &mut soft_errors,
        );
        assert!(!soft_errors.is_empty());
        assert_eq!(file_name, "libmozgtk.so");
        assert_eq!(
            file_path,
            PathBuf::from(
                "/home/martin/Documents/mozilla/devel/mozilla-central/obj/widget/gtk/mozgtk/gtk3/libmozgtk.so"
            )
        );
    }

    #[test]
    fn test_elf_file_so_version() {
        #[rustfmt::skip]
        let test_cases = [
            ("/usr/lib/x86_64-linux-gnu/libstdc++.so.6.0.32", (6, 0, 32, 0)),
            ("/usr/lib/x86_64-linux-gnu/libcairo-gobject.so.2.11800.0", (2, 11800, 0, 0)),
            ("/usr/lib/x86_64-linux-gnu/libm.so.6", (6, 0, 0, 0)),
            ("/usr/lib/x86_64-linux-gnu/libpthread.so.0", (0, 0, 0, 0)),
            ("/usr/lib/x86_64-linux-gnu/libgmodule-2.0.so.0.7800.0", (0, 7800, 0, 0)),
            ("/usr/lib/x86_64-linux-gnu/libabsl_time_zone.so.20220623.0.0", (20220623, 0, 0, 0)),
            ("/usr/lib/x86_64-linux-gnu/libdbus-1.so.3.34.2rc5", (3, 34, 2, 5)),
            ("/usr/lib/x86_64-linux-gnu/libdbus-1.so.3.34.2rc", (3, 34, 2, 0)),
            ("/usr/lib/x86_64-linux-gnu/libdbus-1.so.3.34.rc5", (3, 34, 0, 5)),
            ("/usr/lib/x86_64-linux-gnu/libtoto.so.AAA", (0, 0, 0, 0)),
            ("/usr/lib/x86_64-linux-gnu/libsemver-1.so.1.2.alpha.1", (1, 2, 0, 1)),
            ("/usr/lib/x86_64-linux-gnu/libboop.so.1.2.3.4.5", (1, 2, 3, 4)),
            ("/usr/lib/x86_64-linux-gnu/libboop.so.1.2.3pre4.5", (1, 2, 3, 4)),
        ];

        assert!(SoVersion::parse(OsStr::new("/home/alex/bin/firefox/libmozsandbox.so")).is_none());

        for (path, expected) in test_cases {
            let actual = SoVersion::parse(OsStr::new(path)).unwrap();
            assert_eq!(actual, expected);
        }
    }
}

/// Derives the module list by walking the dynamic linker's debugger rendez-vous.
///
/// The debugger rendez-vous is reachable through a field in the main program's
/// headers, hence the need for `process_inspector`, `program_header_table_address`
/// and `program_header_count`, while `pid` is there in order to get a name for the
/// main program's module, which isn't necessarily given in the DT_DEBUG data (glibc).
pub fn from_debugger_rendezvous(
    process_inspector: &dyn ProcessInspector,
    pid: Pid,
    program_header_table_address: usize,
    program_header_count: usize,
    mut soft_errors: impl WriteErrorList<FromRendezvousError>,
) -> Result<Vec<ModuleCandidate>, FromRendezvousError> {
    let memory_reader = process_inspector.process_reader();

    let main_executable = MainExecutable::read(
        &memory_reader,
        program_header_table_address,
        program_header_count,
    )?;

    // Throughout the code stack we're assuming everything is PIE. Notably,
    // module_reader would require substantial changes to accomodate for
    // non-PIE executables reliably. Let's just error out rather than return
    // garbage.
    if main_executable.load_bias == 0 {
        return Err(FromRendezvousError::NonPieMainExecutable);
    }

    let (_, dynamic_section) = main_executable.dynamic_section(&memory_reader)?;
    let rdv_address = find_rendezvous_address(&dynamic_section)?;
    let rdebug = RDebug::from_memory(rdv_address, &memory_reader)?;

    read_link_map(
        process_inspector,
        &memory_reader,
        pid,
        &rdebug,
        main_executable.load_bias,
        &mut soft_errors,
    )
    .map_err(FromRendezvousError::IterateLinkMapFailed)
}

fn read_link_map(
    process_inspector: &dyn ProcessInspector,
    memory_reader: &ProcessReader<'_>,
    pid: Pid,
    rdebug: &RDebug,
    main_executable_load_bias: usize,
    mut soft_errors: impl WriteErrorList<FromRendezvousError>,
) -> Result<Vec<ModuleCandidate>, RendezvousError> {
    let page_size = page_size();

    // The first item is presumed to be the main executable
    // and gets special treatment.

    let links: Vec<LinkMap> = rdebug
        .map_iterator(memory_reader)
        .collect::<Result<_, _>>()?;
    let candidates = links
        .iter()
        .enumerate()
        .filter_map(|(idx, link)| {
            let main_executable = idx == 0;
            let load_bias = if main_executable {
                main_executable_load_bias
            } else {
                link.l_addr as usize
            };

            // The name is threaded back out of the fallible part so that a
            // module we ended up skipping can still be named in the soft error.
            let mut name = None;
            let candidate = link
                .name(memory_reader)
                .map_err(ModuleCandidateError::ReadNameFailed)
                .and_then(|read| {
                    name = if main_executable && read.is_empty() {
                        // Let's try asking /proc/pid/exe
                        main_executable_name(process_inspector, pid)
                    } else {
                        Some(read)
                    };
                    read_module(memory_reader, &name, load_bias, page_size)
                });

            // One unreadable object shouldn't cost us the rest of the list.
            match candidate {
                Err(source) => {
                    soft_errors.push(FromRendezvousError::SkippedModule {
                        name: name.unwrap_or_default(),
                        address: load_bias,
                        source,
                    });
                    None
                }
                Ok(candidate) => Some(candidate),
            }
        })
        .collect();
    Ok(candidates)
}

/// Reads a single module out of its program header table.
///
/// A module is one entry, spanning all of its `PT_LOAD` segments. Overlap with
/// other entries of the module list is resolved afterwards, once the whole list
/// is known.
fn read_module(
    memory_reader: &ProcessReader<'_>,
    name: &Option<OsString>,
    load_bias: usize,
    page_size: usize,
) -> Result<ModuleCandidate, ModuleCandidateError> {
    let module = ModuleReader::new(ProcessModuleMemoryReader::new(memory_reader, load_bias))
        .map_err(ModuleCandidateError::ReadModuleFailed)?;
    let program_headers = module
        .program_headers()
        .map_err(ModuleCandidateError::ReadModuleFailed)?;

    // `p_vaddr` is relative to the module's load bias.
    let mut segments: Vec<Segment> = program_headers
        .iter()
        .filter(|hdr| hdr.p_type == PT_LOAD)
        .map(|hdr| {
            let start = load_bias + usize::try_from(hdr.p_vaddr).unwrap();
            let end = start + usize::try_from(hdr.p_memsz).unwrap();
            // Round out to whole pages, since that's the granularity the kernel
            // actually mapped the segment at.
            Segment {
                start: align_down(start, page_size),
                end: align_up(end, page_size),
                file_offset: align_down(usize::try_from(hdr.p_offset).unwrap(), page_size),
                executable: hdr.p_flags & PF_X != 0,
            }
        })
        .collect();
    segments.sort_by_key(|segment| segment.start);

    let first = segments
        .first()
        .ok_or(ModuleCandidateError::NoLoadableSegment)?;

    // We span the entire segment range, regardless of any hole between them.
    // Thing will get fixed, clamped and disambiguated later in the process.
    let end_address = segments.iter().map(|segment| segment.end).max().unwrap();
    // We need to know where the actual code segments end for clamping.
    let code_end = segments
        .iter()
        .filter(|segment| segment.executable)
        .map(|segment| segment.end)
        .max()
        .unwrap_or(first.start);

    let base_address = base_address(&module, load_bias, first.start);

    Ok(ModuleCandidate {
        base_address,
        end_address,
        code_end,
        name: name.clone(),
        file_offset: first.file_offset,
        source: ModuleSource::Process,
    })
}

/// Get the base address of a given, that is the address against which all
/// addresses in a module are resolved.
fn base_address<MM: ReadModuleMemory>(
    module: &ModuleReader<MM>,
    load_bias: usize,
    lowest_segment_start: usize,
) -> usize {
    // It's usually the start of the lowest segment, except for shared libraries
    // that use Android packed relocations (according to the Breakpad sources)
    if lowest_segment_start != load_bias
        && module.header().e_type == ET_DYN
        && has_packed_relocations(module)
    {
        load_bias
    } else {
        lowest_segment_start
    }
}

/// Whether the object carries Android's packed relocation tags.
fn has_packed_relocations<MM: ReadModuleMemory>(module: &ModuleReader<MM>) -> bool {
    const DT_ANDROID_REL: u64 = DT_LOOS + 2;
    const DT_ANDROID_RELA: u64 = DT_LOOS + 4;

    let Ok(entries) = module.dynamic_entries() else {
        return false;
    };

    entries
        .iter()
        .any(|entry| entry.d_tag == DT_ANDROID_REL || entry.d_tag == DT_ANDROID_RELA)
}

/// One `PT_LOAD` segment, as the kernel would have mapped it.
#[derive(Debug)]
struct Segment {
    start: usize,
    end: usize,
    file_offset: usize,
    executable: bool,
}

fn main_executable_name(process_inspector: &dyn ProcessInspector, pid: Pid) -> Option<OsString> {
    process_inspector
        .read_link(format!("/proc/{pid}/exe").into())
        .map(PathBuf::into_os_string)
        .inspect_err(|e| {
            log::warn!("failed to read /proc/{pid}/exe for the main executable's name: {e}");
        })
        .ok()
}

fn page_size() -> usize {
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    assert!(
        page_size > 0,
        "somehow we weren't able to get the page size"
    );
    usize::try_from(page_size).unwrap()
}

fn align_down(val: usize, align: usize) -> usize {
    val / align * align
}

fn align_up(val: usize, align: usize) -> usize {
    let result = val / align * align;
    if !val.is_multiple_of(align) {
        result + align
    } else {
        result
    }
}
