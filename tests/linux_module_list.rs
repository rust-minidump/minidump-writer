#![cfg(any(target_os = "linux", target_os = "android"))]

use {
    common::*,
    minidump::*,
    minidump_writer::minidump_writer::{MinidumpWriterConfig, ModuleListSource},
};

mod common;

/// The module sources this target can actually exercise.
const AVAILABLE_SOURCES: &[ModuleListSource] = &[
    ModuleListSource::ProcMaps,
    #[cfg(not(target_feature = "crt-static"))]
    ModuleListSource::DebuggerRendezvous,
];

// Spawn a child, extract its modules using the given method, and return
// the module names in order.
fn module_names(source: ModuleListSource) -> Vec<String> {
    let modules = module_list(source);
    modules
        .iter()
        .map(|module| module.name.clone())
        .collect::<Vec<_>>()
}

fn source_specific_error_str(source: ModuleListSource) -> &'static str {
    match source {
        ModuleListSource::ProcMaps => "NoModulesInProcessMappings",
        ModuleListSource::DebuggerRendezvous => "ModuleListFromDebuggerRendezvousFailed",
    }
}
/// Dumps a freshly spawned child and returns its whole `ModuleListStream`, so a
/// test can look entries up by address rather than by name.
fn module_list(source: ModuleListSource) -> MinidumpModuleList {
    let mut child = start_child_and_wait_for_threads(1);
    let pid = child.id() as i32;

    let mut tmpfile = tempfile::Builder::new().tempfile().unwrap();

    let mut writer = MinidumpWriterConfig::new(pid, pid);
    writer.set_module_list_source(source);
    writer
        .write(&mut tmpfile)
        .expect("could not write minidump");

    child.kill().expect("Failed to kill process");
    child.wait().expect("Failed to wait on killed process");

    let dump = Minidump::read_path(tmpfile.path()).expect("failed to read minidump");

    // We don't want the fallback path!
    assert_minidump_lacks_soft_error(&dump, source_specific_error_str(source));

    dump.get_stream().expect("no module list")
}

/// We want the test exec first, and the libc *somewhere* — unless it's statically
/// linked, of course.
fn assert_module_list_is_sane(modules: &[String]) {
    assert!(!modules.is_empty(), "empty module list");
    assert!(
        modules[0].contains("test"),
        "first module should be the test helper executable, got {:?}",
        modules[0]
    );
    #[cfg(not(target_feature = "crt-static"))]
    assert!(
        modules.iter().any(|name| name.contains("libc")),
        "no libc in the module list: {modules:?}"
    );
}

#[cfg(not(target_feature = "crt-static"))]
#[test]
fn module_list_from_debugger_rendezvous() {
    let modules = module_names(ModuleListSource::DebuggerRendezvous);
    assert_module_list_is_sane(&modules);
}

#[test]
fn module_list_from_proc_maps() {
    let modules = module_names(ModuleListSource::ProcMaps);
    assert_module_list_is_sane(&modules);
}

/// Both sources should agree on which files are loaded.
#[cfg(not(target_feature = "crt-static"))]
#[test]
fn both_module_list_sources_agree_on_files() {
    use std::path::Path;

    // There are *some* variations...
    const LINKER_ALIASES: &[&str] = &["ld-android.so", "linker64", "linker"];

    let file_names = |modules: Vec<String>| {
        let mut names = modules
            .into_iter()
            .filter(|name| name.starts_with('/'))
            .map(|name| {
                Path::new(&name)
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect::<Vec<_>>();
        names.sort();
        names.dedup();
        names
    };

    let from_rendezvous = file_names(module_names(ModuleListSource::DebuggerRendezvous));
    let from_proc_maps = file_names(module_names(ModuleListSource::ProcMaps));

    for name in &from_proc_maps {
        let found = from_rendezvous.contains(name)
            || (LINKER_ALIASES.contains(&name.as_str())
                && from_rendezvous
                    .iter()
                    .any(|other| LINKER_ALIASES.contains(&other.as_str())));
        assert!(
            found,
            "{name} is in the /proc/<pid>/maps module list but not in the rendez-vous one\n\
             rendez-vous: {from_rendezvous:?}\n\
             proc maps:   {from_proc_maps:?}"
        );
    }
}

/// Each ELF object should appear exactly once. Only tested for
/// the rendezvous as it is a known issue of the procmaps method.
#[cfg(not(target_feature = "crt-static"))]
#[test]
fn module_list_has_no_duplicates() {
    let modules = module_names(ModuleListSource::DebuggerRendezvous);
    let mut sorted = modules.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(sorted.len(), modules.len());
}

#[test]
fn module_list_includes_the_vdso() {
    for &source in AVAILABLE_SOURCES {
        let modules = module_names(source);
        assert!(
            modules
                .iter()
                // vDSO has different names depending on the libc.
                .any(|name| name.contains("vdso") || name.contains("linux-gate")),
            "no vDSO in the {source:?} module list: {modules:?}"
        );
    }
}

#[test]
fn no_module_overlaps_another() {
    for &source in AVAILABLE_SOURCES {
        let modules = module_list(source);

        for module in modules.iter() {
            let found = modules.module_at_address(module.raw.base_of_image);
            assert_eq!(
                found.map(|found| found.raw.base_of_image),
                Some(module.raw.base_of_image),
                "`{}` at {:#x} is in the {source:?} module list but resolves to {:?}",
                module.name,
                module.raw.base_of_image,
                found.map(|found| &found.name),
            );
        }
    }
}
