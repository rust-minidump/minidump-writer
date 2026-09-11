// Pointless to test fallback if one of the two sources is *always* broken,
// as is the rendezvous path on statically linked binaries.
#![cfg(all(
    any(target_os = "linux", target_os = "android"),
    not(target_feature = "crt-static")
))]

//! Lives in its own test binary because failspots are process-global: enabling
//! one here would otherwise leak into the tests running concurrently in
//! `linux_module_list.rs`.

use {
    common::*,
    minidump::*,
    minidump_writer::{
        FailSpotName,
        minidump_writer::{MinidumpWriterConfig, ModuleListSource},
    },
};

mod common;

#[test]
fn module_list_procmaps_fallback_to_rendezvous() {
    let mut failspot_client = FailSpotName::testing_client();
    failspot_client.set_enabled(FailSpotName::EnumerateMappingsFromProc, true);

    let mut child = start_child_and_wait_for_threads(1);
    let pid = child.id() as i32;

    let mut tmpfile = tempfile::Builder::new().tempfile().unwrap();

    let mut writer = MinidumpWriterConfig::new(pid, pid);
    writer.set_module_list_source(ModuleListSource::ProcMaps);
    writer.write(&mut tmpfile).unwrap();

    child.kill().expect("Failed to kill process");
    child.wait().expect("Failed to wait on killed process");

    let dump = Minidump::read_path(tmpfile.path()).expect("failed to read minidump");
    let modules: MinidumpModuleList = dump.get_stream().expect("no module list");
    let names = modules
        .iter()
        .map(|module| module.name.clone())
        .collect::<Vec<_>>();

    assert!(!names.is_empty(), "empty module list");
    assert!(names.iter().any(|name| name.contains("libc")));
    assert_minidump_contains_soft_error(&dump, "AggregateMappingsFailed");
    assert_minidump_contains_soft_error(&dump, "NoModulesInProcessMappings");
}
