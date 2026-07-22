#![cfg(any(target_os = "linux", target_os = "android"))]

use {
    common::*,
    minidump::*,
    minidump_writer::{FailSpotName, minidump_writer::MinidumpWriterConfig},
};

mod common;

#[test]
fn memory_info_list_stream() {
    let mut failspot_client = FailSpotName::testing_client();

    // First enumerate mappings the usual way, via /proc/<pid>/maps.
    failspot_client.set_enabled(FailSpotName::EnumerateMappingsFromProc, false);
    memory_info_list_stream_inner();

    // Then force the /proc/<pid>/maps path to fail so that mappings are
    // reconstructed from the debugger rendez-vous instead.
    failspot_client.set_enabled(FailSpotName::EnumerateMappingsFromProc, true);
    memory_info_list_stream_inner();
}

fn memory_info_list_stream_inner() {
    let mut child = start_child_and_wait_for_threads(1);
    let pid = child.id() as i32;

    let mut tmpfile = tempfile::Builder::new()
        .prefix("memory_info_list_stream")
        .tempfile()
        .unwrap();

    // Write a minidump
    MinidumpWriterConfig::new(pid, pid)
        .write(&mut tmpfile)
        .expect("cound not write minidump");
    child.kill().expect("Failed to kill process");
    child.wait().expect("Failed to wait on killed process");

    // Ensure the minidump has a MemoryInfoListStream present and has at least one entry.
    let dump = Minidump::read_path(tmpfile.path()).expect("failed to read minidump");
    let list: MinidumpMemoryInfoList = dump.get_stream().expect("no memory info list");
    assert!(list.iter().count() > 1);
}
