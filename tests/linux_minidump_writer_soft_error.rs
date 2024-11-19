#![cfg(any(target_os = "linux", target_os = "android"))]
#![cfg(feature = "fail-enabled")]

use {
    common::*,
    minidump::Minidump,
    minidump_writer::{
        fail_enabled::{self, FailName},
        minidump_writer::MinidumpWriter,
    },
    serde_json::{json, Value as JsonValue},
};

mod common;

#[test]
fn soft_error_stream() {
    let mut child = start_child_and_wait_for_threads(1);
    let pid = child.id() as i32;

    let mut tmpfile = tempfile::Builder::new()
        .prefix("soft_error_stream")
        .tempfile()
        .unwrap();

    let fail_config = fail_enabled::Config::get();
    let fail_client = fail_config.client();
    fail_client.set_fail_enabled(FailName::StopProcess, true);

    // Write a minidump
    MinidumpWriter::new(pid, pid)
        .dump(&mut tmpfile)
        .expect("cound not write minidump");
    child.kill().expect("Failed to kill process");

    // Ensure the minidump has a MemoryInfoListStream present and has at least one entry.
    let dump = Minidump::read_path(tmpfile.path()).expect("failed to read minidump");
    dump.get_raw_stream(minidump_common::format::MINIDUMP_STREAM_TYPE::MozSoftErrors.into())
        .expect("missing soft error stream");
}

#[test]
fn soft_error_stream_content() {
    let expected_json = json!([
        {"InitErrors": [
            {"StopProcessFailed": {"Stop": "EPERM"}},
            {"FillMissingAuxvInfoErrors": ["InvalidFormat"]},
            {"EnumerateThreadsErrors": [
                {"ReadThreadNameFailed": "\
                    Custom {\n    \
                        kind: Other,\n    \
                        error: \"testing requested failure reading thread name\",\n\
                    }"
                }
            ]}
        ]},
        {"SuspendThreadsErrors": [{"PtraceAttachError": [1234, "EPERM"]}]},
        {"WriteSystemInfoErrors": [
            {"WriteCpuInformationFailed": {"IOError": "\
                Custom {\n    \
                    kind: Other,\n    \
                    error: \"test requested cpuinfo file failure\",\n\
                }"
            }}
        ]}
    ]);

    let mut child = start_child_and_wait_for_threads(1);
    let pid = child.id() as i32;

    let mut tmpfile = tempfile::Builder::new()
        .prefix("soft_error_stream_content")
        .tempfile()
        .unwrap();

    let fail_config = fail_enabled::Config::get();
    let fail_client = fail_config.client();
    for name in [
        FailName::StopProcess,
        FailName::FillMissingAuxvInfo,
        FailName::ThreadName,
        FailName::SuspendThreads,
        FailName::CpuInfoFileOpen,
    ] {
        fail_client.set_fail_enabled(name, true);
    }

    // Write a minidump
    MinidumpWriter::new(pid, pid)
        .dump(&mut tmpfile)
        .expect("cound not write minidump");
    child.kill().expect("Failed to kill process");

    // Ensure the minidump has a MemoryInfoListStream present and has at least one entry.
    let dump = Minidump::read_path(tmpfile.path()).expect("failed to read minidump");
    let contents = std::str::from_utf8(
        dump.get_raw_stream(minidump_common::format::MINIDUMP_STREAM_TYPE::MozSoftErrors.into())
            .expect("missing soft error stream"),
    )
    .expect("expected utf-8 stream");

    let actual_json: JsonValue = serde_json::from_str(contents).expect("expected json");

    if actual_json != expected_json {
        panic!(
            "\
            JSON mismatch:\n\
            =====Expected=====\n\
            \n\
            {expected_json:#}\n\
            \n\
            =====Actual=====\n\
            \n\
            {actual_json:#}\n\
            \n\
        "
        );
    }
}
