#![cfg(any(target_os = "linux", target_os = "android"))]

use common::*;
use minidump::Minidump;
use minidump_writer::{FailSpotName, minidump_writer::MinidumpWriterConfig};
use serde_json as json;

mod common;

#[test]
fn soft_error_stream() {
    let mut child = start_child_and_wait_for_threads(1);
    let pid = child.id() as i32;

    let mut tmpfile = tempfile::Builder::new()
        .prefix("soft_error_stream")
        .tempfile()
        .unwrap();

    let mut fail_client = FailSpotName::testing_client();
    fail_client.set_enabled(FailSpotName::StopProcess, true);

    // Write a minidump
    MinidumpWriterConfig::new(pid, pid)
        .write(&mut tmpfile)
        .expect("cound not write minidump");
    child.kill().expect("Failed to kill process");
    child.wait().expect("Failed to wait on killed process");

    // Ensure the minidump has a MozSoftErrors present
    let dump = Minidump::read_path(tmpfile.path()).expect("failed to read minidump");
    read_minidump_soft_errors_or_panic(&dump);
}

fn visit_json_terminals<V>(json: &json::Value, path: &mut Vec<String>, visit: &mut V)
where
    V: FnMut(&[String], &json::Value),
{
    if let Some(obj) = json.as_object() {
        for (key, value) in obj.iter() {
            path.push(key.clone());
            visit_json_terminals(value, path, visit);
            path.pop();
        }
        return;
    }
    if let Some(arr) = json.as_array() {
        for value in arr.iter() {
            visit_json_terminals(value, path, visit);
        }
        return;
    }
    visit(path, json);
}

#[test]
fn soft_error_stream_content() {
    let mut child = start_child_and_wait_for_threads(1);
    let pid = child.id() as i32;

    let mut tmpfile = tempfile::Builder::new()
        .prefix("soft_error_stream_content")
        .tempfile()
        .unwrap();

    let mut fail_client = FailSpotName::testing_client();
    for name in [
        FailSpotName::StopProcess,
        FailSpotName::FillMissingAuxvInfo,
        FailSpotName::ThreadName,
        FailSpotName::SuspendThreads,
        FailSpotName::CpuInfoFileOpen,
    ] {
        fail_client.set_enabled(name, true);
    }

    // Write a minidump
    MinidumpWriterConfig::new(pid, pid)
        .write(&mut tmpfile)
        .expect("cound not write minidump");
    child.kill().expect("Failed to kill process");
    child.wait().expect("Failed to wait on killed process");

    // Ensure the MozSoftErrors stream contains the expected errors
    let dump = Minidump::read_path(tmpfile.path()).expect("failed to read minidump");

    let actual_json = read_minidump_soft_errors_or_panic(&dump);

    let mut stop_process_error_found = false;
    let mut missing_auxv_error_found = false;
    let mut thread_name_error_found = false;
    let mut suspend_thread_error_found = false;
    let mut cpu_info_error_found = false;

    let mut path = Vec::new();

    visit_json_terminals(&actual_json, &mut path, &mut |path, value| {
        if value.as_i64() == Some(libc::EPERM.into())
            && path.contains(&"StopProcessFailed".to_string())
        {
            stop_process_error_found = true;
        }
        if value.as_str() == Some("InvalidFormat")
            && path.contains(&"FillMissingAuxvInfoErrors".to_string())
        {
            missing_auxv_error_found = true;
        }
        if path.contains(&"ReadThreadNameFailed".to_string()) {
            thread_name_error_found = true;
        }
        if value.as_i64() == Some(libc::EPERM.into())
            && path.contains(&"SuspendThreadsErrors".to_string())
        {
            suspend_thread_error_found = true;
        }
        if value.as_i64() == Some(libc::EPERM.into())
            && path.contains(&"WriteCpuInformationFailed".to_string())
        {
            cpu_info_error_found = true;
        }
    });

    assert!(stop_process_error_found);
    assert!(missing_auxv_error_found);
    assert!(thread_name_error_found);
    assert!(suspend_thread_error_found);
    assert!(cpu_info_error_found);
}
