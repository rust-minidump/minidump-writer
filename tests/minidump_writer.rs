use minidump_writer_linux::minidump_writer::write_minidump;
use nix::sys::signal::Signal;
use std::os::unix::process::ExitStatusExt;

mod common;
use common::start_child_and_wait_for_threads;

#[test]
fn test_write_dump() {
    let num_of_threads = 3;
    let mut child = start_child_and_wait_for_threads(num_of_threads);
    let pid = child.id() as i32;

    let tmpfile = tempfile::Builder::new()
        .prefix("write_dump")
        .tempfile()
        .unwrap();

    write_minidump(tmpfile.path().to_str().unwrap(), pid, pid).expect("Could not write minidump");
    child.kill().expect("Failed to kill process");

    // Reap child
    let waitres = child.wait().expect("Failed to wait for child");
    let status = waitres.signal().expect("Child did not die due to signal");
    assert_eq!(waitres.code(), None);
    assert_eq!(status, Signal::SIGKILL as i32);

    let meta = std::fs::metadata(tmpfile.path()).expect("Couldn't get metadata for tempfile");
    assert!(meta.len() > 0);
}
