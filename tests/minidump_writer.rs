use minidump::*;
use minidump_common::format::MINIDUMP_STREAM_TYPE::*;
use minidump_writer_linux::maps_reader::{MappingEntry, MappingInfo, SystemMappingInfo};
use minidump_writer_linux::minidump_writer::write_minidump;
use nix::sys::signal::Signal;
use std::io::{BufRead, BufReader};
use std::os::unix::process::ExitStatusExt;
use std::str::FromStr;

mod common;
use common::*;

#[test]
fn test_write_dump() {
    let num_of_threads = 3;
    let mut child = start_child_and_wait_for_threads(num_of_threads);
    let pid = child.id() as i32;

    let tmpfile = tempfile::Builder::new()
        .prefix("write_dump")
        .tempfile()
        .unwrap();

    write_minidump(tmpfile.path().to_str().unwrap(), pid, pid, None)
        .expect("Could not write minidump");
    child.kill().expect("Failed to kill process");

    // Reap child
    let waitres = child.wait().expect("Failed to wait for child");
    let status = waitres.signal().expect("Child did not die due to signal");
    assert_eq!(waitres.code(), None);
    assert_eq!(status, Signal::SIGKILL as i32);

    let meta = std::fs::metadata(tmpfile.path()).expect("Couldn't get metadata for tempfile");
    assert!(meta.len() > 0);
}

#[test]
fn test_write_and_read_dump_from_parent() {
    let mut child = start_child_and_return("spawn_mmap_wait");
    let pid = child.id() as i32;

    let tmpfile = tempfile::Builder::new()
        .prefix("write_dump")
        .tempfile()
        .unwrap();

    let mut f = BufReader::new(child.stdout.as_mut().expect("Can't open stdout"));
    let mut buf = String::new();
    let _ = f
        .read_line(&mut buf)
        .expect("Couldn't read address provided by child");
    let mut output = buf.split_whitespace();
    let mmap_addr = usize::from_str(output.next().unwrap()).expect("unable to parse mmap_addr");
    let memory_size = usize::from_str(output.next().unwrap()).expect("unable to parse memory_size");
    // Add information about the mapped memory.
    let mapping = MappingInfo {
        start_address: mmap_addr,
        size: memory_size,
        offset: 0,
        executable: false,
        name: Some("a fake mapping".to_string()),
        system_mapping_info: SystemMappingInfo {
            start_address: mmap_addr,
            end_address: mmap_addr + memory_size,
        },
    };

    let identifier = vec![
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
        0xFF,
    ];
    let entry = MappingEntry {
        mapping,
        identifier,
    };
    write_minidump(
        tmpfile.path().to_str().unwrap(),
        pid,
        pid,
        Some(vec![entry]),
    )
    .expect("Couldn't write minidump");

    child.kill().expect("Failed to kill process");
    // Reap child
    let waitres = child.wait().expect("Failed to wait for child");
    let status = waitres.signal().expect("Child did not die due to signal");
    assert_eq!(waitres.code(), None);
    assert_eq!(status, Signal::SIGKILL as i32);

    let page_size = nix::unistd::sysconf(nix::unistd::SysconfVar::PAGE_SIZE).unwrap();
    let _page_size = page_size.unwrap() as usize;

    let dump = Minidump::read_path(tmpfile.path()).expect("Failed to read minidump");
    let module_list: MinidumpModuleList = dump
        .get_stream()
        .expect("Couldn't find stream MinidumpModuleList");
    let module = module_list
        .module_at_address(mmap_addr as u64)
        .expect("Couldn't find user mapping module");
    assert_eq!(module.base_address(), mmap_addr as u64);
    assert_eq!(module.size(), memory_size as u64);
    assert_eq!(module.code_file(), "a fake mapping");
    assert_eq!(
        module.debug_identifier(),
        Some("33221100554477668899AABBCCDDEEFF0".into())
    );

    let _: MinidumpException = dump.get_stream().expect("Couldn't find MinidumpException");
    let _: MinidumpThreadList = dump.get_stream().expect("Couldn't find MinidumpThreadList");
    let _: MinidumpMemoryList = dump.get_stream().expect("Couldn't find MinidumpMemoryList");
    let _: MinidumpException = dump.get_stream().expect("Couldn't find MinidumpException");
    let _: MinidumpSystemInfo = dump.get_stream().expect("Couldn't find MinidumpSystemInfo");
    let _ = dump
        .get_raw_stream(LinuxCpuInfo)
        .expect("Couldn't find LinuxCpuInfo");
    let _ = dump
        .get_raw_stream(LinuxProcStatus)
        .expect("Couldn't find LinuxProcStatus");
    let _ = dump
        .get_raw_stream(LinuxCmdLine)
        .expect("Couldn't find LinuxCmdLine");
    let _ = dump
        .get_raw_stream(LinuxEnviron)
        .expect("Couldn't find LinuxEnviron");
    let _ = dump
        .get_raw_stream(LinuxAuxv)
        .expect("Couldn't find LinuxAuxv");
    let _ = dump
        .get_raw_stream(LinuxMaps)
        .expect("Couldn't find LinuxMaps");
    let _ = dump
        .get_raw_stream(LinuxDsoDebug)
        .expect("Couldn't find LinuxDsoDebug");
}
