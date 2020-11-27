use minidump_writer_linux::linux_ptrace_dumper;
use nix::sys::mman::{mmap, MapFlags, ProtFlags};
use nix::sys::signal::Signal;
use std::os::unix::io::AsRawFd;
use std::os::unix::process::ExitStatusExt;

mod common;
use common::*;

#[test]
fn test_setup() {
    spawn_child("setup", &[]);
}

#[test]
fn test_thread_list_from_child() {
    // Child spawns and looks in the parent (== this process) for its own thread-ID
    spawn_child("thread_list", &[]);
}

#[test]
fn test_thread_list_from_parent() {
    let num_of_threads = 5;
    let mut child = start_child_and_wait_for_threads(num_of_threads);
    let pid = child.id() as i32;
    let mut dumper =
        linux_ptrace_dumper::LinuxPtraceDumper::new(pid).expect("Couldn't init dumper");
    assert_eq!(dumper.threads.len(), num_of_threads);
    dumper.suspend_threads().expect("Could not suspend threads");

    // let mut matching_threads = 0;
    for (idx, curr_thread) in dumper.threads.iter().enumerate() {
        println!("curr_thread: {}", curr_thread);
        let info = dumper
            .get_thread_info_by_index(idx)
            .expect("Could not get thread info by index");
        let (_stack_ptr, stack_len) = dumper
            .get_stack_info(info.stack_pointer)
            .expect("Could not get stack_pointer");
        assert!(stack_len > 0);

        // TODO: I currently know of no way to write the thread_id into the registers using Rust,
        //       so this check is deactivated for now, because it always fails
        /*
        // In the helper program, we stored a pointer to the thread id in a
        // specific register. Check that we can recover its value.
        #[cfg(target_arch = "x86_64")]
        let process_tid_location = info.regs.rcx;
        #[cfg(target_arch = "x86")]
        let process_tid_location = info.regs.ecx;
        #[cfg(target_arch = "arm")]
        let process_tid_location = info.regs.uregs[3];
        #[cfg(target_arch = "aarch64")]
        let process_tid_location = info.regs.regs[3];
        #[cfg(target_arch = "mips")]
        let process_tid_location = info.mcontext.gregs[1];

        let thread_id_data = LinuxPtraceDumper::copy_from_process(
            *curr_thread,
            process_tid_location as *mut libc::c_void,
            4,
        )
        .expect("Could not copy from process");
        let found_thread_id = i32::from_ne_bytes(
            thread_id_data
                .as_slice()
                .try_into()
                .expect("couldn't parse i32 from read data"),
        );
        matching_threads += if *curr_thread == found_thread_id {
            1
        } else {
            0
        }; */
    }
    dumper.resume_threads().expect("Failed to resume threads");
    child.kill().expect("Failed to kill process");

    // Reap child
    let waitres = child.wait().expect("Failed to wait for child");
    let status = waitres.signal().expect("Child did not die due to signal");
    assert_eq!(waitres.code(), None);
    assert_eq!(status, Signal::SIGKILL as i32);

    // We clean up the child process before checking the final result
    // TODO: I currently know of no way to write the thread_id into the registers using Rust,
    //       so this check is deactivated for now, because it always fails
    // assert_eq!(matching_threads, num_of_threads);
}

// #[cfg(not(any(target_arch = "mips", target_arch = "arm-eabi"))]
#[cfg(not(target_arch = "mips"))]
#[test]
// Ensure that the linux-gate VDSO is included in the mapping list.
fn test_mappings_include_linux_gate() {
    spawn_child("mappings_include_linux_gate", &[]);
}

#[test]
fn test_linux_gate_mapping_id() {
    spawn_child("linux_gate_mapping_id", &[]);
}

#[test]
fn test_merged_mappings() {
    let page_size = nix::unistd::sysconf(nix::unistd::SysconfVar::PAGE_SIZE).unwrap();
    let page_size = page_size.unwrap() as usize;
    let map_size = 3 * page_size;

    let path: &'static str = std::env!("CARGO_BIN_EXE_test");
    let file = std::fs::File::open(path).unwrap();

    // mmap two segments out of the helper binary, one
    // enclosed in the other, but with different protections.
    let mapped_mem = unsafe {
        mmap(
            std::ptr::null_mut(),
            map_size,
            ProtFlags::PROT_READ,
            MapFlags::MAP_SHARED,
            file.as_raw_fd(),
            0,
        )
        .unwrap()
    };

    // Carve a page out of the first mapping with different permissions.
    let _inside_mapping = unsafe {
        mmap(
            (mapped_mem as usize + 2 * page_size) as *mut libc::c_void,
            page_size,
            ProtFlags::PROT_NONE,
            MapFlags::MAP_SHARED | MapFlags::MAP_FIXED,
            file.as_raw_fd(),
            // Map a different offset just to
            // better test real-world conditions.
            page_size as i64,
        )
    };

    spawn_child(
        "merged_mappings",
        &[
            path,
            &format!("{}", mapped_mem as usize),
            &format!("{}", map_size),
        ],
    );
}

#[test]
// Ensure that the linux-gate VDSO is included in the mapping list.
fn test_file_id() {
    spawn_child("file_id", &[]);
}

#[test]
fn test_find_mapping() {
    spawn_child(
        "find_mappings",
        &[
            &format!("{}", libc::printf as *const () as usize),
            &format!("{}", String::new as *const () as usize),
        ],
    );
}

#[test]
fn test_copy_from_process_self() {
    let stack_var: libc::c_long = 0x11223344;
    let heap_var: Box<libc::c_long> = Box::new(0x55667788);
    spawn_child(
        "copy_from_process",
        &[
            &format!("{}", &stack_var as *const libc::c_long as usize),
            &format!("{}", heap_var.as_ref() as *const libc::c_long as usize),
        ],
    );
}
