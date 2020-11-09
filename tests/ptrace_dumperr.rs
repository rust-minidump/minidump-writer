use libc;
use minidump_writer_linux::linux_ptrace_dumper;
use nix::sys::signal::Signal;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::process::ExitStatusExt;
use std::process::{Child, Command, Stdio}; // To have .signal() for ExitStatus

macro_rules! spawn_child {
    ($x:expr) => {
        let child = Command::new("cargo")
            .arg("run")
            .arg("--bin")
            .arg("test")
            .arg("--")
            .arg($x)
            .output()
            .expect("failed to execute child");

        println!("Child output:");
        std::io::stdout().write_all(&child.stdout).unwrap();
        std::io::stdout().write_all(&child.stderr).unwrap();
        assert_eq!(child.status.code().expect("No return value"), 0);
    };
}

#[test]
fn test_setup() {
    spawn_child!("setup");
}

#[test]
fn test_thread_list_from_child() {
    // Child spawns and looks in the parent (== this process) for its own thread-ID
    spawn_child!("thread_list");
}

fn start_child_and_wait_for_threads(num: usize) -> Child {
    let mut child = Command::new("cargo")
        .arg("run")
        .arg("--bin")
        .arg("test")
        .arg("--")
        .arg("spawn_and_wait")
        .arg(format!("{}", num))
        .stdout(Stdio::piped())
        .spawn()
        .expect("failed to execute child");

    {
        let mut f = BufReader::new(child.stdout.as_mut().expect("Can't open stdout"));
        let mut lines = 0;
        while lines < 5 {
            let mut buf = String::new();
            match f.read_line(&mut buf) {
                Ok(_) => {
                    if buf == "1\n" {
                        lines += 1;
                    }
                }
                Err(e) => {
                    panic!(e);
                }
            }
        }
    }
    child
}

#[test]
fn test_thread_list_from_parent() {
    let num_of_threads = 5;
    let mut child = start_child_and_wait_for_threads(num_of_threads);
    let pid = child.id() as i32;
    let dumper = linux_ptrace_dumper::LinuxPtraceDumper::new(pid).expect("Couldn't init dumper");
    assert_eq!(dumper.threads.len(), num_of_threads);
    dumper
        .suspend_thread(pid)
        .expect("Could not suspend threads");

    let mut matching_threads = 0;
    for (idx, curr_thread) in dumper.threads.iter().enumerate() {
        println!("curr_thread: {}", curr_thread);
        let info = dumper
            .get_thread_info_by_index(idx)
            .expect("Could not get thread info by index");
        // dumper.get_stack_info(info.stack_pointer);
        //     const void* stack;
        //     size_t stack_len;
        //     EXPECT_TRUE(dumper.GetStackInfo(&stack, &stack_len,
        //         one_thread.stack_pointer));

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

        println!("src = 0x{:x}", process_tid_location);
        let found_thread_id = dumper
            .copy_from_process(*curr_thread, process_tid_location as *mut libc::c_void, 1)
            .expect("Could not copy from process");
        matching_threads += if *curr_thread as i64 == found_thread_id[0] {
            1
        } else {
            0
        };
    }
    assert_eq!(matching_threads, num_of_threads);
    dumper.resume_thread(pid).expect("Failed to resume threads");
    child.kill().expect("Failed to kill process");

    // Reap child
    let waitres = child.wait().expect("Failed to wait for child");
    let status = waitres.signal().expect("Child did not die due to signal");
    assert_eq!(waitres.code(), None);
    assert_eq!(status, Signal::SIGKILL as i32);
}

// #[cfg(not(any(target_arch = "mips", target_arch = "arm-eabi"))]
#[cfg(not(target_arch = "mips"))]
#[test]
// Ensure that the linux-gate VDSO is included in the mapping list.
fn test_mappings_include_linux_gate() {
    spawn_child!("mappings_include_linux_gate");
}
