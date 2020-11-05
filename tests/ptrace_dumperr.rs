use libc;
use minidump_writer_linux::{linux_ptrace_dumper, Result};
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{fork, getppid, ForkResult};

macro_rules! spawn_child {
    ($x:expr) => {
        let mut child = Command::new("cargo")
            .arg("run")
            .arg("test")
            .arg("--")
            .arg($x)
            .spawn()
            .expect("failed to execute child");

        let ecode = child.wait().expect("failed to wait on child");
        assert_eq!(ecode.code().expect("No return value"), 0);
    };
}
use std::process::Command;

#[test]
fn test_setup() {
    spawn_child!("setup");
}

#[test]
fn test_thread_list() {
    spawn_child!("thread_list");
}
