use minidump_writer_linux::{linux_ptrace_dumper, Result};
use nix::unistd::getppid;
use std::env;

macro_rules! test {
    ($x:expr, $errmsg:expr) => {
        if $x {
            Ok(())
        } else {
            Err($errmsg)
        }
    };
}

fn test_setup() -> Result<()> {
    let ppid = getppid();
    linux_ptrace_dumper::LinuxPtraceDumper::new(ppid.as_raw())?;
    Ok(())
}

fn test_thread_list() -> Result<()> {
    let ppid = getppid();
    let dumper = linux_ptrace_dumper::LinuxPtraceDumper::new(ppid.as_raw())?;
    test!(dumper.threads.len() >= 1, "No threads")?;
    test!(
        dumper
            .threads
            .iter()
            .filter(|&x| x == &ppid.as_raw())
            .count()
            == 1,
        "Thread found multiple times"
    )?;
    Ok(())
}

fn main() -> Result<()> {
    match env::args().last().unwrap().as_str() {
        "setup" => test_setup(),
        "thread_list" => test_thread_list(),
        x => Err(format!("Unknown test option: {}", x).into()),
    }
}
