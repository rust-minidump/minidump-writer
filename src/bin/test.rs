// This binary shouldn't be under /src, but under /tests, but that is
// currently not possible (https://github.com/rust-lang/cargo/issues/4356)

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

fn spawn_and_wait(num: usize) -> Result<()> {
    // One less than the requested amount, as the main thread counts as well
    for _ in 1..num {
        std::thread::spawn(|| {
            println!("1");
            loop {
                std::thread::park();
            }
        });
    }
    println!("1");
    loop {
        std::thread::park();
    }
}

fn main() -> Result<()> {
    let args: Vec<_> = env::args().skip(1).collect();
    match args.len() {
        1 => match args[0].as_ref() {
            "setup" => test_setup(),
            "thread_list" => test_thread_list(),
            _ => Err("Len 1: Unknown test option".into()),
        },
        2 => {
            if args[0] == "spawn_and_wait" {
                let num_of_threads: usize = args[1].parse().unwrap();
                spawn_and_wait(num_of_threads)
            } else {
                Err(format!("Len 2: Unknown test option: {}", args[0]).into())
            }
        }
        _ => Err("Unknown test option".into()),
    }
}
