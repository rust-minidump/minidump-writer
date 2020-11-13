// This binary shouldn't be under /src, but under /tests, but that is
// currently not possible (https://github.com/rust-lang/cargo/issues/4356)
use goblin::elf::header;
use minidump_writer_linux::linux_ptrace_dumper::AT_SYSINFO_EHDR;
use minidump_writer_linux::{linux_ptrace_dumper, Result, LINUX_GATE_LIBRARY_NAME};
use nix::unistd::getppid;
use std::convert::TryInto;
use std::env;
use std::process::id;

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

fn test_file_id() -> Result<()> {
    let ppid = getppid().as_raw();
    let exe_link = format!("/proc/{}/exe", ppid);
    let exe_name = std::fs::read_link(&exe_link)?.into_os_string();
    let mut dumper = linux_ptrace_dumper::LinuxPtraceDumper::new(getppid().as_raw())?;
    let mut found_exe = None;
    for (idx, mapping) in dumper.mappings.iter().enumerate() {
        if mapping.name.as_ref().map(|x| x.into()).as_ref() == Some(&exe_name) {
            found_exe = Some(idx);
            break;
        }
    }
    let idx = found_exe.unwrap();
    dumper.elf_identifier_for_mapping_index(idx)?;
    Ok(())
}

fn test_merged_mappings() -> Result<()> {
    // Now check that LinuxPtraceDumper interpreted the mappings properly.
    let dumper = linux_ptrace_dumper::LinuxPtraceDumper::new(getppid().as_raw())?;
    let _mapping_count = 0;
    for map in dumper.mappings {
        println!(
            "{:?} => {:x} - {:x}",
            map.name.unwrap_or("[Not set]".to_string()),
            map.system_mapping_info.start_address,
            map.system_mapping_info.end_address
        );
    }
    test!(false, "blubb")?;
    Ok(())
    //    for (unsigned i = 0; i < dumper.mappings().size(); ++i) {
    //      const MappingInfo& mapping = *dumper.mappings()[i];
    //      if (strcmp(mapping.name, this->helper_path_.c_str()) == 0) {
    //        // This mapping should encompass the entire original mapped
    //        // range.
    //        EXPECT_EQ(reinterpret_cast<uintptr_t>(this->helper_.mapping()),
    //                  mapping.start_addr);
    //        EXPECT_EQ(this->helper_.size(), mapping.size);
    //        EXPECT_EQ(0U, mapping.offset);
    //        mapping_count++;
    //      }
    //    }
    //    EXPECT_EQ(1, mapping_count);
}

fn test_mappings_include_linux_gate() -> Result<()> {
    let dumper = linux_ptrace_dumper::LinuxPtraceDumper::new(getppid().as_raw())?;
    let linux_gate_loc = dumper.auxv[&AT_SYSINFO_EHDR];
    test!(linux_gate_loc != 0, "linux_gate_loc == 0")?;

    let mut found_linux_gate = false;
    for mapping in dumper.mappings {
        if mapping.name.as_deref() == Some(LINUX_GATE_LIBRARY_NAME) {
            found_linux_gate = true;
            test!(
                linux_gate_loc == mapping.start_address.try_into().unwrap(),
                "linux_gate_loc != start_address"
            )?;
            println!("linux_gate_loc: 0x{:x}", linux_gate_loc);
            let ll = mapping.start_address as *const u8;
            for idx in 0..header::SELFMAG {
                unsafe {
                    test!(
                        std::ptr::read(ll.offset(idx as isize)) == header::ELFMAG[idx],
                        format!(
                            "ll: {} != ELFMAG: {} at {}",
                            std::ptr::read(ll.offset(idx as isize)),
                            header::ELFMAG[idx],
                            idx
                        )
                    )?;
                }
            }
            break;
        }
    }
    test!(found_linux_gate == true, "found no linux_gate")?;
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
            "file_id" => test_file_id(),
            "setup" => test_setup(),
            "thread_list" => test_thread_list(),
            "mappings_include_linux_gate" => test_mappings_include_linux_gate(),
            "merged_mappings" => test_merged_mappings(),
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
