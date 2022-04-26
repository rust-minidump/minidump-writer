#![cfg(target_os = "macos")]

mod common;
use common::start_child_and_return;

use minidump::{
    CrashReason, Minidump, MinidumpBreakpadInfo, MinidumpMemoryList, MinidumpMiscInfo,
    MinidumpModuleList, MinidumpSystemInfo, MinidumpThreadList,
};
use minidump_writer::minidump_writer::MinidumpWriter;

fn get_crash_reason<'a, T: std::ops::Deref<Target = [u8]> + 'a>(
    md: &Minidump<'a, T>,
) -> CrashReason {
    let exc: minidump::MinidumpException<'_> =
        md.get_stream().expect("unable to find exception stream");

    exc.get_crash_reason(
        minidump::system_info::Os::MacOs,
        if cfg!(target_arch = "x86_64") {
            minidump::system_info::Cpu::X86_64
        } else if cfg!(target_arch = "aarch64") {
            minidump::system_info::Cpu::Arm64
        } else {
            unimplemented!()
        },
    )
}

struct Captured<'md> {
    task: u32,
    thread: u32,
    minidump: Minidump<'md, memmap2::Mmap>,
}

fn capture_minidump(name: &str) -> Captured<'_> {
    use std::io::BufRead;

    let mut child = start_child_and_return("");

    let (task, thread) = {
        let mut f = std::io::BufReader::new(child.stdout.as_mut().expect("Can't open stdout"));
        let mut buf = String::new();
        f.read_line(&mut buf).expect("failed to read stdout");
        assert!(!buf.is_empty());

        let mut biter = buf.trim().split(' ');

        let task: u32 = biter.next().unwrap().parse().unwrap();
        let thread: u32 = biter.next().unwrap().parse().unwrap();

        (task, thread)
    };

    let pid = dbg!(std::process::id());
    assert!(task != unsafe { dbg!(mach2::traps::mach_task_self()) });

    let crash_context = crash_context::CrashContext {
        task,
        thread,
        handler_thread: mach2::port::MACH_PORT_NULL,
        exception: Some(crash_context::ExceptionInfo {
            kind: mach2::exception_types::EXC_BREAKPOINT as i32,
            code: 100,
            subcode: None,
        }),
    };

    let mut tmpfile = tempfile::Builder::new().prefix(name).tempfile().unwrap();

    let mut dumper = MinidumpWriter::new(crash_context);

    dumper
        .dump(tmpfile.as_file_mut())
        .expect("failed to write minidump");

    child.kill().expect("failed to kill child");

    let minidump = Minidump::read_path(tmpfile.path()).expect("failed to read minidump");

    Captured {
        task,
        thread,
        minidump,
    }
}

#[test]
fn dump_external_process() {
    let approximate_proc_start_time = std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let md = capture_minidump("dump_external_process").minidump;

    let crash_reason = get_crash_reason(&md);

    assert!(matches!(
        crash_reason,
        CrashReason::MacGeneral(
            minidump_common::errors::ExceptionCodeMac::EXC_BREAKPOINT,
            100
        )
    ));

    let _: MinidumpModuleList = md.get_stream().expect("Couldn't find MinidumpModuleList");
    let _: MinidumpThreadList = md.get_stream().expect("Couldn't find MinidumpThreadList");
    let _: MinidumpMemoryList = md.get_stream().expect("Couldn't find MinidumpMemoryList");
    let _: MinidumpSystemInfo = md.get_stream().expect("Couldn't find MinidumpSystemInfo");
    let _: MinidumpBreakpadInfo = md.get_stream().expect("Couldn't find MinidumpBreakpadInfo");

    let misc_info: MinidumpMiscInfo = md.get_stream().expect("Couldn't find MinidumpMiscInfo");

    if let minidump::RawMiscInfo::MiscInfo2(mi) = &misc_info.raw {
        // Unfortunately the minidump format only has 32-bit precision for the
        // process start time
        let process_create_time = mi.process_create_time as u64;

        assert!(
            process_create_time >= approximate_proc_start_time
                && process_create_time <= approximate_proc_start_time + 2
        );

        // I've tried busy looping to spend CPU time to get this up, but
        // MACH_TASK_BASIC_INFO which should give terminated thread times only ever
        // reports 0, and TASK_THREAD_TIMES_INFO which should show active thread
        // times I've only been able to get upt to a few thousand microseconds
        // even when busy looping for well over a second, and those get truncated
        // to whole seconds. And it seems that crashpad doesn't have tests around
        // this, though that's hard to say given how tedious it is finding stuff
        // in that bloated codebase
        // assert!(mi.process_user_time > 0);
        // assert!(mi.process_kernel_time > 0);

        // These aren't currently available on aarch64, or if they are, they
        // are not via the same sysctlbyname mechanism. Would be nice if Apple
        // documented...anything
        if cfg!(target_arch = "x86_64") {
            assert!(mi.processor_max_mhz > 0);
            assert!(mi.processor_current_mhz > 0);
        }
    } else {
        panic!("unexpected misc info type {:?}", misc_info);
    }
}

/// Validates we can actually walk the stack for each thread in the minidump,
/// this is using minidump-processor, which (currently) depends on breakpad
/// symbols, however https://github.com/mozilla/dump_syms is not available as
/// a library https://github.com/mozilla/dump_syms/issues/253, so we just require
/// that it already be installed, hence the ignore
#[test]
#[ignore = "ignored, requires dump_syms installed"]
fn stackwalks() {
    println!("generating minidump...");
    let md = capture_minidump("stackwalks");

    // Generate the breakpad symbols
    println!("generating symbols...");
    let mut cmd = std::process::Command::new("dump_syms");
    cmd.args(["-o", "mac_stackwalks.sym", "target/debug/test"]);
    assert!(cmd.status().unwrap().success());

    let provider =
        minidump_processor::Symbolizer::new(minidump_processor::simple_symbol_supplier(vec![
            ".".into()
        ]));

    let state = futures::executor::block_on(async {
        minidump_processor::process_minidump(&md.minidump, &provider).await
    })
    .unwrap();

    //state.print(&mut std::io::stdout()).map_err(|_| ()).unwrap();

    // We expect 2 threads, one of which is fake crashing thread
    let fake_crash_thread = state
        .threads
        .iter()
        .find(|cs| cs.thread_id == md.thread)
        .expect("failed to find crash thread");

    // The thread _should_ have a name
    assert_eq!(
        fake_crash_thread.thread_name.as_deref(),
        Some("test-thread")
    );

    assert!(
        fake_crash_thread
            .frames
            .iter()
            .any(|sf| { sf.function_name.as_deref() == Some("wait_until_killed") }),
        "unable to locate expected function"
    );
}
