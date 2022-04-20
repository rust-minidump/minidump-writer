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

#[test]
fn dump_external_process() {
    use std::io::BufRead;

    let approximate_proc_start_time = std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
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

    let mut tmpfile = tempfile::Builder::new()
        .prefix("mac_external_process")
        .tempfile()
        .unwrap();

    let mut dumper = MinidumpWriter::new(crash_context);

    dumper
        .dump(tmpfile.as_file_mut())
        .expect("failed to write minidump");

    child.kill().expect("failed to kill child");

    let md = Minidump::read_path(tmpfile.path()).expect("failed to read minidump");

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
