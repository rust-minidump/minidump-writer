#![cfg(all(target_os = "windows", target_arch = "x86_64"))]

use minidump::{CrashReason, Minidump, MinidumpMemoryList, MinidumpSystemInfo, MinidumpThreadList};
use minidump_writer::minidump_writer::MinidumpWriter;
use std::mem;
use windows_sys::Win32::{
    Foundation::{EXCEPTION_ACCESS_VIOLATION, STATUS_INVALID_PARAMETER},
    System::{
        Diagnostics::Debug::{RtlCaptureContext, EXCEPTION_POINTERS, EXCEPTION_RECORD},
        Threading::GetCurrentThreadId,
    },
};
mod common;
use common::start_child_and_return;

fn get_crash_reason<'a, T: std::ops::Deref<Target = [u8]> + 'a>(
    md: &Minidump<'a, T>,
) -> CrashReason {
    let exc: minidump::MinidumpException<'_> =
        md.get_stream().expect("unable to find exception stream");

    exc.get_crash_reason(
        minidump::system_info::Os::Windows,
        minidump::system_info::Cpu::X86_64,
    )
}

/// Ensures that we can write minidumps for the current process, even if this is
/// not necessarily the primary intended use case of out-of-process dumping
#[test]
fn dump_current_process() {
    let mut tmpfile = tempfile::Builder::new()
        .prefix("windows_current_process")
        .tempfile()
        .unwrap();

    unsafe {
        let mut exception_record: EXCEPTION_RECORD = mem::zeroed();
        let mut exception_context = mem::MaybeUninit::uninit();

        RtlCaptureContext(exception_context.as_mut_ptr());

        let mut exception_context = exception_context.assume_init();

        let exception_ptrs = EXCEPTION_POINTERS {
            ExceptionRecord: &mut exception_record,
            ContextRecord: &mut exception_context,
        };

        exception_record.ExceptionCode = STATUS_INVALID_PARAMETER;

        let crash_context = crash_context::CrashContext {
            exception_pointers: &exception_ptrs,
            thread_id: GetCurrentThreadId(),
            exception_code: STATUS_INVALID_PARAMETER,
        };

        let dumper = MinidumpWriter::current_process(crash_context)
            .expect("failed to create MinidumpWriter");

        dumper
            .dump(tmpfile.as_file_mut())
            .expect("failed to write minidump");
    }

    let md = Minidump::read_path(tmpfile.path()).expect("failed to read minidump");

    let _: MinidumpThreadList = md.get_stream().expect("Couldn't find MinidumpThreadList");
    let _: MinidumpMemoryList = md.get_stream().expect("Couldn't find MinidumpMemoryList");
    let _: MinidumpSystemInfo = md.get_stream().expect("Couldn't find MinidumpSystemInfo");

    let crash_reason = get_crash_reason(&md);

    assert_eq!(
        crash_reason,
        CrashReason::from_windows_error(STATUS_INVALID_PARAMETER as u32)
    );
}

/// Ensures that we can write minidumps for an external process. Unfortunately
/// this requires us to know the actual pointer in the client process for the
/// exception, as the `MiniDumpWriteDump` syscall directly reads points from
/// the process memory, so we communicate that back from the client process
/// via stdout
#[test]
fn dump_external_process() {
    use std::io::BufRead;

    let mut child = start_child_and_return(&format!("{:x}", EXCEPTION_ACCESS_VIOLATION));

    let mut f = std::io::BufReader::new(child.stdout.as_mut().expect("Can't open stdout"));
    let mut buf = String::new();
    f.read_line(&mut buf).expect("failed to read stdout");

    let mut biter = buf.split(' ');

    let exception_pointers: usize = biter.next().unwrap().parse().unwrap();
    let thread_id: u32 = biter.next().unwrap().parse().unwrap();
    let exception_code = u32::from_str_radix(biter.next().unwrap(), 16).unwrap() as i32;

    assert_eq!(exception_code, EXCEPTION_ACCESS_VIOLATION);

    let crash_context = crash_context::CrashContext {
        exception_pointers: exception_pointers as _,
        thread_id,
        exception_code,
    };

    let mut tmpfile = tempfile::Builder::new()
        .prefix("windows_external_process")
        .tempfile()
        .unwrap();

    let dumper = MinidumpWriter::external_process(crash_context, child.id())
        .expect("failed to create MinidumpWriter");

    dumper
        .dump(tmpfile.as_file_mut())
        .expect("failed to write minidump");

    child.kill().expect("failed to kill child");

    let md = Minidump::read_path(tmpfile.path()).expect("failed to read minidump");

    let _: MinidumpThreadList = md.get_stream().expect("Couldn't find MinidumpThreadList");
    let _: MinidumpMemoryList = md.get_stream().expect("Couldn't find MinidumpMemoryList");
    let _: MinidumpSystemInfo = md.get_stream().expect("Couldn't find MinidumpSystemInfo");

    let crash_reason = get_crash_reason(&md);

    assert_eq!(
        crash_reason,
        CrashReason::from_windows_error(EXCEPTION_ACCESS_VIOLATION as u32)
    );
}
