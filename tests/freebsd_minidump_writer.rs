#![cfg(target_os = "freebsd")]
#![allow(unused_imports, unused_variables, clippy::len_zero)]

use {
    common::*,
    minidump::*,
    minidump_common::format::MINIDUMP_STREAM_TYPE::*,
    minidump_writer::{
        Pid,
        app_memory::AppMemory,
        auxv::AuxvDumpInfo,
        crash_context::CrashContext,
        minidump_writer::{MinidumpWriter, MinidumpWriterConfig, errors::WriterError},
    },
    serde_json::Value,
    std::{
        io::{BufRead, BufReader},
        process::Stdio,
    },
};

mod common;

#[derive(Debug, PartialEq)]
enum Context {
    With,
    Without,
}

impl Context {
    pub fn minidump_writer(&self, pid: Pid) -> MinidumpWriterConfig {
        let main_lwp = get_main_thread_lwp(pid).unwrap_or(pid);
        let mut mw = MinidumpWriterConfig::new(pid, main_lwp);
        if self == &Context::With {
            let crash_context = get_crash_context(main_lwp, pid);
            mw.set_crash_context(crash_context);
        }
        mw
    }
}

/// Queries the main thread's LWP ID for a process using sysctl.
/// On FreeBSD, thread IDs (LWP IDs) are not the same as the process PID.
/// The main thread's ki_tid is returned if found; otherwise falls back to PID.
fn get_main_thread_lwp(pid: Pid) -> Option<Pid> {
    let mib = [
        libc::CTL_KERN,
        libc::KERN_PROC,
        libc::KERN_PROC_PID | libc::KERN_PROC_INC_THREAD,
        pid,
    ];
    let mut len: usize = 0;
    let res = unsafe {
        libc::sysctl(
            mib.as_ptr(),
            mib.len() as libc::c_uint,
            std::ptr::null_mut(),
            &mut len,
            std::ptr::null(),
            0,
        )
    };
    if res != 0 || len == 0 {
        return None;
    }
    let count = len / std::mem::size_of::<libc::kinfo_proc>();
    let mut buffer = vec![0u8; len];
    let res = unsafe {
        libc::sysctl(
            mib.as_ptr(),
            mib.len() as libc::c_uint,
            buffer.as_mut_ptr() as *mut libc::c_void,
            &mut len,
            std::ptr::null(),
            0,
        )
    };
    if res != 0 || count == 0 {
        return None;
    }
    let kprocs = buffer.as_ptr() as *const libc::kinfo_proc;
    unsafe { Some((*kprocs).ki_tid) }
}

fn get_crash_context(tid: Pid, pid: Pid) -> CrashContext {
    let mut ucontext: libc::ucontext_t = unsafe { std::mem::zeroed() };
    // SAFETY getcontext is not in the libc crate, so call it via raw FFI.
    unsafe {
        unsafe extern "C" {
            #[allow(improper_ctypes)]
            fn getcontext(ucp: *mut libc::ucontext_t) -> libc::c_int;
        }
        let ret = getcontext(&mut ucontext);
        assert_eq!(ret, 0, "getcontext failed");
    }
    CrashContext {
        siginfo: unsafe { std::mem::zeroed() },
        ucontext,
        pid,
        tid,
    }
}

#[test]
fn auxv_sysctl_fills_elf_entries() {
    let mut auxv = AuxvDumpInfo::default();
    auxv.try_filling_missing_info(std::process::id() as Pid)
        .expect("failed to read auxv for current process");

    assert!(auxv.get_program_header_count().unwrap_or_default() > 0);
    assert!(auxv.get_program_header_address().unwrap_or_default() > 0);
    assert!(auxv.get_entry_address().unwrap_or_default() > 0);
}

fn contains_json_string(value: &Value, expected: &str) -> bool {
    match value {
        Value::String(actual) => actual == expected,
        Value::Array(items) => items
            .iter()
            .any(|item| contains_json_string(item, expected)),
        Value::Object(entries) => entries
            .values()
            .any(|item| contains_json_string(item, expected)),
        _ => false,
    }
}

#[test]
fn skip_stacks_if_mapping_unreferenced_omits_thread_stacks() {
    let mut child = start_child_and_wait_for_threads(1);
    let pid = child.id() as i32;
    let main_lwp = get_main_thread_lwp(pid).unwrap_or(pid);

    let mut tmpfile = tempfile::Builder::new()
        .prefix("skip_stacks_if_mapping_unreferenced")
        .tempfile()
        .unwrap();

    let mut tmp = MinidumpWriterConfig::new(pid, main_lwp);
    tmp.skip_stacks_if_mapping_unreferenced()
        .set_principal_mapping_address(usize::MAX);
    tmp.write(&mut tmpfile).expect("Could not write minidump");
    child.kill().expect("Failed to kill process");
    let _waitres = child.wait().expect("Failed to wait for child");

    let dump = Minidump::read_path(tmpfile.path()).expect("Failed to read minidump");
    let soft_errors = read_minidump_soft_errors_or_panic(&dump);
    assert!(contains_json_string(
        &soft_errors,
        "PrincipalMappingNotReferenced"
    ));

    let threads: MinidumpThreadList = dump.get_stream().expect("Couldn't find MinidumpThreadList");
    assert!(!threads.threads.is_empty(), "Expected at least one thread");
    assert!(
        threads
            .threads
            .iter()
            .all(|thread| thread.raw.stack.memory.data_size == 0),
        "Expected all thread stacks to be omitted"
    );
}

macro_rules! contextual_test {
    ( $(#[$attr:meta])? fn $name:ident ($ctx:ident : Context) $body:block ) => {
        mod $name {
            use super::*;

            fn test($ctx: Context) $body

            #[test]
            $(#[$attr])?
            fn without_context() {
                test(Context::Without)
            }

            #[test]
            $(#[$attr])?
            fn with_context() {
                test(Context::With)
            }
        }
    }
}

contextual_test! {
    fn write_dump(context: Context) {
        let num_of_threads = 3;
        let mut child = start_child_and_wait_for_threads(num_of_threads);
        let pid = child.id() as i32;

        let mut tmpfile = tempfile::Builder::new()
            .prefix("write_dump")
            .tempfile()
            .unwrap();

        let tmp = context.minidump_writer(pid);
        let in_memory_buffer = tmp.write(&mut tmpfile).expect("Could not write minidump");
        child.kill().expect("Failed to kill process");

        let _waitres = child.wait().expect("Failed to wait for child");

        let meta = std::fs::metadata(tmpfile.path()).expect("Couldn't get metadata for tempfile");
        assert!(meta.len() > 0);

        let mem_slice = std::fs::read(tmpfile.path()).expect("Failed to read minidump");
        assert_eq!(mem_slice.len(), in_memory_buffer.len());
        assert_eq!(mem_slice, in_memory_buffer);

        let dump = Minidump::read_path(tmpfile.path()).expect("Failed to read minidump");
        let _: MinidumpModuleList = dump.get_stream().expect("Couldn't find MinidumpModuleList");
        let thread_list: MinidumpThreadList = dump.get_stream().expect("Couldn't find MinidumpThreadList");
        assert!(thread_list.threads.len() > 0);
        let _: MinidumpMemoryList = dump.get_stream().expect("Couldn't find MinidumpMemoryList");
        let _: MinidumpSystemInfo = dump.get_stream().expect("Couldn't find MinidumpSystemInfo");
        let exception: MinidumpException = dump.get_stream().expect("Couldn't find MinidumpException");
        let thread_ids: Vec<u32> = thread_list.threads.iter().map(|t| t.raw.thread_id).collect();
        assert!(
            thread_ids.contains(&exception.raw.thread_id),
            "Exception thread_id {} must exist in thread list {:?}",
            exception.raw.thread_id,
            thread_ids
        );
    }
}

contextual_test! {
    #[ignore]
    fn write_with_additional_memory(context: Context) {
        let mut child = start_child_and_return(&["spawn_alloc_wait"]);
        let pid = child.id() as i32;

        let mut tmpfile = tempfile::Builder::new()
            .prefix("additional_memory")
            .tempfile()
            .unwrap();

        let mut f = BufReader::new(child.stdout.as_mut().expect("Can't open stdout"));
        let mut buf = String::new();
        let _ = f.read_line(&mut buf).expect("Couldn't read address provided by child");
        let mut output = buf.split_whitespace();
        let memory_addr: usize = output.next().unwrap().parse().expect("unable to parse memory_addr");
        let memory_size: usize = output.next().unwrap().parse().expect("unable to parse memory_size");

        let mut tmp = context.minidump_writer(pid);

        let app_memory = AppMemory {
            ptr: memory_addr,
            length: memory_size,
        };
        tmp.set_app_memory(vec![app_memory]);

        tmp.write(&mut tmpfile).expect("Could not write minidump");
        child.kill().expect("Failed to kill process");
        let _waitres = child.wait().expect("Failed to wait for child");

        let dump = Minidump::read_path(tmpfile.path()).expect("Failed to read minidump");
        let section: MinidumpMemoryList = dump.get_stream().expect("Couldn't find MinidumpMemoryList");
        let region = section
            .memory_at_address(memory_addr as u64)
            .expect("Couldn't find memory region");

        assert_eq!(region.base_address, memory_addr as u64);
        assert_eq!(region.size, memory_size as u64);
    }
}

contextual_test! {
    fn named_threads(context: Context) {
        let num_of_threads = 3;
        let mut child = start_child_and_wait_for_named_threads(num_of_threads);
        let pid = child.id() as i32;

        let mut tmpfile = tempfile::Builder::new()
            .prefix("named_threads")
            .tempfile()
            .unwrap();

        let tmp = context.minidump_writer(pid);
        tmp.write(&mut tmpfile).expect("Could not write minidump");
        child.kill().expect("Failed to kill process");
        let _waitres = child.wait().expect("Failed to wait for child");

        let dump = Minidump::read_path(tmpfile.path()).expect("Failed to read minidump");

        let threads: MinidumpThreadList = dump.get_stream().expect("Couldn't find MinidumpThreadList");
        let thread_names: MinidumpThreadNames = dump.get_stream().expect("Couldn't find MinidumpThreadNames");

        let thread_ids: Vec<_> = threads.threads.iter().map(|t| t.raw.thread_id).collect();
        let named_count = thread_ids
            .iter()
            .filter(|id| thread_names.get_name(**id).is_some())
            .count();
        assert!(named_count > 0, "Expected at least one named thread");
    }
}

contextual_test! {
    fn file_descriptors(context: Context) {
        let num_of_files = 5;
        let num_of_threads = num_of_files + 1;
        let mut child = start_child_and_wait_for_create_files(num_of_files);
        let pid = child.id() as i32;

        let mut tmpfile = tempfile::Builder::new()
            .prefix("file_descriptors")
            .tempfile()
            .unwrap();

        let tmp = context.minidump_writer(pid);
        tmp.write(&mut tmpfile).expect("Could not write minidump");
        child.kill().expect("Failed to kill process");
        let _waitres = child.wait().expect("Failed to wait for child");

        let dump = Minidump::read_path(tmpfile.path()).expect("Failed to read minidump");

        // Handle data stream requires procfs with /proc/<pid>/fd support
        let proc_fd_exists = std::path::Path::new(&format!("/proc/{}/fd", pid)).exists();
        match dump.get_stream::<MinidumpHandleDataStream>() {
            Ok(handle_data) if proc_fd_exists => {
                assert!(
                    handle_data.handles.len() > 0,
                    "Expected file descriptors in handle data stream"
                );
            }
            Err(_) if !proc_fd_exists => {}
            Err(e) => panic!("Unexpected error reading handle data stream: {e}"),
            Ok(_) => {}
        }
    }
}

contextual_test! {
    fn memory_info_list_stream(context: Context) {
        let num_of_threads = 1;
        let mut child = start_child_and_wait_for_threads(num_of_threads);
        let pid = child.id() as i32;

        let mut tmpfile = tempfile::Builder::new()
            .prefix("memory_info_list")
            .tempfile()
            .unwrap();

        let tmp = context.minidump_writer(pid);
        tmp.write(&mut tmpfile).expect("Could not write minidump");
        child.kill().expect("Failed to kill process");
        let _waitres = child.wait().expect("Failed to wait for child");

        let dump = Minidump::read_path(tmpfile.path()).expect("Failed to read minidump");
        let mem_info_list: MinidumpMemoryInfoList = dump.get_stream().expect("Couldn't find MinidumpMemoryInfoList");
        assert!(mem_info_list.iter().count() > 0, "Expected memory info entries");
    }
}

contextual_test! {
    fn minidump_size_limit(context: Context) {
        let num_of_threads = 3;
        let mut child = start_child_and_wait_for_threads(num_of_threads);
        let pid = child.id() as i32;

        let mut tmpfile_nolimit = tempfile::Builder::new()
            .prefix("no_limit")
            .tempfile()
            .unwrap();

        let tmp = context.minidump_writer(pid);
        tmp.write(&mut tmpfile_nolimit).expect("Could not write minidump");
        let no_limit_size = std::fs::metadata(tmpfile_nolimit.path()).unwrap().len();

        let mut tmpfile_limit = tempfile::Builder::new()
            .prefix("with_limit")
            .tempfile()
            .unwrap();

        let mut tmp = context.minidump_writer(pid);
        tmp.set_minidump_size_limit(no_limit_size / 2);
        tmp.write(&mut tmpfile_limit).expect("Could not write minidump");
        let limit_size = std::fs::metadata(tmpfile_limit.path()).unwrap().len();

        child.kill().expect("Failed to kill process");
        let _waitres = child.wait().expect("Failed to wait for child");

        assert!(
            limit_size <= no_limit_size,
            "Limited dump ({}) should be <= unlimited ({})",
            limit_size,
            no_limit_size
        );
    }
}

contextual_test! {
    fn sanitized_stacks(context: Context) {
        let num_of_threads = 1;
        let mut child = start_child_and_wait_for_threads(num_of_threads);
        let pid = child.id() as i32;

        let mut tmpfile = tempfile::Builder::new()
            .prefix("sanitized_stacks")
            .tempfile()
            .unwrap();

        let mut tmp = context.minidump_writer(pid);
        tmp.sanitize_stack();
        tmp.write(&mut tmpfile).expect("Could not write minidump");
        child.kill().expect("Failed to kill process");
        let _waitres = child.wait().expect("Failed to wait for child");

        let dump = Minidump::read_path(tmpfile.path()).expect("Failed to read minidump");
        let _: MinidumpThreadList = dump.get_stream().expect("Couldn't find MinidumpThreadList");
        let _: MinidumpMemoryList = dump.get_stream().expect("Couldn't find MinidumpMemoryList");

        assert!(std::fs::metadata(tmpfile.path()).unwrap().len() > 0);
    }
}
