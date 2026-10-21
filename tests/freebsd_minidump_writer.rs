#![cfg(target_os = "freebsd")]

use {
    common::*,
    minidump::*,
    minidump_common::errors::ExceptionCodeLinux,
    minidump_writer::{
        CrashContext, Pid, app_memory::AppMemory, auxv::AuxvDumpInfo,
        minidump_writer::MinidumpWriterConfig,
    },
    serde_json::Value,
    std::io::{BufRead, BufReader},
    std::process::Stdio,
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
            let mut crash_context = get_crash_context(main_lwp, pid);
            crash_context.siginfo.si_signo = libc::SIGSEGV;
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
    auxv.try_filling_missing_info(minidump_writer::local(std::process::id() as Pid).as_ref())
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
        assert!(!thread_list.threads.is_empty());
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

        // The exception code reflects the dump mode: DUMP_REQUESTED without a
        // crash context, the context's signal number otherwise.
        let expected_code = if matches!(context, Context::With) {
            libc::SIGSEGV as u32
        } else {
            ExceptionCodeLinux::DUMP_REQUESTED as u32
        };
        assert_eq!(exception.raw.exception_record.exception_code, expected_code);

        // Every module must be symbolizable.
        let modules: MinidumpModuleList = dump.get_stream().expect("Couldn't find MinidumpModuleList");
        assert!(!modules.iter().any(|m| m.debug_identifier().is_none()));
    }
}

contextual_test! {
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
        // The helper prints the pointer with `{:p}` (i.e. `0x`-prefixed hex).
        let memory_addr: usize = usize::from_str_radix(
            output.next().unwrap().trim_start_matches("0x"),
            16,
        )
        .expect("unable to parse memory_addr");
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
        // The helper names spawned threads `thread_1` .. `thread_{n-1}`; the
        // main thread falls back to the process command name.
        for id in 1..num_of_threads {
            let tid_name = format!("thread_{id}");
            let named = thread_ids.iter().any(|tid| {
                thread_names
                    .get_name(*tid)
                    .is_some_and(|n| n.as_ref() == tid_name.as_str())
            });
            assert!(named, "expected a thread named {tid_name}");
        }
    }
}

contextual_test! {
    fn file_descriptors(context: Context) {
        let num_of_files = 5;
        let _num_of_threads = num_of_files + 1;
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
                    !handle_data.handles.is_empty(),
                    "Expected file descriptors in handle data stream"
                );
                // stdin/stdout/stderr plus the created test files.
                assert!(
                    handle_data.handles.len() >= num_of_files + 3,
                    "expected at least {} handles, got {}",
                    num_of_files + 3,
                    handle_data.handles.len()
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

#[test]
fn minidump_size_limit() {
    // More than LIMIT_BASE_THREAD_COUNT (20) threads so the stack-size
    // cap actually kicks in for the extra threads.
    let num_of_threads = 40;
    let mut child = start_child_and_wait_for_threads(num_of_threads);
    let pid = child.id() as i32;

    let mut total_normal_stack_size = 0u64;
    let normal_file_size;

    // First, write a minidump with no size limit.
    {
        let mut tmpfile = tempfile::Builder::new()
            .prefix("no_limit")
            .tempfile()
            .unwrap();

        let tmp = MinidumpWriterConfig::new(pid, pid);
        tmp.write(&mut tmpfile).expect("Could not write minidump");
        normal_file_size = std::fs::metadata(tmpfile.path()).unwrap().len();

        let dump = Minidump::read_path(tmpfile.path()).expect("Failed to read minidump");
        let threads: MinidumpThreadList =
            dump.get_stream().expect("Couldn't find MinidumpThreadList");
        for thread in threads.threads {
            assert!(thread.raw.stack.memory.data_size > 0);
            total_normal_stack_size += u64::from(thread.raw.stack.memory.data_size);
        }
    }

    // Second, write a minidump with a size limit small enough to be
    // triggered.
    {
        const LIMIT_AVERAGE_THREAD_STACK_LENGTH: u64 = 8 * 1024;
        let mut minidump_size_limit = LIMIT_AVERAGE_THREAD_STACK_LENGTH * 40;
        if normal_file_size < minidump_size_limit {
            minidump_size_limit = normal_file_size;
        }

        let mut tmpfile = tempfile::Builder::new()
            .prefix("with_limit")
            .tempfile()
            .unwrap();

        let mut tmp = MinidumpWriterConfig::new(pid, pid);
        tmp.set_minidump_size_limit(minidump_size_limit);
        tmp.write(&mut tmpfile).expect("Could not write minidump");
        let limit_size = std::fs::metadata(tmpfile.path()).unwrap().len();

        // If this fails because it's the same size, the size-limit logic
        // didn't kick in like it was supposed to.
        assert!(
            limit_size < normal_file_size,
            "limited ({limit_size}) must be smaller than unlimited ({normal_file_size})"
        );

        let mut total_limit_stack_size = 0u64;
        let dump = Minidump::read_path(tmpfile.path()).expect("Failed to read minidump");
        let threads: MinidumpThreadList =
            dump.get_stream().expect("Couldn't find MinidumpThreadList");
        for thread in threads.threads {
            assert!(thread.raw.stack.memory.data_size > 0);
            total_limit_stack_size += u64::from(thread.raw.stack.memory.data_size);
        }

        // The stacks must shrink by at least 1KB per extra thread.
        const LIMIT_BASE_THREAD_COUNT: usize = 20;
        const MIN_PER_EXTRA_THREAD_STACK_REDUCTION: u64 = 1024;
        let min_reduction =
            (40 - LIMIT_BASE_THREAD_COUNT) as u64 * MIN_PER_EXTRA_THREAD_STACK_REDUCTION;
        assert!(
            total_limit_stack_size < total_normal_stack_size - min_reduction,
            "stacks barely shrank: {total_limit_stack_size} vs {total_normal_stack_size}"
        );
    }

    child.kill().expect("Failed to kill process");
    let _waitres = child.wait().expect("Failed to wait for child");
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

/// The main module must be read from process memory even when the binary has
/// been deleted from disk: the build id in the dump has to match the one
/// computed from the file before deletion.
#[test]
fn with_deleted_binary() {
    let num_of_threads = 1;
    let binary_copy_dir = tempfile::Builder::new()
        .prefix("deleted_binary")
        .tempdir()
        .unwrap();
    let binary_copy = binary_copy_dir.as_ref().join("binary_copy");

    std::fs::copy(std::env!("CARGO_BIN_EXE_test"), &binary_copy).expect("Failed to copy binary");
    let mem_slice = std::fs::read(&binary_copy).expect("Failed to read binary");

    let mut child = std::process::Command::new(&binary_copy)
        .arg("spawn_and_wait")
        .arg(num_of_threads.to_string())
        .stdout(Stdio::piped())
        .spawn()
        .expect("failed to execute child");
    wait_for_threads(&mut child, num_of_threads);

    let pid = child.id() as i32;

    let mut build_id =
        <minidump_writer::module_reader::BuildId as minidump_writer::module_reader::ReadFromModule>::read_from_module(
            minidump_writer::module_reader::ModuleMemory::Slice(&mem_slice),
        )
        .expect("Failed to get build_id")
        .0;

    std::fs::remove_file(&binary_copy).expect("Failed to remove binary");

    let mut tmpfile = tempfile::Builder::new()
        .prefix("deleted_binary")
        .tempfile()
        .unwrap();

    let main_lwp = get_main_thread_lwp(pid).unwrap_or(pid);
    MinidumpWriterConfig::new(pid, main_lwp)
        .write(&mut tmpfile)
        .expect("Could not write minidump");

    child.kill().expect("Failed to kill process");
    let _waitres = child.wait().expect("Failed to wait for child");

    let dump = Minidump::read_path(tmpfile.path()).expect("Failed to read minidump");
    let module_list: MinidumpModuleList = dump
        .get_stream()
        .expect("Couldn't find stream MinidumpModuleList");

    let main_module = module_list
        .main_module()
        .expect("Could not get main module");
    let did = main_module
        .debug_identifier()
        .expect("expected value debug id");
    let did_uuid = did.uuid();
    let uuid = did_uuid.as_bytes();

    // Swap the first three fields to match the minidump GUID layout.
    if cfg!(target_endian = "little") {
        build_id[..4].reverse();
        build_id[4..6].reverse();
        build_id[6..8].reverse();
    }

    // The build id can be shorter than a UUID (e.g. LLD's xxhash ids);
    // the rest is zero-padded.
    build_id.resize(16, 0);

    assert_eq!(uuid.as_slice(), &build_id);

    // The 'age' appendix is always 0 on non-windows targets.
    assert_eq!(did.appendix(), 0);
}

/// Dumping our own process is refused: ptrace doesn't work on itself.
#[test]
fn cannot_ptrace_same_process() {
    let own_pid = std::process::id() as i32;
    let mut tmpfile = tempfile::Builder::new()
        .prefix("same_process")
        .tempfile()
        .unwrap();

    let result = MinidumpWriterConfig::new(own_pid, own_pid).write(&mut tmpfile);
    let err = result.expect_err("expected an error for self-dump");
    let json = serde_json::to_value(&err).expect("serializable");
    assert!(
        json.to_string().contains("CannotPtraceSameProcess"),
        "unexpected error: {err:#?}"
    );
}

/// Module list properties: non-empty, sane bases/sizes and names.
#[test]
fn module_list_properties() {
    let mut child = start_child_and_wait_for_threads(1);
    let pid = child.id() as i32;

    let mut tmpfile = tempfile::Builder::new()
        .prefix("module_list_props")
        .tempfile()
        .unwrap();
    MinidumpWriterConfig::new(pid, get_main_thread_lwp(pid).unwrap_or(pid))
        .write(&mut tmpfile)
        .expect("Could not write minidump");
    child.kill().expect("Failed to kill process");
    let _waitres = child.wait().expect("Failed to wait for child");

    let dump = Minidump::read_path(tmpfile.path()).expect("Failed to read minidump");
    let modules: MinidumpModuleList = dump.get_stream().expect("Couldn't find MinidumpModuleList");

    let all = modules.iter().collect::<Vec<_>>();
    assert!(!all.is_empty());
    assert!(modules.main_module().is_some());
    for module in &all {
        assert!(
            module.size() > 0,
            "module {:?} has zero size",
            module.code_file()
        );
        assert!(
            !module.code_file().is_empty(),
            "module at {:#x} has no name",
            module.base_address()
        );
    }
}

/// With a crash context, ~256 bytes around the crashing instruction pointer
/// must be present in the memory list.
#[test]
fn crash_thread_ip_memory() {
    let mut child = start_child_and_wait_for_threads(1);
    let pid = child.id() as i32;
    let main_lwp = get_main_thread_lwp(pid).unwrap_or(pid);

    // Grab a valid instruction pointer of the child from its auxv entry
    // point, then let go before the writer attaches.
    let entry_point = {
        let inspector = minidump_writer::local(pid);
        inspector.attach().expect("attach");
        let mut auxv = minidump_writer::auxv::AuxvDumpInfo::default();
        auxv.try_filling_missing_info(inspector.as_ref())
            .expect("auxv");
        let entry = auxv.get_entry_address().expect("AT_ENTRY") as usize;
        inspector.detach().expect("detach");
        entry
    };

    let mut crash_context = get_crash_context(main_lwp, pid);
    crash_context.ucontext.uc_mcontext.mc_rip = entry_point as i64;

    let mut tmpfile = tempfile::Builder::new()
        .prefix("crash_ip_mem")
        .tempfile()
        .unwrap();
    let mut cfg = MinidumpWriterConfig::new(pid, main_lwp);
    cfg.set_crash_context(crash_context);
    cfg.write(&mut tmpfile).expect("Could not write minidump");
    child.kill().expect("Failed to kill process");
    let _waitres = child.wait().expect("Failed to wait for child");

    let dump = Minidump::read_path(tmpfile.path()).expect("Failed to read minidump");
    let memory: MinidumpMemoryList = dump.get_stream().expect("Couldn't find MinidumpMemoryList");
    let region = memory
        .memory_at_address(entry_point as u64)
        .expect("memory around the crashing IP");
    assert!(
        region.size > 0 && region.size <= 256,
        "unexpected size {}",
        region.size
    );
}

/// Dumping a process that is not our own child exercises the ECHILD wait
/// path (polling `ki_stat` instead of `waitpid`).
#[test]
fn write_dump_for_non_child() {
    let mut child = start_child_and_return(&["spawn_spawn_wait"]);
    let _pid = child.id() as i32;

    let mut f = BufReader::new(child.stdout.as_mut().expect("Can't open stdout"));
    let mut buf = String::new();
    let _ = f.read_line(&mut buf).expect("Couldn't read grandchild pid");
    let grandchild_pid: i32 = buf.trim().parse().expect("pid");
    std::thread::sleep(std::time::Duration::from_millis(500));

    let mut tmpfile = tempfile::Builder::new()
        .prefix("non_child")
        .tempfile()
        .unwrap();
    MinidumpWriterConfig::new(grandchild_pid, grandchild_pid)
        .write(&mut tmpfile)
        .expect("Could not write minidump");

    // Don't leak the parked grandchild on development machines.
    unsafe {
        libc::kill(grandchild_pid, libc::SIGKILL);
    }

    let dump = Minidump::read_path(tmpfile.path()).expect("Failed to read minidump");
    let threads: MinidumpThreadList = dump.get_stream().expect("Couldn't find MinidumpThreadList");
    assert!(!threads.threads.is_empty());

    child.kill().expect("Failed to kill process");
    let _waitres = child.wait().expect("Failed to wait for child");
}

/// A stack pointer inside an unreadable region must scan upwards to the next
/// RW mapping (e.g. a guard region on stack overflow).
#[test]
fn stack_info_scan_skips_unreadable_regions() {
    let mut child = start_child_and_wait_for_threads(1);
    let pid = child.id() as i32;

    let mut writer = MinidumpWriterConfig::new(pid, pid)
        .build_for_testing(error_graph::strategy::DontCare)
        .expect("init");
    let page = writer.page_size.max(1);

    let base = 0x1_0000;
    let mk = |start: usize, size: usize, perms| minidump_writer::maps_reader::MappingInfo {
        start_address: start,
        size,
        system_mapping_info: minidump_writer::maps_reader::SystemMappingInfo {
            start_address: start,
            end_address: start + size,
        },
        offset: 0,
        permissions: perms,
        name: None,
    };
    writer.mappings = vec![
        // No-access region containing the stack pointer.
        mk(
            base,
            page,
            minidump_writer::vm_permissions::VmPermissions::empty(),
        ),
        // The actual stack, two pages further up.
        mk(
            base + 2 * page,
            8 * page,
            minidump_writer::vm_permissions::VmPermissions::READ
                | minidump_writer::vm_permissions::VmPermissions::WRITE,
        ),
    ];

    // sp inside the no-access mapping: `find_mapping` finds it but
    // `may_be_stack` rejects it, so the scan moves up to the RW stack.
    let (valid_sp, len) = writer
        .get_stack_info(base)
        .expect("stack info via upward scan");
    assert_eq!(valid_sp, base + 2 * page);
    assert_eq!(len, 8 * page);

    drop(writer);
    child.kill().expect("Failed to kill process");
    let _waitres = child.wait().expect("Failed to wait for child");
}

/// User-supplied mappings must be written with their identifier.
#[test]
fn user_mapping_list_identifier() {
    let mut child = start_child_and_wait_for_threads(1);
    let pid = child.id() as i32;

    let mut tmpfile = tempfile::Builder::new()
        .prefix("user_mapping")
        .tempfile()
        .unwrap();

    let identifier: Vec<u8> = (0..16u8).collect();
    let entry = minidump_writer::maps_reader::MappingEntry {
        info: minidump_writer::maps_reader::MappingInfo {
            start_address: 0x1000,
            size: 0x2000,
            system_mapping_info: minidump_writer::maps_reader::SystemMappingInfo {
                start_address: 0x1000,
                end_address: 0x3000,
            },
            offset: 0,
            permissions: minidump_writer::vm_permissions::VmPermissions::READ
                | minidump_writer::vm_permissions::VmPermissions::WRITE,
            name: Some("fake_user_mapping".into()),
        },
        identifier: Some(identifier.clone()),
    };

    let mut cfg = MinidumpWriterConfig::new(pid, pid);
    cfg.set_user_mapping_list(vec![entry]);
    cfg.write(&mut tmpfile).expect("Could not write minidump");
    child.kill().expect("Failed to kill process");
    let _waitres = child.wait().expect("Failed to wait for child");

    let dump = Minidump::read_path(tmpfile.path()).expect("Failed to read minidump");
    let modules: MinidumpModuleList = dump.get_stream().expect("Couldn't find MinidumpModuleList");

    let module = modules
        .iter()
        .find(|m| m.code_file().contains("fake_user_mapping"))
        .expect("user module in list");
    let did = module.debug_identifier().expect("identifier present");

    // The CV record identifier is reinterpreted as a GUID (first three
    // fields byte-swapped on little-endian).
    let mut expected = identifier;
    if cfg!(target_endian = "little") {
        expected[..4].reverse();
        expected[4..6].reverse();
        expected[6..8].reverse();
    }
    assert_eq!(did.uuid().as_bytes(), expected.as_slice());
    assert_eq!(did.appendix(), 0);
}
