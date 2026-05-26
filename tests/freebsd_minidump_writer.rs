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
        module_reader,
    },
    std::{
        collections::HashSet,
        io::{BufRead, BufReader, Seek, SeekFrom},
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
    let inspector = minidump_writer::ProcessInspector::local(std::process::id() as Pid);
    auxv.try_filling_missing_info(&inspector, error_graph::ErrorList::default())
        .expect("failed to read auxv for current process");

    assert!(auxv.get_program_header_count().unwrap_or_default() > 0);
    assert!(auxv.get_program_header_address().unwrap_or_default() > 0);
    assert!(auxv.get_entry_address().unwrap_or_default() > 0);
}

fn contains_json_string(value: &serde_json::Value, expected: &str) -> bool {
    match value {
        serde_json::Value::String(actual) => actual == expected,
        serde_json::Value::Array(items) => items
            .iter()
            .any(|item| contains_json_string(item, expected)),
        serde_json::Value::Object(entries) => entries
            .values()
            .any(|item| contains_json_string(item, expected)),
        _ => false,
    }
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

        // Verify memory contents match what the child allocated
        // (0..memory_size bytes cycling 0..255)
        let mut values = Vec::<u8>::with_capacity(memory_size);
        for idx in 0..memory_size {
            values.push((idx % 255) as u8);
        }
        assert_eq!(region.bytes, values);
    }
}

#[test]
fn skip_stacks_if_mapping_unreferenced_omits_thread_stacks() {
    let num_of_threads = 1;
    let mut child = start_child_and_wait_for_threads(num_of_threads);
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

contextual_test! {
    fn named_threads(context: Context) {
        let num_of_threads = 5;
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

        let thread_names: MinidumpThreadNames = dump
            .get_stream()
            .expect("Couldn't find MinidumpThreadNames");

        let thread_ids: Vec<_> = threads.threads.iter().map(|t| t.raw.thread_id).collect();
        let names: HashSet<_> = thread_ids
            .iter()
            .map(|id| thread_names.get_name(*id).unwrap_or_default())
            .map(|cow| cow.into_owned())
            .collect();
        let mut expected = HashSet::new();
        expected.insert("test".to_string());
        for id in 1..num_of_threads {
            expected.insert(format!("thread_{id}"));
        }
        assert_eq!(expected, names);
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

                // Verify stdin, stdout, stderr (fd 0, 1, 2) are present
                for i in 0..3 {
                    let descriptor = handle_data.handles.get(i).expect("Descriptor should be present");
                    let fd = *descriptor.raw.handle().expect("Handle should be populated");
                    assert_eq!(fd, i as u64);
                }

                let non_std_files = &handle_data.handles[3..];

                // Verify that the test files created by the child are present
                for i in 0..num_of_files {
                    assert!(
                        non_std_files.iter().any(|descriptor| {
                            let Some(name) = &descriptor.object_name else { return false; };
                            let Some(file_name) = name.rsplit_once('/').map(|(_, fname)| fname) else { return false; };
                            if !file_name.starts_with("test_file") {
                                return false;
                            }

                            file_name.ends_with(&i.to_string())
                        }),
                        "unable to locate expected file `test_file{i}` in file handle stream"
                    );
                }
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
        assert!(mem_info_list.iter().count() > 1, "Expected memory info entries");
    }
}

contextual_test! {
    fn minidump_size_limit(context: Context) {
        let num_of_threads = 40;
        let mut child = start_child_and_wait_for_threads(num_of_threads);
        let pid = child.id() as i32;

        let mut total_normal_stack_size = 0;
        let normal_file_size;
        // First, write a minidump with no size limit.
        {
            let mut tmpfile = tempfile::Builder::new()
                .prefix("write_dump_unlimited")
                .tempfile()
                .unwrap();

            context.minidump_writer(pid).write(&mut tmpfile).expect("Could not write minidump");

            let meta = std::fs::metadata(tmpfile.path()).expect("Couldn't get metadata for tempfile");
            assert!(meta.len() > 0);

            normal_file_size = meta.len();

            // Read dump file and check its contents
            let dump = Minidump::read_path(tmpfile.path()).expect("Failed to read minidump");
            let thread_list: MinidumpThreadList =
                dump.get_stream().expect("Couldn't find MinidumpThreadList");
            for thread in thread_list.threads {
                assert!(thread.raw.thread_id > 0);
                assert!(thread.raw.stack.memory.data_size > 0);
                total_normal_stack_size += thread.raw.stack.memory.data_size;
            }
        }

        // Second, write a minidump with a size limit big enough to not trigger anything.
        {
            // Set size limit arbitrarily 2MiB larger than the normal file size -- such
            // that the limiting code will not kick in.
            let minidump_size_limit = normal_file_size + 2 * 1024 * 1024;

            let mut tmpfile = tempfile::Builder::new()
                .prefix("write_dump_pseudolimited")
                .tempfile()
                .unwrap();

            let mut tmp = context.minidump_writer(pid);
            tmp.set_minidump_size_limit(minidump_size_limit);
            tmp.write(&mut tmpfile).expect("Could not write minidump");

            let meta = std::fs::metadata(tmpfile.path()).expect("Couldn't get metadata for tempfile");

            // Make sure limiting wasn't actually triggered.
            let min = std::cmp::min(meta.len(), normal_file_size);
            let max = std::cmp::max(meta.len(), normal_file_size);

            // Setting a stack limit limits the size of non-main stacks even before
            // the limit is reached. This will cause slight variations in size
            // between a limited and an unlimited minidump.
            assert!(max - min < 1024, "max = {max:} min = {min:}");
        }

        // Third, write a minidump with a size limit small enough to be triggered.
        {
            // Copied from sections/thread_list_stream.rs
            const LIMIT_AVERAGE_THREAD_STACK_LENGTH: u64 = 8 * 1024;
            let mut minidump_size_limit = LIMIT_AVERAGE_THREAD_STACK_LENGTH * 40;

            // If, in reality, each of the threads' stack is *smaller* than
            // kLimitAverageThreadStackLength, the normal file size could very well be
            // smaller than the arbitrary limit that was just set. In that case,
            // either of these numbers should trigger the size-limiting code, but we
            // might as well pick the smallest.
            if normal_file_size < minidump_size_limit {
                minidump_size_limit = normal_file_size;
            }

            let mut tmpfile = tempfile::Builder::new()
                .prefix("write_dump_limited")
                .tempfile()
                .unwrap();

            let mut tmp = context.minidump_writer(pid);
            tmp.set_minidump_size_limit(minidump_size_limit);
            tmp.write(&mut tmpfile).expect("Could not write minidump");

            let meta = std::fs::metadata(tmpfile.path()).expect("Couldn't get metadata for tempfile");
            assert!(meta.len() > 0);
            // Make sure the file size is at least smaller than the original. If this
            // fails because it's the same size, then the size-limit logic didn't kick
            // in like it was supposed to.
            assert!(meta.len() < normal_file_size);

            let mut total_limit_stack_size = 0;
            // Read dump file and check its contents
            let dump = Minidump::read_path(tmpfile.path()).expect("Failed to read minidump");
            let thread_list: MinidumpThreadList =
                dump.get_stream().expect("Couldn't find MinidumpThreadList");
            for thread in thread_list.threads {
                assert!(thread.raw.thread_id > 0);
                assert!(thread.raw.stack.memory.data_size > 0);
                total_limit_stack_size += thread.raw.stack.memory.data_size;
            }

            // Make sure stack size shrunk by at least 1KB per extra thread.
            // Copied from sections/thread_list_stream.rs
            const LIMIT_BASE_THREAD_COUNT: usize = 20;
            const MIN_PER_EXTRA_THREAD_STACK_REDUCTION: usize = 1024;
            let min_expected_reduction =
                (40 - LIMIT_BASE_THREAD_COUNT) * MIN_PER_EXTRA_THREAD_STACK_REDUCTION;
            assert!(total_limit_stack_size < total_normal_stack_size - min_expected_reduction as u32);
        }

        child.kill().expect("Failed to kill process");
        let _waitres = child.wait().expect("Failed to wait for child");
    }
}

contextual_test! {
    fn sanitized_stacks(context: Context) {
        if context == Context::With {
            // FIXME the context's stack pointer very often doesn't lie in mapped memory, resulting
            // in the stack memory having 0 size (so no slice will match `defaced` in the
            // assertion).
            return;
        }
        let num_of_threads = 1;
        let mut child = start_child_and_wait_for_threads(num_of_threads);
        let pid = child.id() as i32;

        let mut tmpfile = tempfile::Builder::new()
            .prefix("sanitized_stacks")
            .tempfile()
            .unwrap();

        let mut tmp = context.minidump_writer(pid);
        tmp.sanitize_stack();
        tmp.write(&mut tmpfile).expect("Failed to dump minidump");
        child.kill().expect("Failed to kill process");
        let _waitres = child.wait().expect("Failed to wait for child");

        // Read dump file and check its contents
        let dump = Minidump::read_path(tmpfile.path()).expect("Failed to read minidump");
        let dump_array = std::fs::read(tmpfile.path()).expect("Failed to read minidump as vec");
        let thread_list: MinidumpThreadList =
            dump.get_stream().expect("Couldn't find MinidumpThreadList");

        let defaced;
        #[cfg(target_pointer_width = "64")]
        {
            defaced = 0x0defaced0defacedusize.to_ne_bytes();
        }
        #[cfg(target_pointer_width = "32")]
        {
            defaced = 0x0defacedusize.to_ne_bytes()
        };

        for thread in thread_list.threads {
            let mem = thread.raw.stack.memory;
            let start = mem.rva as usize;
            let end = (mem.rva + mem.data_size) as usize;
            let slice = &dump_array.as_slice()[start..end];
            assert!(
                slice.windows(defaced.len()).any(|window| window == defaced),
                "Expected sanitized (defaced) pattern in thread stack"
            );
        }
    }
}

contextual_test! {
    fn write_early_abort(context: Context) {
        let mut child = start_child_and_return(&["spawn_alloc_wait"]);
        let pid = child.id() as i32;

        let mut tmpfile = tempfile::Builder::new()
            .prefix("early_abort")
            .tempfile()
            .unwrap();

        let mut f = BufReader::new(child.stdout.as_mut().expect("Can't open stdout"));
        let mut buf = String::new();
        let _ = f
            .read_line(&mut buf)
            .expect("Couldn't read address provided by child");
        let mut output = buf.split_whitespace();
        // We do not read the actual memory_address, but use NULL, which
        // should create an error during dumping and lead to a truncated minidump.
        let _ = output.next().unwrap().trim_start_matches("0x");
        let memory_addr: usize = 0;
        let memory_size: usize = output
            .next()
            .unwrap()
            .parse()
            .expect("unable to parse memory_size");

        let app_memory = AppMemory {
            ptr: memory_addr,
            length: memory_size,
        };

        let mut tmp = context.minidump_writer(pid);
        tmp.set_app_memory(vec![app_memory]);

        // This should fail, because during the dump an error is detected (try_from fails)
        match tmp.write(&mut tmpfile) {
            Err(WriterError::SectionAppMemoryError(_)) => (),
            Ok(_) => panic!("Expected an error but write succeeded"),
            Err(e) => panic!("Wrong kind of error returned: {e:?}"),
        }

        child.kill().expect("Failed to kill process");
        let _waitres = child.wait().expect("Failed to wait for child");

        // Read dump file and check its contents. There should be a truncated minidump available
        let dump = Minidump::read_path(tmpfile.path()).expect("Failed to read minidump");
        // Should be there
        let _: MinidumpThreadList = dump.get_stream().expect("Couldn't find MinidumpThreadList");
        let _: MinidumpModuleList = dump.get_stream().expect("Couldn't find MinidumpModuleList");

        // Should be missing:
        assert!(dump.get_stream::<MinidumpMemoryList>().is_err());
    }
}

#[test]
fn with_deleted_binary() {
    let num_of_threads = 1;
    let binary_copy_dir = tempfile::Builder::new()
        .prefix("deleted_binary")
        .tempdir()
        .unwrap();
    let binary_copy = binary_copy_dir.as_ref().join("binary_copy");

    let path: String = if let Ok(p) = std::env::var("TEST_HELPER") {
        p
    } else {
        std::env!("CARGO_BIN_EXE_test").into()
    };

    std::fs::copy(path, &binary_copy).expect("Failed to copy binary");
    let mem_slice = std::fs::read(&binary_copy).expect("Failed to read binary");

    let mut child = std::process::Command::new(&binary_copy)
        .env("RUST_BACKTRACE", "1")
        .arg("spawn_and_wait")
        .arg(num_of_threads.to_string())
        .stdout(Stdio::piped())
        .spawn()
        .expect("failed to execute child");
    wait_for_threads(&mut child, num_of_threads);

    let pid = child.id() as i32;

    let mut build_id =
        module_reader::read_build_id_from_module(SliceModuleMemoryReader(mem_slice.as_slice()))
            .expect("Failed to get build_id");

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

    // Begin checks on dump
    let meta = std::fs::metadata(tmpfile.path()).expect("Couldn't get metadata for tempfile");
    assert!(meta.len() > 0);

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
    {
        let uuid = did.uuid();
        let uuid = uuid.as_bytes();

        // Swap bytes in the original to match the expected uuid
        if cfg!(target_endian = "little") {
            build_id[..4].reverse();
            build_id[4..6].reverse();
            build_id[6..8].reverse();
        }

        // The build_id from the binary can be as little as 8 bytes, eg LLD uses
        // xxhash to calculate the build_id by default from 10+
        build_id.resize(16, 0);

        assert_eq!(uuid.as_slice(), &build_id);
    }

    // The 'age'/appendix, always 0 on non-windows targets
    assert_eq!(did.appendix(), 0);
}

/// Verify that a minidump with a user-supplied mapping can be written and
/// read back correctly. This is the FreeBSD equivalent of Linux's
/// `write_and_read_dump_from_parent` test, adapted for FreeBSD's API
/// (MappingInfo instead of MappingEntry + SystemMappingInfo).
#[test]
#[ignore]
fn write_with_user_mapping() {
    let mut child = start_child_and_return(&["spawn_mmap_wait"]);
    let pid = child.id() as i32;

    let mut tmpfile = tempfile::Builder::new()
        .prefix("write_with_user_mapping")
        .tempfile()
        .unwrap();

    let mut f = BufReader::new(child.stdout.as_mut().expect("Can't open stdout"));
    let mut buf = String::new();
    let _ = f
        .read_line(&mut buf)
        .expect("Couldn't read address provided by child");
    let mut output = buf.split_whitespace();
    let mmap_addr: usize = output
        .next()
        .unwrap()
        .parse()
        .expect("unable to parse mmap_addr");
    let memory_size: usize = output
        .next()
        .unwrap()
        .parse()
        .expect("unable to parse memory_size");

    use minidump_writer::maps_reader::{MappingInfo, SystemMappingInfo};
    use minidump_writer::vm_permissions::VmPermissions;

    // Add information about the mapped memory.
    let mapping = MappingInfo {
        start_address: mmap_addr,
        size: memory_size,
        system_mapping_info: SystemMappingInfo {
            start_address: mmap_addr,
            end_address: mmap_addr + memory_size,
        },
        offset: 0,
        permissions: VmPermissions::READ | VmPermissions::WRITE,
        name: Some(std::ffi::OsString::from("a fake mapping")),
    };

    let main_lwp = get_main_thread_lwp(pid).unwrap_or(pid);
    let mut tmp = MinidumpWriterConfig::new(pid, main_lwp);

    tmp.set_user_mapping_list(vec![mapping]);
    tmp.write(&mut tmpfile)
        .expect("Could not write minidump");

    child.kill().expect("Failed to kill process");
    let _waitres = child.wait().expect("Failed to wait for child");

    let dump = Minidump::read_path(tmpfile.path()).expect("Failed to read minidump");
    let module_list: MinidumpModuleList = dump
        .get_stream()
        .expect("Couldn't find stream MinidumpModuleList");
    let module = module_list
        .module_at_address(mmap_addr as u64)
        .expect("Couldn't find user mapping module");
    assert_eq!(module.base_address(), mmap_addr as u64);
    assert_eq!(module.size(), memory_size as u64);
    assert_eq!(module.code_file(), "a fake mapping");

    let _: MinidumpException = dump.get_stream().expect("Couldn't find MinidumpException");
    let _: MinidumpThreadList = dump.get_stream().expect("Couldn't find MinidumpThreadList");
    let _: MinidumpMemoryList = dump.get_stream().expect("Couldn't find MinidumpMemoryList");
    let _: MinidumpSystemInfo = dump.get_stream().expect("Couldn't find MinidumpSystemInfo");
    let _: MinidumpMemoryInfoList = dump.get_stream().expect("Couldn't find MinidumpMemoryInfoList");
}