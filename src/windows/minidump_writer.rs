use crate::windows::errors::Error;
use minidump_common::format::{BreakpadInfoValid, MINIDUMP_BREAKPAD_INFO, MINIDUMP_STREAM_TYPE};
use scroll::Pwrite;
use std::{ffi::c_void, os::windows::io::AsRawHandle};
pub use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::{
    Foundation::{
        CloseHandle, ERROR_SUCCESS, STATUS_INVALID_HANDLE, STATUS_NONCONTINUABLE_EXCEPTION,
    },
    System::{ApplicationVerifier as av, Diagnostics::Debug as md, Threading as threading},
};

pub struct MinidumpWriter {
    /// Optional exception information
    exc_info: Option<md::MINIDUMP_EXCEPTION_INFORMATION>,
    /// Handle to the crashing process, which could be ourselves
    crashing_process: HANDLE,
    /// The id of the process we are dumping
    pid: u32,
    /// The id of the 'crashing' thread
    tid: u32,
    /// The exception code for the dump
    exception_code: i32,
    /// Whether we are dumping the current process or not
    is_external_process: bool,
}

impl MinidumpWriter {
    /// Creates a minidump of the current process, optionally including an
    /// exception code and the CPU context of the specified thread. If no thread
    /// is specified the current thread CPU context is used.
    ///
    /// Note that it is inherently unreliable to dump the currently running
    /// process, at least in the event of an actual exception. It is recommended
    /// to dump from an external process if possible via [`Self::dump_crash_context`]
    ///
    /// # Errors
    ///
    /// In addition to the errors described in [`Self::dump_crash_context`], this
    /// function can also fail if `thread_id` is specified and we are unable to
    /// acquire the thread's context
    pub fn dump_local_context(
        exception_code: Option<i32>,
        thread_id: Option<u32>,
        destination: &mut std::fs::File,
    ) -> Result<(), Error> {
        let exception_code = exception_code.unwrap_or(STATUS_NONCONTINUABLE_EXCEPTION);

        // SAFETY: syscalls, while this encompasses most of the function, the user
        // has no invariants to uphold so the entire function is not marked unsafe
        unsafe {
            let mut exception_context = if let Some(tid) = thread_id {
                let mut ec = std::mem::MaybeUninit::uninit();

                // We need to suspend the thread to get its context, which would be bad
                // if it's the current thread, so we check it early before regrets happen
                if tid == threading::GetCurrentThreadId() {
                    md::RtlCaptureContext(ec.as_mut_ptr());
                } else {
                    // We _could_ just fallback to the current thread if we can't get the
                    // thread handle, but probably better for this to fail with a specific
                    // error so that the caller can do that themselves if they want to
                    // https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openthread
                    let thread_handle = threading::OpenThread(
                        threading::THREAD_GET_CONTEXT
                            | threading::THREAD_QUERY_INFORMATION
                            | threading::THREAD_SUSPEND_RESUME, // desired access rights, we only need to get the context, which also requires suspension
                        0,   // inherit handles
                        tid, // thread id
                    );

                    if thread_handle == 0 {
                        return Err(Error::ThreadOpen(std::io::Error::last_os_error()));
                    }

                    struct OwnedHandle(HANDLE);

                    impl Drop for OwnedHandle {
                        fn drop(&mut self) {
                            // SAFETY: syscall
                            unsafe { CloseHandle(self.0) };
                        }
                    }

                    let thread_handle = OwnedHandle(thread_handle);

                    // As noted in the GetThreadContext docs, we have to suspend the thread before we can get its context
                    // https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-suspendthread
                    if threading::SuspendThread(thread_handle.0) == u32::MAX {
                        return Err(Error::ThreadSuspend(std::io::Error::last_os_error()));
                    }

                    // https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getthreadcontext
                    if md::GetThreadContext(thread_handle.0, ec.as_mut_ptr()) == 0 {
                        // Try to be a good citizen and resume the thread
                        threading::ResumeThread(thread_handle.0);

                        return Err(Error::ThreadContext(std::io::Error::last_os_error()));
                    }

                    // _presumably_ this will not fail if SuspendThread succeeded, but if it does
                    // there's really not much we can do about it, thus we don't bother checking the
                    // return value
                    threading::ResumeThread(thread_handle.0);
                }

                ec.assume_init()
            } else {
                let mut ec = std::mem::MaybeUninit::uninit();
                md::RtlCaptureContext(ec.as_mut_ptr());
                ec.assume_init()
            };

            let mut exception_record: md::EXCEPTION_RECORD = std::mem::zeroed();

            let exception_ptrs = md::EXCEPTION_POINTERS {
                ExceptionRecord: &mut exception_record,
                ContextRecord: &mut exception_context,
            };

            exception_record.ExceptionCode = exception_code;

            let cc = crash_context::CrashContext {
                exception_pointers: (&exception_ptrs as *const md::EXCEPTION_POINTERS).cast(),
                process_id: std::process::id(),
                thread_id: thread_id.unwrap_or_else(|| threading::GetCurrentThreadId()),
                exception_code,
            };

            Self::dump_crash_context(cc, destination)
        }
    }

    /// Writes a minidump for the context described by [`crash_context::CrashContext`].
    ///
    /// # Errors
    ///
    /// Fails if the process specified in the context is not the local process
    /// and we are unable to open it due to eg. security reasons, or we fail to
    /// write the minidump, which can be due to a host of issues with both acquiring
    /// the process information as well as writing the actual minidump contents to disk
    ///
    /// # Safety
    ///
    /// If [`crash_context::CrashContext::exception_pointers`] is specified, it
    /// is the responsibility of the caller to ensure that the pointer is valid
    /// for the duration of this function call.
    pub unsafe fn dump_crash_context(
        crash_context: crash_context::CrashContext,
        destination: &mut std::fs::File,
    ) -> Result<(), Error> {
        let pid = crash_context.process_id;

        // SAFETY: syscalls
        let (crashing_process, is_external_process) = unsafe {
            if pid != std::process::id() {
                let proc = threading::OpenProcess(
                    threading::PROCESS_ALL_ACCESS, // desired access
                    0,                             // inherit handles
                    pid,                           // pid
                );

                if proc == 0 {
                    return Err(std::io::Error::last_os_error().into());
                }

                (proc, true)
            } else {
                (threading::GetCurrentProcess(), false)
            }
        };

        let pid = crash_context.process_id;
        let tid = crash_context.thread_id;
        let exception_code = crash_context.exception_code;

        let exc_info = (!crash_context.exception_pointers.is_null()).then(||
            // https://docs.microsoft.com/en-us/windows/win32/api/minidumpapiset/ns-minidumpapiset-minidump_exception_information
            md::MINIDUMP_EXCEPTION_INFORMATION {
                ThreadId: crash_context.thread_id,
                // This is a mut pointer for some reason...I don't _think_ it is
                // actually mut in practice...?
                ExceptionPointers: crash_context.exception_pointers as *mut _,
                /// The `EXCEPTION_POINTERS` contained in crash context is a pointer into the
                /// memory of the process that crashed, as it contains an `EXCEPTION_RECORD`
                /// record which is an internally linked list, so in the case that we are
                /// dumping a process other than the current one, we need to tell
                /// `MiniDumpWriteDump` that the pointers come from an external process so that
                /// it can use eg `ReadProcessMemory` to get the contextual information from
                /// the crash, rather than from the current process
                ClientPointers: if is_external_process { 1 } else { 0 },
            });

        let mdw = Self {
            exc_info,
            crashing_process,
            pid,
            tid,
            exception_code,
            is_external_process,
        };

        mdw.dump(destination)
    }

    /// Writes a minidump to the specified file
    fn dump(mut self, destination: &mut std::fs::File) -> Result<(), Error> {
        let exc_info = self.exc_info.take();

        let mut user_streams = Vec::with_capacity(2);

        let mut breakpad_info = self.fill_breakpad_stream();

        if let Some(bp_info) = &mut breakpad_info {
            user_streams.push(md::MINIDUMP_USER_STREAM {
                Type: MINIDUMP_STREAM_TYPE::BreakpadInfoStream as u32,
                BufferSize: bp_info.len() as u32,
                // Again with the mut pointer
                Buffer: bp_info.as_mut_ptr().cast(),
            });
        }

        let mut handle_stream_buffer = if self.exception_code == STATUS_INVALID_HANDLE {
            self.fill_handle_stream()
        } else {
            None
        };

        // Note that we do this by ref, as the buffer inside the option needs
        // to stay alive for as long as we're writing the minidump since
        // the user stream has a pointer to it
        if let Some(buf) = &mut handle_stream_buffer {
            let handle_stream = md::MINIDUMP_USER_STREAM {
                Type: MINIDUMP_STREAM_TYPE::HandleOperationListStream as u32,
                BufferSize: buf.len() as u32,
                // Still not getting over the mut pointers here
                Buffer: buf.as_mut_ptr().cast(),
            };

            user_streams.push(handle_stream);
        }

        let user_stream_infos = md::MINIDUMP_USER_STREAM_INFORMATION {
            UserStreamCount: user_streams.len() as u32,
            UserStreamArray: user_streams.as_mut_ptr(),
        };

        // Write the actual minidump
        // https://docs.microsoft.com/en-us/windows/win32/api/minidumpapiset/nf-minidumpapiset-minidumpwritedump
        // SAFETY: syscall
        let ret = unsafe {
            md::MiniDumpWriteDump(
                self.crashing_process, // HANDLE to the process with the crash we want to capture
                self.pid,              // process id
                destination.as_raw_handle() as HANDLE, // file to write the minidump to
                md::MiniDumpNormal,    // MINIDUMP_TYPE - we _might_ want to make this configurable
                exc_info
                    .as_ref()
                    .map_or(std::ptr::null(), |ei| ei as *const _), // exceptionparam - the actual exception information
                &user_stream_infos, // user streams
                std::ptr::null(),   // callback, unused
            )
        };

        if ret == 0 {
            Err(std::io::Error::last_os_error().into())
        } else {
            Ok(())
        }
    }

    /// Create an MDRawBreakpadInfo stream to the minidump, to provide additional
    /// information about the exception handler to the Breakpad processor.
    /// The information will help the processor determine which threads are
    /// relevant. The Breakpad processor does not require this information but
    /// can function better with Breakpad-generated dumps when it is present.
    /// The native debugger is not harmed by the presence of this information.
    ///
    /// This info is only relevant for in-process dumping
    fn fill_breakpad_stream(&self) -> Option<[u8; 12]> {
        if self.is_external_process {
            return None;
        }

        let mut breakpad_info = [0u8; 12];

        let bp_info = MINIDUMP_BREAKPAD_INFO {
            validity: BreakpadInfoValid::DumpThreadId.bits()
                | BreakpadInfoValid::RequestingThreadId.bits(),
            dump_thread_id: self.tid,
            // Safety: syscall
            requesting_thread_id: unsafe { threading::GetCurrentThreadId() },
        };

        // TODO: derive Pwrite for MINIDUMP_BREAKPAD_INFO
        // https://github.com/rust-minidump/rust-minidump/pull/534
        let mut offset = 0;
        breakpad_info.gwrite(bp_info.validity, &mut offset).ok()?;
        breakpad_info
            .gwrite(bp_info.dump_thread_id, &mut offset)
            .ok()?;
        breakpad_info
            .gwrite(bp_info.requesting_thread_id, &mut offset)
            .ok()?;

        Some(breakpad_info)
    }

    /// In the case of a `STATUS_INVALID_HANDLE` exception, this function
    /// enumerates all of the handle operations that occurred within the crashing
    /// process and fills out a minidump user stream with the ops pertaining to
    /// the last invalid handle that is enumerated, which is, presumably
    /// (hopefully?), the one that led to the exception
    fn fill_handle_stream(&self) -> Option<Vec<u8>> {
        // State object we pass to the enumeration
        struct HandleState {
            ops: Vec<av::AVRF_HANDLE_OPERATION>,
            last_invalid: u64,
        }

        unsafe extern "system" fn enum_callback(
            resource_description: *mut c_void,
            enumeration_context: *mut c_void,
            enumeration_level: *mut u32,
        ) -> u32 {
            let description = &*resource_description.cast::<av::AVRF_HANDLE_OPERATION>();
            let mut hs = &mut *enumeration_context.cast::<HandleState>();

            // Remember the last invalid handle operation.
            if description.OperationType == av::OperationDbBADREF as u32 {
                hs.last_invalid = description.Handle;
            }

            // Record all handle operations.
            hs.ops.push(*description);
            *enumeration_level = av::HeapEnumerationEverything as u32;
            ERROR_SUCCESS
        }

        let mut hs = HandleState {
            ops: Vec::new(),
            last_invalid: 0,
        };

        // https://docs.microsoft.com/en-us/windows/win32/api/avrfsdk/nf-avrfsdk-verifierenumerateresource
        // SAFETY: syscall
        if unsafe {
            av::VerifierEnumerateResource(
                self.crashing_process,                // process to enumerate the handles for
                0,                                    // flags
                av::AvrfResourceHandleTrace,          // resource typea, we want to trace handles
                Some(enum_callback),                  // enumeration callback
                (&mut hs as *mut HandleState).cast(), // enumeration context
            )
        } == ERROR_SUCCESS
        {
            let mut stream_buf = Vec::new();

            // https://docs.microsoft.com/en-us/windows/win32/api/minidumpapiset/ns-minidumpapiset-minidump_handle_operation_list
            let mut md_list = md::MINIDUMP_HANDLE_OPERATION_LIST {
                SizeOfHeader: std::mem::size_of::<md::MINIDUMP_HANDLE_OPERATION_LIST>() as u32,
                SizeOfEntry: std::mem::size_of::<av::AVRF_HANDLE_OPERATION>() as u32,
                NumberOfEntries: 0,
                Reserved: 0,
            };

            stream_buf.resize(md_list.SizeOfHeader as usize, 0);

            #[inline]
            fn to_bytes<T: Sized>(v: &T) -> &[u8] {
                // SAFETY: both AVRF_HANDLE_OPERATION and MINIDUMP_HANDLE_OPERATION_LIST
                // are POD types
                unsafe {
                    std::slice::from_raw_parts((v as *const T).cast(), std::mem::size_of::<T>())
                }
            }

            for op in hs.ops.into_iter().filter(|op| op.Handle == hs.last_invalid) {
                stream_buf.extend_from_slice(to_bytes(&op));
                md_list.NumberOfEntries += 1;
            }

            stream_buf[..md_list.SizeOfHeader as usize].copy_from_slice(to_bytes(&md_list));

            Some(stream_buf)
        } else {
            // We don't _particularly_ care if this fails, it's better if we had
            // the info, but not critical
            None
        }
    }
}

impl Drop for MinidumpWriter {
    fn drop(&mut self) {
        // Note we close the handle regardless of whether it is the local handle
        // or an external one, as noted in the docs
        //
        // > The pseudo handle need not be closed when it is no longer needed.
        // > Calling the CloseHandle function with a pseudo handle has no effect.
        // SAFETY: syscall
        unsafe { CloseHandle(self.crashing_process) };
    }
}
