use crate::windows::errors::Error;
use minidump_common::format::{BreakpadInfoValid, MINIDUMP_BREAKPAD_INFO, MINIDUMP_STREAM_TYPE};
use scroll::Pwrite;
use std::{ffi::c_void, os::windows::io::AsRawHandle};
pub use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::{
    Foundation::{CloseHandle, ERROR_SUCCESS, STATUS_INVALID_HANDLE},
    System::{
        ApplicationVerifier as av,
        Diagnostics::Debug as md,
        Threading::{GetCurrentThreadId, OpenProcess},
    },
};

pub struct MinidumpWriter {
    /// The crash context as captured by an exception handler
    crash_context: crash_context::CrashContext,
    /// Handle to the crashing process, which could be ourselves
    crashing_process: HANDLE,
    /// The pid of the crashing process.
    crashing_pid: u32,
    /// The `EXCEPTION_POINTERS` contained in crash context is a pointer into the
    /// memory of the process that crashed, as it contains an `EXCEPTION_RECORD`
    /// record which is an internally linked list, so in the case that we are
    /// dumping a process other than the current one, we need to tell
    /// MiniDumpWriteDump that the pointers come from an external process so that
    /// it can use eg ReadProcessMemory to get the contextual information from
    /// the crash, rather than from the current process
    is_external_process: bool,
}

impl MinidumpWriter {
    /// Creates a minidump writer for a crash that occurred in an external process.
    pub fn external_process(
        crash_context: crash_context::CrashContext,
        pid: u32,
        proc_handle: HANDLE,
    ) -> Self {
        Self {
            crash_context,
            crashing_process: proc_handle,
            crashing_pid: pid,
            is_external_process: true,
        }
    }

    /// Creates a minidump writer for a crash that occurred in the current process.
    ///
    /// # Errors
    ///
    /// Fails if we are unable to open a `HANDLE` to the current process
    pub fn current_process(crash_context: crash_context::CrashContext) -> Result<Self, Error> {
        let crashing_pid = std::process::id();

        // SAFETY: syscall
        let crashing_process = unsafe {
            OpenProcess(
                268435456, // desired access - GENERIC_ALL - for some reason this is defined in SystemServices which is massive and not worth bringing in for ONE constant
                0,         // inherit handles
                crashing_pid,
            )
        };

        if crashing_process == 0 {
            Err(std::io::Error::last_os_error().into())
        } else {
            Ok(Self {
                crash_context,
                crashing_process,
                crashing_pid,
                is_external_process: false,
            })
        }
    }

    /// Writes a minidump to the specified file
    pub fn dump(&self, destination: &mut std::fs::File) -> Result<(), Error> {
        let exc_info = if !self.crash_context.exception_pointers.is_null() {
            // https://docs.microsoft.com/en-us/windows/win32/api/minidumpapiset/ns-minidumpapiset-minidump_exception_information
            Some(md::MINIDUMP_EXCEPTION_INFORMATION {
                ThreadId: self.crash_context.thread_id,
                // This is a mut pointer for some reason...I don't _think_ it is
                // actually mut in practice...?
                ExceptionPointers: self.crash_context.exception_pointers as *mut _,
                ClientPointers: if self.is_external_process { 1 } else { 0 },
            })
        } else {
            None
        };

        // This is a bit dangerous if doing in-process dumping, but that's not
        // (currently) a real target of this crate, so this allocation is fine
        let mut user_streams = Vec::with_capacity(3);

        // Add an MDRawBreakpadInfo stream to the minidump, to provide additional
        // information about the exception handler to the Breakpad processor.
        // The information will help the processor determine which threads are
        // relevant. The Breakpad processor does not require this information but
        // can function better with Breakpad-generated dumps when it is present.
        // The native debugger is not harmed by the presence of this information.
        //
        // This info is only relevant for in-process dumping
        let mut breakpad_info = [0u8; 12];
        if !self.is_external_process {
            let bp_info = MINIDUMP_BREAKPAD_INFO {
                validity: BreakpadInfoValid::DumpThreadId.bits()
                    | BreakpadInfoValid::RequestingThreadId.bits(),
                dump_thread_id: self.crash_context.thread_id,
                // Safety: syscall
                requesting_thread_id: unsafe { GetCurrentThreadId() },
            };

            // TODO: derive Pwrite for MINIDUMP_BREAKPAD_INFO
            let mut offset = 0;
            offset += breakpad_info.pwrite(bp_info.validity, offset)?;
            offset += breakpad_info.pwrite(bp_info.dump_thread_id, offset)?;
            breakpad_info.pwrite(bp_info.requesting_thread_id, offset)?;

            user_streams.push(md::MINIDUMP_USER_STREAM {
                Type: MINIDUMP_STREAM_TYPE::BreakpadInfoStream as u32,
                BufferSize: breakpad_info.len() as u32,
                // Again with the mut pointer
                Buffer: breakpad_info.as_mut_ptr().cast(),
            });
        }

        // When dumping an external process we want to retrieve the actual contents
        // of the assertion info and add it as a user stream, but we need to
        // keep the memory alive for the duration of the write
        // SAFETY: POD
        let mut assertion_info: crash_context::RawAssertionInfo = unsafe { std::mem::zeroed() };

        if let Some(ai) = self.crash_context.assertion_info {
            let ai_ptr = if self.is_external_process {
                // Even though this information is useful for non-exceptional dumps
                // (purecall, invalid parameter), we don't treat it is a critical
                // failure if we can't read it (unlike Breakpad) since we will still
                // have the synthetic exception context that was generated which
                // indicates the kind (again, purecall or invalid parameter), and
                // realistically, the assertion information is going to fairly pointless
                // anyways (at least for invalid parameters) since the information
                // supplied to the handler is only going to be filled in if using
                // the debug MSVCRT, which you can only realistically do in dev
                // environments since the debug MSVCRT is not redistributable.
                let mut assert_info =
                    std::mem::MaybeUninit::<crash_context::RawAssertionInfo>::uninit();
                let mut bytes_read = 0;

                // SAFETY: syscall
                if unsafe {
                    md::ReadProcessMemory(
                        self.crashing_process, // client process handle to read the memory from
                        ai.cast(),             // the pointer to read from the client process
                        assert_info.as_mut_ptr().cast(), // The buffer we're filling with the memory
                        std::mem::size_of::<crash_context::RawAssertionInfo>(),
                        &mut bytes_read,
                    )
                } == 0
                {
                    // log::error!(
                    //     "failed to read assertion information from client: {}",
                    //     last_os_error()
                    // );
                    std::ptr::null()
                } else if bytes_read != std::mem::size_of::<crash_context::RawAssertionInfo>() {
                    // log::error!(
                    //     "read invalid number of bytes: expected {} != received {}",
                    //     std::mem::size_of::<crash_context::RawAssertionInfo>(),
                    //     bytes_read
                    // );
                    std::ptr::null()
                } else {
                    // SAFETY: this is fine as lone as Windows didn't lie to us
                    assertion_info = unsafe { assert_info.assume_init() };

                    &assertion_info
                }
            } else {
                ai
            };

            if !ai.is_null() {
                user_streams.push(md::MINIDUMP_USER_STREAM {
                    Type: MINIDUMP_STREAM_TYPE::AssertionInfoStream as u32,
                    BufferSize: std::mem::size_of::<crash_context::RawAssertionInfo>() as u32,
                    // Again with the mut pointer
                    Buffer: (ai_ptr as *mut crash_context::RawAssertionInfo).cast(),
                });
            }
        }

        let handle_stream = self.fill_handle_stream();

        // Note that we do this by ref, as the buffer inside the option needs
        // to stay alive for as long as we're writing the minidump since
        // the user stream has a pointer to it
        if let Some((_buf, handle_stream)) = &handle_stream {
            user_streams.push(*handle_stream);
        }

        let user_stream = md::MINIDUMP_USER_STREAM_INFORMATION {
            UserStreamCount: user_streams.len() as u32,
            UserStreamArray: user_streams.as_mut_ptr(),
        };

        // Write the actual minidump
        // https://docs.microsoft.com/en-us/windows/win32/api/minidumpapiset/nf-minidumpapiset-minidumpwritedump
        // SAFETY: syscall
        let ret = unsafe {
            md::MiniDumpWriteDump(
                self.crashing_process, // HANDLE to the process with the crash we want to capture
                self.crashing_pid,     // process id
                destination.as_raw_handle() as HANDLE, // file to write the minidump to
                md::MiniDumpNormal,    // MINIDUMP_TYPE - we _might_ want to make this configurable
                exc_info
                    .as_ref()
                    .map_or(std::ptr::null(), |ei| ei as *const _), // exceptionparam - the actual exception information
                &user_stream,     // user streams
                std::ptr::null(), // callback, unused
            )
        };

        if ret == 0 {
            Err(std::io::Error::last_os_error().into())
        } else {
            Ok(())
        }
    }

    /// In the case of a `STATUS_INVALID_HANDLE` exception, this function
    /// enumerates all of the handle operations that occurred within the crashing
    /// process and fills out a minidump user stream with the ops pertaining to
    /// the last invalid handle that is enumerated, which is, presumably
    /// (hopfully?), the one that led to the exception
    fn fill_handle_stream(&self) -> Option<(Vec<u8>, md::MINIDUMP_USER_STREAM)> {
        if self.crash_context.exception_code != STATUS_INVALID_HANDLE {
            return None;
        }

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
        } != 0
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
                let s = std::slice::from_ref(v);

                unsafe { std::slice::from_raw_parts(s.as_ptr().cast(), std::mem::size_of::<T>()) }
            }

            for op in hs.ops.into_iter().filter(|op| op.Handle == hs.last_invalid) {
                stream_buf.extend_from_slice(to_bytes(&op));
                md_list.NumberOfEntries += 1;
            }

            stream_buf[..md_list.SizeOfHeader as usize].copy_from_slice(to_bytes(&md_list));

            let handle_stream = md::MINIDUMP_USER_STREAM {
                Type: MINIDUMP_STREAM_TYPE::HandleOperationListStream as u32,
                BufferSize: stream_buf.len() as u32,
                // Still not getting over the mut pointers here
                Buffer: stream_buf.as_mut_ptr().cast(),
            };

            Some((stream_buf, handle_stream))
        } else {
            // We don't _particularly_ care if this fails, it's better if we had
            // the info, but not critical
            None
        }
    }
}

impl Drop for MinidumpWriter {
    fn drop(&mut self) {
        // If we're the current process we created the handle ourselves, so we need to close it
        if !self.is_external_process {
            // SAFETY: syscall
            unsafe { CloseHandle(self.crashing_process) };
        }
    }
}
