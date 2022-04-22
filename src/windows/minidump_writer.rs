use crate::windows::errors::Error;
use minidump_common::format::{BreakpadInfoValid, MINIDUMP_BREAKPAD_INFO, MINIDUMP_STREAM_TYPE};
use scroll::Pwrite;
use std::{ffi::c_void, os::windows::io::AsRawHandle};
pub use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::{
    Foundation::{CloseHandle, ERROR_SUCCESS, STATUS_INVALID_HANDLE},
    System::{ApplicationVerifier as av, Diagnostics::Debug as md, Threading as threading},
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
    ///
    /// # Errors
    ///
    /// Fails if we are unable to open the external process for some reason
    pub fn external_process(
        crash_context: crash_context::CrashContext,
        pid: u32,
    ) -> Result<Self, Error> {
        // SAFETY: syscall
        let crashing_process = unsafe {
            threading::OpenProcess(
                threading::PROCESS_ALL_ACCESS, // desired access
                0,                             // inherit handles
                pid,                           // pid
            )
        };

        if crashing_process == 0 {
            Err(std::io::Error::last_os_error().into())
        } else {
            Ok(Self {
                crash_context,
                crashing_process,
                crashing_pid: pid,
                is_external_process: true,
            })
        }
    }

    /// Creates a minidump writer for a crash that occurred in the current process.
    ///
    /// Note that in-process dumping is inherently unreliable, it is recommended
    /// to use the [`Self::external_process`] in a different process than the
    /// one that crashed when possible.
    pub fn current_process(crash_context: crash_context::CrashContext) -> Self {
        let crashing_pid = std::process::id();

        // SAFETY: syscall
        let crashing_process = unsafe { threading::GetCurrentProcess() };

        Self {
            crash_context,
            crashing_process,
            crashing_pid,
            is_external_process: false,
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
        let mut user_streams = Vec::with_capacity(2);

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
                requesting_thread_id: unsafe { threading::GetCurrentThreadId() },
            };

            // TODO: derive Pwrite for MINIDUMP_BREAKPAD_INFO
            // https://github.com/rust-minidump/rust-minidump/pull/534
            let mut offset = 0;
            breakpad_info.gwrite(bp_info.validity, &mut offset)?;
            breakpad_info.gwrite(bp_info.dump_thread_id, &mut offset)?;
            breakpad_info.gwrite(bp_info.requesting_thread_id, &mut offset)?;

            user_streams.push(md::MINIDUMP_USER_STREAM {
                Type: MINIDUMP_STREAM_TYPE::BreakpadInfoStream as u32,
                BufferSize: breakpad_info.len() as u32,
                // Again with the mut pointer
                Buffer: breakpad_info.as_mut_ptr().cast(),
            });
        }

        let mut handle_stream_buffer = self.fill_handle_stream();

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
                self.crashing_pid,     // process id
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

    /// In the case of a `STATUS_INVALID_HANDLE` exception, this function
    /// enumerates all of the handle operations that occurred within the crashing
    /// process and fills out a minidump user stream with the ops pertaining to
    /// the last invalid handle that is enumerated, which is, presumably
    /// (hopefully?), the one that led to the exception
    fn fill_handle_stream(&self) -> Option<Vec<u8>> {
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
        } == 0
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
        // SAFETY: syscall
        unsafe { CloseHandle(self.crashing_process) };
    }
}
