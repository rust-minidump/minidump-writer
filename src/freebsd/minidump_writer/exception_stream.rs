use {super::*, crate::mem_writer::MemoryWriter, minidump_common::errors::ExceptionCodeLinux};

#[derive(Debug, thiserror::Error, serde::Serialize)]
pub enum SectionExceptionStreamError {
    #[error("Failed to write to memory")]
    MemoryWriterError(#[from] crate::mem_writer::MemoryWriterError),
}

impl MinidumpWriter {
    pub fn write_exception_stream(
        &mut self,
        buffer: &mut DumpBuf,
    ) -> Result<MDRawDirectory, SectionExceptionStreamError> {
        let exception = if let Some(context) = &self.crash_context {
            MDException {
                exception_code: context.siginfo.si_signo as u32,
                exception_flags: context.siginfo.si_code as u32,
                exception_address: context.siginfo.si_addr as u64,
                ..Default::default()
            }
        } else {
            let addr = match &self.crashing_thread_context {
                CrashingThreadContext::CrashContextPlusAddress((_, addr)) => *addr,
                _ => 0,
            };
            MDException {
                exception_code: ExceptionCodeLinux::DUMP_REQUESTED as u32,
                exception_address: addr as u64,
                ..Default::default()
            }
        };

        let thread_context = match &self.crashing_thread_context {
            CrashingThreadContext::CrashContext(ctx)
            | CrashingThreadContext::CrashContextPlusAddress((ctx, _)) => *ctx,
            CrashingThreadContext::None => MDLocationDescriptor {
                data_size: 0,
                rva: 0,
            },
        };

        let stream = MDRawExceptionStream {
            thread_id: self.blamed_thread as u32,
            exception_record: exception,
            __align: 0,
            thread_context,
        };
        let exc = MemoryWriter::alloc_with_val(buffer, stream)?;
        let dirent = MDRawDirectory {
            stream_type: MDStreamType::ExceptionStream as u32,
            location: exc.location(),
        };

        Ok(dirent)
    }
}
