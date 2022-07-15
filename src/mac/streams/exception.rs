use super::*;

impl MinidumpWriter {
    /// Writes the [`minidump_common::format::MINIDUMP_EXCEPTION_STREAM`] stream.
    ///
    /// This stream is optional on MacOS as a user requested minidump could
    /// choose not to specify the exception information.
    pub(crate) fn write_exception(
        &mut self,
        buffer: &mut DumpBuf,
        dumper: &TaskDumper,
    ) -> Result<MDRawDirectory, WriterError> {
        // This shouldn't fail since we won't be writing this stream if the crash context is
        // not present
        let crash_context = self
            .crash_context
            .as_ref()
            .ok_or(WriterError::NoCrashContext)?;

        let thread_state = dumper.read_thread_state(crash_context.thread).ok();

        let thread_context = if let Some(ts) = &thread_state {
            let mut cpu = Default::default();
            Self::fill_cpu_context(ts, &mut cpu);
            MemoryWriter::alloc_with_val(buffer, cpu)
                .map(|mw| mw.location())
                .ok()
        } else {
            None
        };

        let exception_record = crash_context
            .exception
            .as_ref()
            .map(|exc| {
                let exception_address = if let Some(subcode) = exc.subcode {
                    subcode as u64
                } else if let Some(ts) = thread_state {
                    ts.pc()
                } else {
                    0
                };

                // The naming is confusing here, but it is how it is
                MDException {
                    exception_code: exc.kind as u32,
                    exception_flags: exc.code as u32,
                    exception_address,
                    ..Default::default()
                }
            })
            .unwrap_or_default();

        let stream = MDRawExceptionStream {
            thread_id: crash_context.thread,
            exception_record,
            thread_context: thread_context.unwrap_or_default(),
            __align: 0,
        };

        let exc_section = MemoryWriter::<MDRawExceptionStream>::alloc_with_val(buffer, stream)?;

        Ok(MDRawDirectory {
            stream_type: MDStreamType::ExceptionStream as u32,
            location: exc_section.location(),
        })
    }
}
