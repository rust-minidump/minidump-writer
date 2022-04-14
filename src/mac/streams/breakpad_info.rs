use super::*;
use format::{BreakpadInfoValid, MINIDUMP_BREAKPAD_INFO as BreakpadInfo};

impl MiniDumpWriter {
    fn write_breakpad_info(&mut self, buffer: &mut DumpBuf) -> Result<MDRawDirectory, WriterError> {
        let mut bp_section = MemoryWriter::<BreakpadInfo>::alloc(buffer)?;
        let dirent = MDRawDirectory {
            stream_type: MDStreamType::BreakpadInfoStream as u32,
            location: info_section.location(),
        };

        let bp_info = BreakpadInfo {
            validity: BreakpadInfoValid::DumpThreadId.bits()
                | BreakpadInfoValid::RequestingThreadId.bits(),
            // The thread where the exception port handled the exception, might
            // be useful to ignore/deprioritize when processing the minidump
            dump_thread_id: self.crash_context.handler_thread,
            // The actual thread where the exception was thrown
            requesting_thread_id: self.crash_context.thread,
        };

        Ok(dirent)
    }
}
