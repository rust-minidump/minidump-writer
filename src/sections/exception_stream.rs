use crate::minidump_writer::{CrashingThreadContext, DumpBuf, MinidumpWriter};
use crate::sections::MemoryWriter;
use crate::Result;
use minidump_common::format::*;

pub fn write(config: &mut MinidumpWriter, buffer: &mut DumpBuf) -> Result<MDRawDirectory> {
    let exception = if let Some(context) = &config.crash_context {
        let mut res: MDException = Default::default();
        res.exception_code = context.siginfo.si_signo as u32;
        res.exception_flags = context.siginfo.si_code as u32;
        res.exception_address = unsafe { context.siginfo.si_addr() } as u64;
        res
    } else {
        let addr = match config.crashing_thread_context {
            CrashingThreadContext::CrashContextPlusAddress((_, addr)) => addr,
            _ => 0,
        };
        let mut res: MDException = Default::default();
        res.exception_code = MD_EXCEPTION_CODE_LIN_DUMP_REQUESTED;
        res.exception_address = addr;
        res
    };

    let thread_context = match config.crashing_thread_context {
        CrashingThreadContext::CrashContextPlusAddress((ctx, _)) => ctx,
        CrashingThreadContext::CrashContext(ctx) => ctx,
        CrashingThreadContext::None => Default::default(),
    };

    let mut stream: MDRawExceptionStream = Default::default();
    stream.thread_id = config.blamed_thread as u32;
    stream.exception_record = exception;
    stream.thread_context = thread_context;
    let exc = MemoryWriter::alloc_with_val(buffer, stream)?;
    let dirent = MDRawDirectory {
        stream_type: MD_EXCEPTION_STREAM,
        location: exc.location(),
    };

    Ok(dirent)
}
