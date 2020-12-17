use crate::minidump_writer::{CrashingThreadContext, DumpBuf, MinidumpWriter};
use crate::sections::MemoryWriter;
use crate::Result;
use minidump_common::format::*;

pub fn write(config: &mut MinidumpWriter, buffer: &mut DumpBuf) -> Result<MDRawDirectory> {
    let exception = if let Some(context) = &config.crash_context {
        // TODO: Default::default()
        MDException {
            exception_code: context.siginfo.si_signo as u32,
            exception_flags: context.siginfo.si_code as u32,
            exception_record: 0,
            exception_address: unsafe { context.siginfo.si_addr() } as u64,
            number_parameters: 0,
            __align: 0,
            exception_information: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        }
    } else {
        let addr = match config.crashing_thread_context {
            CrashingThreadContext::CrashContextPlusAddress((_, addr)) => addr,
            _ => 0,
        };
        MDException {
            exception_code: MD_EXCEPTION_CODE_LIN_DUMP_REQUESTED as u32,
            exception_flags: 0,
            exception_record: 0,
            exception_address: addr,
            number_parameters: 0,
            __align: 0,
            exception_information: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        }
    };

    let thread_context = match config.crashing_thread_context {
        CrashingThreadContext::CrashContextPlusAddress((ctx, _)) => ctx,
        CrashingThreadContext::CrashContext(ctx) => ctx,
        CrashingThreadContext::None => MDLocationDescriptor {
            data_size: 0,
            rva: 0,
        },
    };

    let stream = MDRawExceptionStream {
        thread_id: config.blamed_thread as u32,
        exception_record: exception,
        __align: 0,
        thread_context,
    };
    let exc = MemoryWriter::alloc_with_val(buffer, stream)?;
    let dirent = MDRawDirectory {
        stream_type: MD_EXCEPTION_STREAM as u32,
        location: exc.location(),
    };

    Ok(dirent)
}
