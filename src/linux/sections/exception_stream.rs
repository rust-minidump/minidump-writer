use super::minidump_writer::CrashingThreadContext;
use super::*;

#[allow(non_camel_case_types, unused)]
#[repr(u32)]
enum MDExceptionCodeLinux {
    MD_EXCEPTION_CODE_LIN_SIGHUP = 1,     /* Hangup (POSIX) */
    MD_EXCEPTION_CODE_LIN_SIGINT = 2,     /* Interrupt (ANSI) */
    MD_EXCEPTION_CODE_LIN_SIGQUIT = 3,    /* Quit (POSIX) */
    MD_EXCEPTION_CODE_LIN_SIGILL = 4,     /* Illegal instruction (ANSI) */
    MD_EXCEPTION_CODE_LIN_SIGTRAP = 5,    /* Trace trap (POSIX) */
    MD_EXCEPTION_CODE_LIN_SIGABRT = 6,    /* Abort (ANSI) */
    MD_EXCEPTION_CODE_LIN_SIGBUS = 7,     /* BUS error (4.2 BSD) */
    MD_EXCEPTION_CODE_LIN_SIGFPE = 8,     /* Floating-point exception (ANSI) */
    MD_EXCEPTION_CODE_LIN_SIGKILL = 9,    /* Kill, unblockable (POSIX) */
    MD_EXCEPTION_CODE_LIN_SIGUSR1 = 10,   /* User-defined signal 1 (POSIX).  */
    MD_EXCEPTION_CODE_LIN_SIGSEGV = 11,   /* Segmentation violation (ANSI) */
    MD_EXCEPTION_CODE_LIN_SIGUSR2 = 12,   /* User-defined signal 2 (POSIX) */
    MD_EXCEPTION_CODE_LIN_SIGPIPE = 13,   /* Broken pipe (POSIX) */
    MD_EXCEPTION_CODE_LIN_SIGALRM = 14,   /* Alarm clock (POSIX) */
    MD_EXCEPTION_CODE_LIN_SIGTERM = 15,   /* Termination (ANSI) */
    MD_EXCEPTION_CODE_LIN_SIGSTKFLT = 16, /* Stack faultd */
    MD_EXCEPTION_CODE_LIN_SIGCHLD = 17,   /* Child status has changed (POSIX) */
    MD_EXCEPTION_CODE_LIN_SIGCONT = 18,   /* Continue (POSIX) */
    MD_EXCEPTION_CODE_LIN_SIGSTOP = 19,   /* Stop, unblockable (POSIX) */
    MD_EXCEPTION_CODE_LIN_SIGTSTP = 20,   /* Keyboard stop (POSIX) */
    MD_EXCEPTION_CODE_LIN_SIGTTIN = 21,   /* Background read from tty (POSIX) */
    MD_EXCEPTION_CODE_LIN_SIGTTOU = 22,   /* Background write to tty (POSIX) */
    MD_EXCEPTION_CODE_LIN_SIGURG = 23,
    /* Urgent condition on socket (4.2 BSD) */
    MD_EXCEPTION_CODE_LIN_SIGXCPU = 24, /* CPU limit exceeded (4.2 BSD) */
    MD_EXCEPTION_CODE_LIN_SIGXFSZ = 25,
    /* File size limit exceeded (4.2 BSD) */
    MD_EXCEPTION_CODE_LIN_SIGVTALRM = 26, /* Virtual alarm clock (4.2 BSD) */
    MD_EXCEPTION_CODE_LIN_SIGPROF = 27,   /* Profiling alarm clock (4.2 BSD) */
    MD_EXCEPTION_CODE_LIN_SIGWINCH = 28,  /* Window size change (4.3 BSD, Sun) */
    MD_EXCEPTION_CODE_LIN_SIGIO = 29,     /* I/O now possible (4.2 BSD) */
    MD_EXCEPTION_CODE_LIN_SIGPWR = 30,    /* Power failure restart (System V) */
    MD_EXCEPTION_CODE_LIN_SIGSYS = 31,    /* Bad system call */
    MD_EXCEPTION_CODE_LIN_DUMP_REQUESTED = 0xFFFFFFFF, /* No exception,
                                          dump requested. */
}

pub fn write(
    config: &mut MinidumpWriter,
    buffer: &mut DumpBuf,
) -> Result<MDRawDirectory, errors::SectionExceptionStreamError> {
    let exception = if let Some(context) = &config.crash_context {
        MDException {
            exception_code: context.inner.siginfo.ssi_signo as u32,
            exception_flags: context.inner.siginfo.ssi_code as u32,
            exception_address: context.inner.siginfo.ssi_addr as u64,
            ..Default::default()
        }
    } else {
        let addr = match &config.crashing_thread_context {
            CrashingThreadContext::CrashContextPlusAddress((_, addr)) => *addr,
            _ => 0,
        };
        MDException {
            exception_code: MDExceptionCodeLinux::MD_EXCEPTION_CODE_LIN_DUMP_REQUESTED as u32,
            exception_address: addr as u64,
            ..Default::default()
        }
    };

    let thread_context = match config.crashing_thread_context {
        CrashingThreadContext::CrashContextPlusAddress((ctx, _))
        | CrashingThreadContext::CrashContext(ctx) => ctx,
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
        stream_type: MDStreamType::ExceptionStream as u32,
        location: exc.location(),
    };

    Ok(dirent)
}
