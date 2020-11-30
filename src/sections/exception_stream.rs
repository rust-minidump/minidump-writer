use crate::minidump_format::*;
use crate::minidump_writer::{DumpBuf, MinidumpWriter};
use crate::section_writer::*;
use crate::Result;

pub fn write(_config: &mut MinidumpWriter, buffer: &mut DumpBuf) -> Result<MDRawDirectory> {
    let exc = SectionWriter::<MDRawExceptionStream>::alloc(buffer)?;
    let dirent = MDRawDirectory {
        stream_type: MDStreamType::ExceptionStream as u32,
        location: exc.location(),
    };
    // TODO: Not implemented yet
    // stream->thread_id = GetCrashThread();
    // stream->exception_record.exception_code = dumper_->crash_signal();
    // stream->exception_record.exception_flags = dumper_->crash_signal_code();
    // stream->exception_record.exception_address = dumper_->crash_address();
    // const std::vector<uint64_t> crash_exception_info =
    //     dumper_->crash_exception_info();
    // stream->exception_record.number_parameters = crash_exception_info.size();
    // memcpy(stream->exception_record.exception_information,
    //        crash_exception_info.data(),
    //        sizeof(uint64_t) * crash_exception_info.size());
    // stream->thread_context = crashing_thread_context_;
    Ok(dirent)
}
