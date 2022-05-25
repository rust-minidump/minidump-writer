use super::*;

impl MinidumpWriter {
    /// Writes the [`MDStreamType::ThreadNamesStream`] which is an array of
    /// [`miniduimp_common::format::MINIDUMP_THREAD`]
    pub(crate) fn write_thread_names(
        &mut self,
        buffer: &mut DumpBuf,
        dumper: &TaskDumper,
    ) -> Result<MDRawDirectory, WriterError> {
        let threads = dumper.read_threads()?;

        // Ignore the thread that handled the exception
        let thread_count = if self.crash_context.handler_thread != mach2::port::MACH_PORT_NULL {
            threads.len() - 1
        } else {
            threads.len()
        };

        let list_header = MemoryWriter::<u32>::alloc_with_val(buffer, thread_count as u32)?;

        let mut dirent = MDRawDirectory {
            stream_type: MDStreamType::ThreadNamesStream as u32,
            location: list_header.location(),
        };

        let mut names = MemoryArrayWriter::<MDRawThreadName>::alloc_array(buffer, thread_count)?;
        dirent.location.data_size += names.location().data_size;

        let handler_thread = self.crash_context.handler_thread;
        for (i, tid) in threads
            .iter()
            .filter(|tid| **tid != handler_thread)
            .enumerate()
        {
            // It's unfortunate if we can't grab a thread name, but it's also
            // not a critical failure
            let name_loc = match Self::write_thread_name(buffer, *tid) {
                Some(loc) => loc,
                None => write_string_to_location(buffer, "")?,
            };

            let thread = MDRawThreadName {
                thread_id: *tid,
                thread_name_rva: name_loc.rva.into(),
            };

            names.set_value_at(buffer, thread, i)?;
        }

        Ok(dirent)
    }

    /// Attempts to retrieve and write the threadname, returning the threa names
    /// location if successful
    fn write_thread_name(
        buffer: &mut Buffer,
        tid: u32,
    ) -> Result<MDLocationDescriptor, TaskDumpError> {
        const THREAD_INFO_COUNT: u32 =
            (std::mem::size_of::<libc::proc_threadinfo>() / std::mem::size_of::<u32>()) as u32;

        // SAFETY: syscalls
        unsafe {
            let mut thread_info = std::mem::MaybeUninit::<libc::proc_threadinfo>::uninit();
            let mut count = THREAD_INFO_COUNT;

            // As noted in usr/include/mach/thread_info.h, the THREAD_EXTENDED_INFO
            // return is exactly the same as proc_pidinfo(..., proc_threadinfo)

            mach_call!(mach::thread_info(
                tid,
                5, // THREAD_EXTENDED_INFO
                thread_info.as_mut_ptr().cast(),
                &mut size,
            ))?;

            let thread_info = thread_info.assume_init();
            let name = dbg!(std::str::from_utf8(std::slice::from_raw_parts(
                thread_info.pth_name.as_ptr().cast(),
                thread_info.pth_name.len(),
            )))?;

            // Ignore the null terminator
            let tname = match name.find('\0') {
                Some(i) => &name[..i],
                None => name,
            };

            Ok(write_string_to_location(buffer, tname)?)
        }
    }
}
