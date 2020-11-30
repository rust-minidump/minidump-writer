use crate::app_memory::AppMemoryList;
use crate::dso_debug;
use crate::linux_ptrace_dumper::LinuxPtraceDumper;
use crate::maps_reader::{MappingInfo, MappingList};
use crate::minidump_format::*;
use crate::section_writer::*;
use crate::sections::*;
use crate::thread_info::Pid;
use crate::Result;
use std::io::{Cursor, Read, Write};

pub type DumpBuf = Cursor<Vec<u8>>;

#[derive(Debug)]
pub struct MinidumpWriter {
    pub process_id: Pid,
    pub blamed_thread: Pid,
    pub minidump_size_limit: Option<u64>,
    pub skip_stacks_if_mapping_unreferenced: bool,
    pub principal_mapping: Option<MappingInfo>,
    pub user_mapping_list: MappingList,
    pub app_memory: AppMemoryList,
    pub memory_blocks: Vec<MDMemoryDescriptor>,
}

// This doesn't work yet:
// https://github.com/rust-lang/rust/issues/43408
// fn write<T: Sized, P: AsRef<Path>>(path: P, value: T) -> Result<()> {
//     let mut file = std::fs::File::open(path)?;
//     let bytes: [u8; size_of::<T>()] = unsafe { transmute(value) };
//     file.write_all(&bytes)?;
//     Ok(())
// }

impl MinidumpWriter {
    pub fn new(process: Pid, blamed_thread: Pid) -> Self {
        MinidumpWriter {
            process_id: process,
            blamed_thread,
            minidump_size_limit: None,
            skip_stacks_if_mapping_unreferenced: false,
            principal_mapping: None,
            user_mapping_list: MappingList::new(),
            app_memory: AppMemoryList::new(),
            memory_blocks: Vec::new(),
        }
    }

    pub fn set_minidump_size_limit(&mut self, limit: u64) -> &mut Self {
        self.minidump_size_limit = Some(limit);
        self
    }

    pub fn set_user_mapping_list(&mut self, user_mapping_list: MappingList) -> &mut Self {
        self.user_mapping_list = user_mapping_list;
        self
    }

    pub fn set_principal_mapping(&mut self, principal_mapping: MappingInfo) -> &mut Self {
        self.principal_mapping = Some(principal_mapping);
        self
    }

    pub fn set_app_memory(&mut self, app_memory: AppMemoryList) -> &mut Self {
        self.app_memory = app_memory;
        self
    }

    pub fn skip_stacks_if_mapping_unreferenced(&mut self) -> &mut Self {
        self.skip_stacks_if_mapping_unreferenced = true; // Off by default
        self
    }

    pub fn dump(&mut self, destination: &mut impl Write) -> Result<()> {
        let mut dumper = LinuxPtraceDumper::new(self.process_id)?;
        dumper.suspend_threads()?;
        // TODO: Doesn't exist yet
        //self.dumper.late_init()?;
        let mut buffer = Cursor::new(Vec::new());
        self.generate_dump(&mut buffer, &mut dumper)?;

        // Write results to file
        destination.write_all(buffer.get_ref())?;

        dumper.resume_threads()?;

        Ok(())
    }

    fn generate_dump(
        &mut self,
        buffer: &mut DumpBuf,
        dumper: &mut LinuxPtraceDumper,
    ) -> Result<()> {
        // A minidump file contains a number of tagged streams. This is the number
        // of stream which we write.
        let num_writers = 13u32;

        let mut header_section = SectionWriter::<MDRawHeader>::alloc(buffer)?;

        let mut dir_section =
            SectionArrayWriter::<MDRawDirectory>::alloc_array(buffer, num_writers as usize)?;

        let header = MDRawHeader {
            signature: MD_HEADER_SIGNATURE,
            version: MD_HEADER_VERSION,
            stream_count: num_writers,
            //   header.get()->stream_directory_rva = dir.position();
            stream_directory_rva: dir_section.position as u32,
            checksum: 0, /* Can be 0.  In fact, that's all that's
                          * been found in minidump files. */
            time_date_stamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs() as u32, // TODO: This is not Y2038 safe, but thats how its currently defined as
            flags: 0,
        };
        header_section.set_value(buffer, header)?;

        // Ensure the header gets flushed. If we crash somewhere below,
        // we should have a mostly-intact dump
        // TODO: Write header_section to file here

        let mut dir_idx = 0;
        let mut dirent = thread_list_stream::write(self, buffer, &dumper)?;
        dir_section.set_value_at(buffer, dirent, dir_idx)?;
        dir_idx += 1;

        dirent = mappings::write(self, buffer, dumper)?;
        dir_section.set_value_at(buffer, dirent, dir_idx)?;
        dir_idx += 1;

        let _ = app_memory::write(self, buffer)?;

        dirent = memory_list_stream::write(self, buffer)?;
        dir_section.set_value_at(buffer, dirent, dir_idx)?;
        dir_idx += 1;

        // Currently unused
        dirent = exception_stream::write(self, buffer)?;
        dir_section.set_value_at(buffer, dirent, dir_idx)?;
        dir_idx += 1;

        dirent = systeminfo_stream::write(buffer)?;
        dir_section.set_value_at(buffer, dirent, dir_idx)?;
        dir_idx += 1;

        dirent = match self.write_file(buffer, "/proc/cpuinfo") {
            Ok(location) => MDRawDirectory {
                stream_type: MDStreamType::LinuxCpuInfo as u32,
                location,
            },
            Err(_) => Default::default(),
        };
        dir_section.set_value_at(buffer, dirent, dir_idx)?;
        dir_idx += 1;

        dirent = match self.write_file(buffer, &format!("/proc/{}/status", self.blamed_thread)) {
            Ok(location) => MDRawDirectory {
                stream_type: MDStreamType::LinuxProcStatus as u32,
                location,
            },
            Err(_) => Default::default(),
        };
        dir_section.set_value_at(buffer, dirent, dir_idx)?;
        dir_idx += 1;

        dirent = match self
            .write_file(buffer, "/etc/lsb-release")
            .or_else(|_| self.write_file(buffer, "/etc/os-release"))
        {
            Ok(location) => MDRawDirectory {
                stream_type: MDStreamType::LinuxLsbRelease as u32,
                location,
            },
            Err(_) => Default::default(),
        };
        dir_section.set_value_at(buffer, dirent, dir_idx)?;
        dir_idx += 1;

        dirent = match self.write_file(buffer, &format!("/proc/{}/cmdline", self.blamed_thread)) {
            Ok(location) => MDRawDirectory {
                stream_type: MDStreamType::LinuxCmdLine as u32,
                location,
            },
            Err(_) => Default::default(),
        };
        dir_section.set_value_at(buffer, dirent, dir_idx)?;
        dir_idx += 1;

        dirent = match self.write_file(buffer, &format!("/proc/{}/environ", self.blamed_thread)) {
            Ok(location) => MDRawDirectory {
                stream_type: MDStreamType::LinuxEnviron as u32,
                location,
            },
            Err(_) => Default::default(),
        };
        dir_section.set_value_at(buffer, dirent, dir_idx)?;
        dir_idx += 1;

        dirent = match self.write_file(buffer, &format!("/proc/{}/auxv", self.blamed_thread)) {
            Ok(location) => MDRawDirectory {
                stream_type: MDStreamType::LinuxAuxv as u32,
                location,
            },
            Err(_) => Default::default(),
        };
        dir_section.set_value_at(buffer, dirent, dir_idx)?;
        dir_idx += 1;

        dirent = match self.write_file(buffer, &format!("/proc/{}/maps", self.blamed_thread)) {
            Ok(location) => MDRawDirectory {
                stream_type: MDStreamType::LinuxMaps as u32,
                location,
            },
            Err(_) => Default::default(),
        };
        dir_section.set_value_at(buffer, dirent, dir_idx)?;
        dir_idx += 1;

        dirent = dso_debug::write_dso_debug_stream(buffer, self.blamed_thread, &dumper.auxv)?;
        dir_section.set_value_at(buffer, dirent, dir_idx)?;

        // If you add more directory entries, don't forget to update kNumWriters,
        // above.
        Ok(())
    }

    fn write_file(&self, buffer: &mut DumpBuf, filename: &str) -> Result<MDLocationDescriptor> {
        // TODO: Is this buffer-limitation really needed? Or could we read&write all?
        // We can't stat the files because several of the files that we want to
        // read are kernel seqfiles, which always have a length of zero. So we have
        // to read as much as we can into a buffer.
        let buf_size = 1024 - 2 * std::mem::size_of::<usize>() as u64;

        let mut file = std::fs::File::open(std::path::PathBuf::from(filename))?.take(buf_size);
        let mut content = Vec::new();
        file.read_to_end(&mut content)?;

        let section = SectionArrayWriter::<u8>::alloc_from_array(buffer, &content)?;
        Ok(section.location())
    }
}
