use super::*;

#[cfg(target_pointer_width = "32")]
compile_error!("this module assumes a 64-bit pointer width");

fn all_image_addr(task: mach2::mach_types::task_name_t) -> Option<u64> {
    let mut task_dyld_info = std::mem::MaybeUninit::<mach2::task_info::task_dyld_info>::uninit();
    let mut count = std::mem::size_of::<mach2::task_info::task_dyld_info>()
        / std::mem::size_of::<mach2::vm_types::natural_t>();

    // SAFETY: syscall
    kern_ret(|| unsafe {
        mach2::task::task_info(
            task,
            mach2::task_info::TASK_DYLD_INFO,
            task_dyld_info.as_mut_ptr().cast(),
            &mut count,
        )
    })
    .ok()?;

    Some(task_dyld_info.all_image_info_addr)
}

// dyld_image_info
#[repr(C)]
struct ImageInfo {
    load_address: u64,
    file_path: u64,
    file_mod_date: u64,
}

// usr/include/mach-o/loader.h, the file type for the main executable image
const MH_EXECUTE: u32 = 0x2;
// usr/include/mach-o/loader.h, magic number for MachHeader
const MH_MAGIC_64: u32 = 0xfeedfacf;
// usr/include/mach-o/loader.h, command to map a segment
const LC_SEGMENT_64: u32 = 0x19;
// usr/include/mach-o/loader.h, dynamically linked shared lib ident
const LC_ID_DYLIB: u32 = 0xd;
// usr/include/mach-o/loader.h, the uuid
const LC_UUID: u32 = 0x1b;

impl MiniDumpWriter {
    fn write_module_list(&mut self, buffer: &mut DumpBuf) -> Result<MDRawDirectory, WriterError> {
        let modules = if let Some(all_images) = all_image_addr(self.crash_context.task) {
            self.read_loaded_modules(all_images)?
        } else {
            vec![]
        };

        let list_header = MemoryWriter::<u32>::alloc_with_val(buffer, modules.len() as u32)?;

        let mut dirent = MDRawDirectory {
            stream_type: MDStreamType::ModuleListStream as u32,
            location: list_header.location(),
        };

        if !modules.is_empty() {
            let mapping_list = MemoryArrayWriter::<MDRawModule>::alloc_from_iter(buffer, modules)?;
            dirent.location.data_size += mapping_list.location().data_size;
        }

        Ok(dirent)
    }

    fn read_loaded_modules(&self, all_images_addr: u64) -> Result<Vec, WriterError> {
        // Read the structure inside of dyld that contains information about
        // loaded images.  We're reading from the desired task's address space.

        // dyld_all_image_infos defined in usr/include/mach-o/dyld_images.h, we
        // only need a couple of fields at the beginning
        #[repr(C)]
        struct AllImagesInfo {
            version: u32, // == 1 in Mac OS X 10.4
            info_array_count: u32,
            info_array_addr: u64,
        }

        // Here we make the assumption that dyld loaded at the same address in
        // the crashed process vs. this one.  This is an assumption made in
        // "dyld_debug.c" and is said to be nearly always valid.
        let dyld_all_info_buf =
            self.read_task_memory(all_images_addr, std::mem::size_of::<AllImagesInfo>())?;
        let dyld_info: &AllImagesInfo = &*(dyld_all_info_buf.cast());

        let dyld_info_buf = self.read_task_memory(
            dyld_info.info_array_addr,
            dyld_info.info_array_count * std::mem::size_of::<ImageInfo>(),
        )?;

        let all_images = unsafe {
            std::slice::from_raw_parts(
                dyld_info.buf.as_ptr().cast::<ImageInfo>(),
                dyld_info.info_array_count as usize,
            )
        };

        let mut images = Vec::with_capacity(all_images.len());

        for image in all_images {
            // Apparently MacOS will happily list the same image multiple times
            // for some reason, so only add images once
            let insert_index = if let Err(i) =
                images.binary_search_by(|img| image.load_address.cmp(&img.load_address))
            {
                i
            } else {
                continue;
            };

            if let Ok(module) = self.read_module(image) {
                images.insert(insert_index, module);
            }
        }

        // The modules are sorted by load address, but we always want the
        // main executable to be first in the minidump

        Ok(images)
    }

    fn read_module(&self, image: ImageInfo, buf: &mut DumpBuf) -> Result<MDRawModule, WriterError> {
        // usr/include/mach-o/loader.h
        #[repr(C)]
        struct MachHeader {
            magic: u32,         // mach magic number identifier
            cpu_type: i32,      // cpu_type_t cpu specifier
            cpu_sub_type: i32,  // cpu_subtype_t machine specifier
            file_type: u32,     // type of file
            num_commands: u32,  // number of load commands
            size_commands: u32, // size of all the load commands
            flags: u32,
            __reserved: u32,
        }

        // usr/include/mach-o/loader.h
        #[repr(C)]
        struct LoadCommand {
            cmd: u32,      // type of load command
            cmd_size: u32, // total size of the command in bytes
        }

        /*
         * The 64-bit segment load command indicates that a part of this file is to be
         * mapped into a 64-bit task's address space.  If the 64-bit segment has
         * sections then section_64 structures directly follow the 64-bit segment
         * command and their size is reflected in cmdsize.
         */
        #[repr(C)]
        struct SegmentCommand64 {
            cmd: u32,      // type of load command
            cmd_size: u32, // total size of the command in bytes
            segment_name: [u8; 16],
            vm_addr: u64,      // memory address the segment is mapped to
            vm_size: u64,      // total size of the segment
            file_off: u64,     // file offset of the segment
            file_size: u64,    // amount mapped from the file
            max_prot: i32,     // maximum VM protection
            init_prot: i32,    // initial VM protection
            num_sections: u32, // number of sections in the segment
            flags: u32,
        }

        /*
         * Dynamicly linked shared libraries are identified by two things.  The
         * pathname (the name of the library as found for execution), and the
         * compatibility version number.  The pathname must match and the compatibility
         * number in the user of the library must be greater than or equal to the
         * library being used.  The time stamp is used to record the time a library was
         * built and copied into user so it can be use to determined if the library used
         * at runtime is exactly the same as used to built the program.
         */
        #[repr(C)]
        struct Dylib {
            name: u32,                  // offset from the load command start to the pathname
            timestamp: u32,             // library's build time stamp
            current_version: u32,       // library's current version number
            compatibility_version: u32, // library's compatibility vers number
        }

        /*
         * A dynamically linked shared library (filetype == MH_DYLIB in the mach header)
         * contains a dylib_command (cmd == LC_ID_DYLIB) to identify the library.
         * An object that uses a dynamically linked shared library also contains a
         * dylib_command (cmd == LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB, or
         * LC_REEXPORT_DYLIB) for each library it uses.
         */
        #[repr(C)]
        struct DylibCommand {
            cmd: u32,      // type of load command
            cmd_size: u32, // total size of the command in bytes, including pathname string
            dylib: Dylib,  // library identification
        }

        /*
         * The uuid load command contains a single 128-bit unique random number that
         * identifies an object produced by the static link editor.
         */
        #[repr(C)]
        struct UuidCommand {
            cmd: u32,      // type of load command
            cmd_size: u32, // total size of the command in bytes
            uuid: [u8; 16],
        }

        let mach_header_buf =
            self.read_task_memory(image.load_address, std::mem::size_of::<MachHeader>())?;

        let header: &MachHeader = &*(mach_header_buf.cast());

        //let header_size = std::mem::size_of::<MachHeader>() + header.size_commands;

        if header.magic != MH_MAGIC_64 {
            return Err(WriterError::InvalidMachHeader);
        }

        // Read the load commands which immediately follow the image header from
        // the task memory
        let load_commands_buf = self.read_task_memory(
            image.load_address + std::mem::size_of::<MachHeader>() as u64,
            header.size_commands,
        )?;

        // Loads commands vary in size depending on the actual type, so we have
        // to manually update the pointer offset rather than just stuffing the
        // buffer into a slice
        let mut next_header = load_commands.buf.as_ptr();

        struct ImageSizes {
            vm_addr: u64,
            vm_size: u64,
            slide: isize,
        }

        let mut image_sizes = None;
        let mut image_version = None;
        let mut image_uuid = None;

        // TODO: pullout the load command parsing to its own function for testing
        for i in 0..header.num_commands {
            let header = &*(next_header.cast::<LoadCommand>());

            if image_sizes.is_none() && header.cmd == LC_SEGMENT_64 {
                let seg: &SegmentCommand64 = &*(next_header.cast());

                if seg.segment_name[..7] == b"__TEXT\0" {
                    let slide = if seg.file_off == 0 && seg.file_size != 0 {
                        image.load_address - seg.vm_addr
                    } else {
                        0
                    };

                    image_sizes = Some(ImageSizes {
                        vm_addr: seg.vm_addr,
                        vm_size: seg.vm_size,
                        slide,
                    });
                }
            }

            if image_version.is_none() && header.cmd == LC_ID_DYLIB {
                let seg: &DylibComand = &*(next_header.cast());

                image_version = Some(seg.current_version);
            }

            if image_uuid.is_none() && header.cmd == LC_UUID {
                let seg: &UuidComand = &*(next_header.cast());
                image_uuid = Some(seg.uuid);
            }

            if image_sizes.is_some() && image_version.is_some() {
                break;
            }

            next_header = next_header.offset(header.cmd_size as isize);
        }

        let image_sizes = image_sizes.ok_or_else(|| WriterError::InvalidMachHeader)?;

        let file_path = if image.file_path != 0 {
            self.read_string(image.file_path)?.unwrap_or_default()
        } else {
            String::new()
        };

        let module_name = write_string_to_location(buf, &file_path)?;

        let mut raw_module = MDRawModule {
            base_of_image: image_sizes.vm_addr + image_sizes.slide,
            size_of_image: image_sizes.vm_size as u32,
            module_name_rva: module_name.rva,
            ..Default::default()
        };

        // Version info is not available for the main executable image since
        // it doesn't have a LC_ID_DYLIB load command
        if let Some(version) = image_version {
            raw_module.version_info.signature = format::VS_FFI_SIGNATURE;
            raw_module.version_info.struct_version = format::VS_FFI_STRUCVERSION;

            // Convert MAC dylib version format, which is a 32 bit number, to the
            // format used by minidump.  The mac format is <16 bits>.<8 bits>.<8 bits>
            // so it fits nicely into the windows version with some massaging
            // The mapping is:
            //    1) upper 16 bits of MAC version go to lower 16 bits of product HI
            //    2) Next most significant 8 bits go to upper 16 bits of product LO
            //    3) Least significant 8 bits go to lower 16 bits of product LO
            raw_module.version_info.file_version_hi = version >> 16;
            raw_module.version_info.file_version_lo = ((version & 0xff00) << 8) | (version & 0xff);
        }

        // TODO: write CV record
    }

    /// Reads a null terminated string starting at the specified address from
    /// the crashing tasks' memory.
    ///
    /// This string is capped at 8k which should never be close to being hit as
    /// it is only used for file paths for loaded modules, but then again, this
    /// is MacOS, so who knows what insanity goes on.
    fn read_string(&self, addr: u64) -> Result<Option<String>, WriterError> {
        // The problem is we don't know how much to read until we know how long
        // the string is. And we don't know how long the string is, until we've read
        // the memory!  So, we'll try to read kMaxStringLength bytes
        // (or as many bytes as we can until we reach the end of the vm region).
        let get_region_size = || {
            let region = self.get_vm_region(addr)?;

            let mut size_to_end = region.range.end - addr;

            // If the remaining is less than 4k, check if the next region is
            // contiguous, and extend the memory that could contain the string
            // to include it
            if size_to_end < 4 * 1024 {
                let maybe_adjacent = self.get_vm_region(region.range.end)?;

                if maybe_adjacent.range.start == region.range.end {
                    size_to_end += maybe_adjacent.range.end - maybe_adjacent.range.start;
                }
            }

            Ok(size_to_end)
        };

        if let Ok(size_to_end) = get_region_size() {
            let mut bytes = self.read_task_memory(addr, size_to_end)?;

            // Find the null terminator and truncate our string
            if let Some(null_pos) = bytes.iter().position(|c| c == 0) {
                bytes.resize(null_pos, 0);
            }

            String::from_utf8(bytes).map(Some)?
        } else {
            Ok(None)
        }
    }
}
