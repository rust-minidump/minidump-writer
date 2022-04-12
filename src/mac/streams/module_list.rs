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

impl MiniDumpWriter {
    fn write_module_list(&mut self, buffer: &mut DumpBuf) -> Result<MDRawDirectory, WriterError> {
        let modules = if let Some(all_images) = all_image_addr(self.crash_context.task) {

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

    fn read_loaded_images(&self, all_images_addr: u64) -> Result<Vec<>, WriterError> {
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

        // dyld_image_info
        #[repr(C)]
        struct ImageInfo {
            load_address: u64,
            file_path: u64,
            file_mod_date: u64,
        }

        // usr/include/mach-o/loader.h
        #[repr(C)]
        struct MachHeader {
            magic: u32, // mach magic number identifier
            cpu_type: i32, // cpu_type_t cpu specifier
            cpu_sub_type: i32, // cpu_subtype_t machine specifier
            file_type: u32, // type of file
            num_commands: u32, // number of load commands
            size_commands: u32, // size of all the load commands
            flags: u32,
            __reserved: u32,
        }

        // Here we make the assumption that dyld loaded at the same address in
        // the crashed process vs. this one.  This is an assumption made in
        // "dyld_debug.c" and is said to be nearly always valid.
        let dyld_all_info_buf = self.read_task_memory(all_images_addr, std::mem::size_of::<AllImagesInfo>())?;
        let dyld_info: &AllImagesInfo = &*(dyld_all_info_buf.cast());

        let dyld_info_buf = self.read_task_memory(dyld_info.info_array_addr, dyld_info.info_array_count * std::mem::size_of::<ImageInfo>())?;

        let all_images = unsafe {
            std::slice::from_raw_parts(dyld_info.buf.as_ptr().cast::<ImageInfo>(), dyld_info.info_array_count as usize)
        };
        
        let mut images = Vec::with_capacity(all_images.len();

        for image in all_images {
            let mach_header_buf = if let Ok(buf) = self.read_task_memory(image.load_address, std::mem::size_of::<MachHeader>()) {
                buf
            } else {
                continue;
            };

            let header: &MachHeader = &*(mach_header_buf.cast());
            //let header_size = std::mem::size_of::<MachHeader>() + header.size_commands;

            let file_path = if image.file_path != 0 {
            }
        }

    for (int i = 0; i < count; ++i) {
      dyld_image_info& info = infoArray[i];

      // First read just the mach_header from the image in the task.
      vector<uint8_t> mach_header_bytes;
      if (ReadTaskMemory(images.task_,
                         info.load_address_,
                         sizeof(mach_header_type),
                         mach_header_bytes) != KERN_SUCCESS)
        continue;  // bail on this dynamic image

      mach_header_type* header =
          reinterpret_cast<mach_header_type*>(&mach_header_bytes[0]);

      // Now determine the total amount necessary to read the header
      // plus all of the load commands.
      size_t header_size =
          sizeof(mach_header_type) + header->sizeofcmds;

      if (ReadTaskMemory(images.task_,
                         info.load_address_,
                         header_size,
                         mach_header_bytes) != KERN_SUCCESS)
        continue;

      // Read the file name from the task's memory space.
      string file_path;
      if (info.file_path_) {
        // Although we're reading kMaxStringLength bytes, it's copied in the
        // the DynamicImage constructor below with the correct string length,
        // so it's not really wasting memory.
        file_path = ReadTaskString(images.task_, info.file_path_);
      }

      // Create an object representing this image and add it to our list.
      DynamicImage* new_image;
      new_image = new DynamicImage(&mach_header_bytes[0],
                                   header_size,
                                   info.load_address_,
                                   file_path,
                                   static_cast<uintptr_t>(info.file_mod_date_),
                                   images.task_,
                                   images.cpu_type_);

      if (new_image->IsValid()) {
        images.image_list_.push_back(DynamicImageRef(new_image));
      } else {
        delete new_image;
      }
    }

    // sorts based on loading address
    sort(images.image_list_.begin(), images.image_list_.end());
    // remove duplicates - this happens in certain strange cases
    // You can see it in DashboardClient when Google Gadgets plugin
    // is installed.  Apple's crash reporter log and gdb "info shared"
    // both show the same library multiple times at the same address

    vector<DynamicImageRef>::iterator it = unique(images.image_list_.begin(),
                                                  images.image_list_.end());
    images.image_list_.erase(it, images.image_list_.end());
    }

    fn read_string(&self, addr: u64) -> Result<String, WriterError> {
        // The problem is we don't know how much to read until we know how long
        // the string is. And we don't know how long the string is, until we've read
        // the memory!  So, we'll try to read kMaxStringLength bytes
        // (or as many bytes as we can until we reach the end of the vm region).
        let size_to_end = {
            let mut region_base = addr;
            let mut region_size = 0;
            let mut nesting_level = 0;
        vm_region_submap_info_64 submap_info;
        mach_msg_type_number_t info_count = VM_REGION_SUBMAP_INFO_COUNT_64;
        
        // Get information about the vm region containing |address|
        vm_region_recurse_info_t region_info;
        region_info = reinterpret_cast<vm_region_recurse_info_t>(&submap_info);
        
        kern_return_t result =
        mach_vm_region_recurse(target_task,
        &region_base,
        &region_size,
        &nesting_level,
        region_info,
        &info_count);
        
        if (result == KERN_SUCCESS) {
        // Get distance from |address| to the end of this region
        *size_to_end = region_base + region_size -(mach_vm_address_t)address;
        
        // If we want to handle strings as long as 4096 characters we may need
        // to check if there's a vm region immediately following the first one.
        // If so, we need to extend |*size_to_end| to go all the way to the end
        // of the second region.
        if (*size_to_end < 4096) {
        // Second region starts where the first one ends
        mach_vm_address_t region_base2 =
        (mach_vm_address_t)(region_base + region_size);
        mach_vm_size_t region_size2;
        
        // Get information about the following vm region
        result =
        mach_vm_region_recurse(target_task,
        &region_base2,
        &region_size2,
        &nesting_level,
        region_info,
        &info_count);
        
        // Extend region_size to go all the way to the end of the 2nd region
        if (result == KERN_SUCCESS
        && region_base2 == region_base + region_size) {
        region_size += region_size2;
        }
        }
        
        *size_to_end = region_base + region_size -(mach_vm_address_t)address;
        } else {
        region_size = 0;
        *size_to_end = 0;
        }
        
        return region_size;
        };
        mach_vm_size_t size_to_end;
        GetMemoryRegionSize(target_task, address, &size_to_end);
        
        if (size_to_end > 0) {
        mach_vm_size_t size_to_read =
        size_to_end > kMaxStringLength ? kMaxStringLength : size_to_end;
        
        vector<uint8_t> bytes;
        if (ReadTaskMemory(target_task, address, (size_t)size_to_read, bytes) !=
        KERN_SUCCESS)
        return string();
        
            //==============================================================================
        // Returns the size of the memory region containing |address| and the
        // number of bytes from |address| to the end of the region.
        // We potentially, will extend the size of the original
        // region by the size of the following region if it's contiguous with the
        // first in order to handle cases when we're reading strings and they
        // straddle two vm regions.
        //
        static mach_vm_size_t GetMemoryRegionSize(task_port_t target_task,
            const uint64_t address,
            mach_vm_size_t* size_to_end) {
        
        }
        }
    }
}
