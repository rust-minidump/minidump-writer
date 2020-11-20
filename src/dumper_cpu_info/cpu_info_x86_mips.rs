use crate::minidump_format::*;
use crate::Result;
use std::io::{BufRead, BufReader};
use std::path;

struct CpuInfoEntry {
    info_name: &'static str,
    value: i32,
    found: bool,
}

impl CpuInfoEntry {
    fn new(info_name: &'static str, value: i32, found: bool) -> Self {
        CpuInfoEntry {
            info_name,
            value,
            found,
        }
    }
}

pub fn write_cpu_information(sys_info: &mut MDRawSystemInfo) -> Result<()> {
    let vendor_id_name = "vendor_id";
    let cpu_info_table = [
        CpuInfoEntry::new("processor", -1, false),
        #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
        CpuInfoEntry::new("model", 0, false),
        #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
        CpuInfoEntry::new("stepping", 0, false),
        #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
        CpuInfoEntry::new("cpu family", 0, false),
    ];

    // processor_architecture should always be set, do this first
    if cfg!(target_arch = "mips") {
        sys_info.processor_architecture = MDCPUArchitecture::Mips as u16;
    } else if cfg!(target_arch = "mips64") {
        sys_info.processor_architecture = MDCPUArchitecture::Mips64 as u16;
    } else if cfg!(target_arch = "x86") {
        sys_info.processor_architecture = MDCPUArchitecture::X86 as u16;
    } else {
        sys_info.processor_architecture = MDCPUArchitecture::Amd64 as u16;
    }

    let cpuinfo_file = std::fs::File::open(path::PathBuf::from("/proc/cpuinfo"))?;

    for line in BufReader::new(cpuinfo_file).lines() {
        let line = line?;
    }
    Ok(())
}

//   bool WriteCPUInformation(MDRawSystemInfo* sys_info) {

//     const int fd = sys_open("/proc/cpuinfo", O_RDONLY, 0);
//     if (fd < 0)
//       return false;

//     {
//       PageAllocator allocator;
//       ProcCpuInfoReader* const reader = new(allocator) ProcCpuInfoReader(fd);
//       const char* field;
//       while (reader->GetNextField(&field)) {
//         bool is_first_entry = true;
//         for (CpuInfoEntry& entry : cpu_info_table) {
//           if (!is_first_entry && entry.found) {
//             // except for the 'processor' field, ignore repeated values.
//             continue;
//           }
//           is_first_entry = false;
//           if (!my_strcmp(field, entry.info_name)) {
//             size_t value_len;
//             const char* value = reader->GetValueAndLen(&value_len);
//             if (value_len == 0)
//               continue;

//             uintptr_t val;
//             if (my_read_decimal_ptr(&val, value) == value)
//               continue;

//             entry.value = static_cast<int>(val);
//             entry.found = true;
//           }
//         }

//         // special case for vendor_id
//         if (!my_strcmp(field, vendor_id_name)) {
//           size_t value_len;
//           const char* value = reader->GetValueAndLen(&value_len);
//           if (value_len > 0)
//             my_strlcpy(vendor_id, value, sizeof(vendor_id));
//         }
//       }
//       sys_close(fd);
//     }

//     // make sure we got everything we wanted
//     for (const CpuInfoEntry& entry : cpu_info_table) {
//       if (!entry.found) {
//         return false;
//       }
//     }
//     // cpu_info_table[0] holds the last cpu id listed in /proc/cpuinfo,
//     // assuming this is the highest id, change it to the number of CPUs
//     // by adding one.
//     cpu_info_table[0].value++;

//     sys_info->number_of_processors = cpu_info_table[0].value;
// #if defined(__i386__) || defined(__x86_64__)
//     sys_info->processor_level      = cpu_info_table[3].value;
//     sys_info->processor_revision   = cpu_info_table[1].value << 8 |
//                                      cpu_info_table[2].value;
// #endif

//     if (vendor_id[0] != '\0') {
//       my_memcpy(sys_info->cpu.x86_cpu_info.vendor_id, vendor_id,
//                 sizeof(sys_info->cpu.x86_cpu_info.vendor_id));
//     }
//     return true;
//   }
