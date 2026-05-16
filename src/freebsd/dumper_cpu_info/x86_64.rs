use {super::CpuInfoError, crate::minidump_format::*, std::io};

type Result<T> = std::result::Result<T, CpuInfoError>;

pub fn write_cpu_information(sys_info: &mut MDRawSystemInfo) -> Result<()> {
    sys_info.processor_architecture = if cfg!(target_arch = "x86") {
        MDCPUArchitecture::PROCESSOR_ARCHITECTURE_INTEL
    } else {
        MDCPUArchitecture::PROCESSOR_ARCHITECTURE_AMD64
    } as u16;

    let cpu_count = read_hw_ncpu()?;
    let cpu_model = read_hw_model()?;

    sys_info.number_of_processors = cpu_count as u8;

    let (vendor_id, family, model, stepping) = parse_cpu_model(&cpu_model);

    if !vendor_id.is_empty() {
        let vendor_id = vendor_id.as_bytes();
        let vendor_len = std::cmp::min(3 * std::mem::size_of::<u32>(), vendor_id.len());
        sys_info.cpu.data[..vendor_len].copy_from_slice(&vendor_id[..vendor_len]);
    }

    sys_info.processor_level = family as u16;
    sys_info.processor_revision = ((model << 8) | stepping) as u16;

    Ok(())
}

fn read_hw_ncpu() -> Result<i32> {
    let mib = [libc::CTL_HW, libc::HW_NCPU];
    let mut ncpu: i32 = 0;
    let mut len = std::mem::size_of::<i32>() as libc::size_t;

    unsafe {
        // SAFETY: sysctl is a well-defined kernel interface. We provide valid
        // pointers for mib, output buffer, and size. The kernel fills the
        // buffer and returns 0 on success, which we check.
        if libc::sysctl(
            mib.as_ptr(),
            mib.len() as libc::c_uint,
            &mut ncpu as *mut i32 as *mut libc::c_void,
            &mut len,
            std::ptr::null(),
            0,
        ) != 0
        {
            return Err(CpuInfoError::ReadError(io::Error::last_os_error()));
        }
    }

    Ok(ncpu)
}

fn read_hw_model() -> Result<String> {
    let mib = [libc::CTL_HW, libc::HW_MODEL];
    let mut len = 0;

    // SAFETY: sysctl is a well-defined kernel interface. First call gets the
    // required buffer size; second call fills the buffer. We check return values.
    unsafe {
        if libc::sysctl(
            mib.as_ptr(),
            mib.len() as libc::c_uint,
            std::ptr::null_mut(),
            &mut len,
            std::ptr::null(),
            0,
        ) != 0
        {
            return Err(CpuInfoError::ReadError(io::Error::last_os_error()));
        }

        if len == 0 {
            return Ok(String::from("Unknown"));
        }

        let mut buffer = vec![0u8; len];
        if libc::sysctl(
            mib.as_ptr(),
            mib.len() as libc::c_uint,
            buffer.as_mut_ptr() as *mut libc::c_void,
            &mut len,
            std::ptr::null(),
            0,
        ) != 0
        {
            return Err(CpuInfoError::ReadError(io::Error::last_os_error()));
        }

        buffer.truncate(len - 1);

        String::from_utf8(buffer).map_err(|_| CpuInfoError::ParseError)
    }
}

fn parse_cpu_model(model: &str) -> (String, u32, u32, u32) {
    let model_lower = model.to_lowercase();

    let vendor = if model_lower.contains("intel") {
        "GenuineIntel".to_string()
    } else if model_lower.contains("amd") {
        "AuthenticAMD".to_string()
    } else if model_lower.contains("hygon") {
        "HygonGenuine".to_string()
    } else if model_lower.contains("centaur") || model_lower.contains("via") {
        "CentaurHauls".to_string()
    } else if model_lower.contains("zhaoxin") {
        "Shanghai".to_string()
    } else {
        String::new()
    };

    let (family, model, stepping) = extract_cpu_stepping(model);

    (vendor, family, model, stepping)
}

fn extract_cpu_stepping(_model: &str) -> (u32, u32, u32) {
    // SAFETY: __cpuid is safe to call on any x86_64 CPU; it executes the
    // CPUID instruction which merely reads processor identification info.
    #[cfg(target_arch = "x86_64")]
    {
        use std::arch::x86_64::__cpuid;

        let result = __cpuid(1);
        let eax = result.eax;

        let stepping = eax & 0xF;
        let model = (eax >> 4) & 0xF;
        let family = (eax >> 8) & 0xF;
        let ext_model = (eax >> 16) & 0xF;
        let ext_family = (eax >> 20) & 0xFF;

        let display_family = if family == 0xF {
            ext_family + family
        } else {
            family
        };

        let display_model = if family == 0xF || family == 0x6 {
            (ext_model << 4) + model
        } else {
            model
        };

        (display_family, display_model, stepping)
    }

    // Fallback for architectures without CPUID (e.g. future aarch64 support).
    #[cfg(not(target_arch = "x86_64"))]
    {
        (0, 0, 0)
    }
}
