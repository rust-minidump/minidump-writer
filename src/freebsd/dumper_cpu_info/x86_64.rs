use {super::CpuInfoError, crate::minidump_format::*, std::io};

type Result<T> = std::result::Result<T, CpuInfoError>;

pub fn write_cpu_information(sys_info: &mut MDRawSystemInfo) -> Result<()> {
    sys_info.processor_architecture = MDCPUArchitecture::PROCESSOR_ARCHITECTURE_AMD64 as u16;

    // `MDRawSystemInfo` only has a u8 slot; systems with more than 255
    // CPUs (HPC boxes) report the maximum.
    sys_info.number_of_processors = u8::try_from(read_hw_ncpu()?).unwrap_or(u8::MAX);

    let cpu_model = read_hw_model()?;
    let (vendor_id, family, model, stepping) = parse_cpu_model(&cpu_model);

    if !vendor_id.is_empty() {
        // `cpu.data` only holds three u32s.
        let vendor_id =
            &vendor_id.as_bytes()[..vendor_id.len().min(3 * std::mem::size_of::<u32>())];
        sys_info.cpu.data[..vendor_id.len()].copy_from_slice(vendor_id);
    }

    sys_info.processor_level = family as u16;
    sys_info.processor_revision = ((model << 8) | stepping) as u16;

    Ok(())
}

/// `sysctl(hw.ncpu)`
fn read_hw_ncpu() -> Result<i32> {
    let mib = [libc::CTL_HW, libc::HW_NCPU];
    let mut ncpu: i32 = 0;
    let mut len = std::mem::size_of::<i32>() as libc::size_t;

    // SAFETY: the out-pointer and size describe a valid `i32` slot.
    if unsafe {
        libc::sysctl(
            mib.as_ptr(),
            mib.len() as libc::c_uint,
            &mut ncpu as *mut i32 as *mut libc::c_void,
            &mut len,
            std::ptr::null(),
            0,
        )
    } != 0
    {
        return Err(CpuInfoError::ReadError(io::Error::last_os_error()));
    }

    Ok(ncpu)
}

/// `sysctl(hw.model)`, the human-readable CPU description.
fn read_hw_model() -> Result<String> {
    let mib = [libc::CTL_HW, libc::HW_MODEL];
    let mut len = 0;

    // SAFETY: the size-query call only writes `len`.
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
    }

    if len == 0 {
        return Ok(String::from("Unknown"));
    }

    // hw.model is a NUL-terminated string.
    let mut buffer = vec![0u8; len];
    // SAFETY: the buffer has the size reported by the kernel.
    if unsafe {
        libc::sysctl(
            mib.as_ptr(),
            mib.len() as libc::c_uint,
            buffer.as_mut_ptr() as *mut libc::c_void,
            &mut len,
            std::ptr::null(),
            0,
        )
    } != 0
    {
        return Err(CpuInfoError::ReadError(io::Error::last_os_error()));
    }

    let len = buffer.iter().position(|&b| b == 0).unwrap_or(len);
    buffer.truncate(len);

    String::from_utf8(buffer).map_err(|_| CpuInfoError::ParseError)
}

/// Maps the `hw.model` description to a CPUID vendor string, and reads
/// family/model/stepping from the CPUID instruction.
fn parse_cpu_model(model: &str) -> (&'static str, u32, u32, u32) {
    const VENDORS: &[(&str, &str)] = &[
        ("intel", "GenuineIntel"),
        ("amd", "AuthenticAMD"),
        ("hygon", "HygonGenuine"),
        ("centaur", "CentaurHauls"),
        ("via", "CentaurHauls"),
        ("zhaoxin", "Shanghai"),
    ];

    let model_lower = model.to_lowercase();
    let vendor = VENDORS
        .iter()
        .find_map(|(needle, vendor)| model_lower.contains(needle).then_some(*vendor))
        .unwrap_or("");

    (vendor, family(), model_number(), stepping())
}

fn cpuid1_eax() -> u32 {
    // CPUID leaf 1 only reads processor identification data.
    // (`__cpuid` became a safe intrinsic in newer rustc versions; the
    // unsafe block keeps this compiling on the MSRV.)
    use std::arch::x86_64::__cpuid;
    #[allow(unused_unsafe)]
    unsafe {
        __cpuid(1).eax
    }
}

fn stepping() -> u32 {
    cpuid1_eax() & 0xF
}

fn model_number() -> u32 {
    let eax = cpuid1_eax();
    let model = (eax >> 4) & 0xF;
    let family = (eax >> 8) & 0xF;
    let ext_model = (eax >> 16) & 0xF;

    if family == 0xF || family == 0x6 {
        (ext_model << 4) + model
    } else {
        model
    }
}

fn family() -> u32 {
    let eax = cpuid1_eax();
    let family = (eax >> 8) & 0xF;
    let ext_family = (eax >> 20) & 0xFF;

    if family == 0xF {
        ext_family + family
    } else {
        family
    }
}
