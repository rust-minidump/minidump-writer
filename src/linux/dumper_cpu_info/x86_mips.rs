use crate::errors::CpuInfoError;
use crate::minidump_format::*;
use std::io::{BufRead, BufReader};
use std::path;

type Result<T> = std::result::Result<T, CpuInfoError>;

pub fn write_cpu_information(sys_info: &mut MDRawSystemInfo) -> Result<()> {
    // processor_architecture should always be set, do this first
    sys_info.processor_architecture = if cfg!(target_arch = "mips") {
        MDCPUArchitecture::PROCESSOR_ARCHITECTURE_MIPS
    } else if cfg!(target_arch = "mips64") {
        MDCPUArchitecture::PROCESSOR_ARCHITECTURE_MIPS64
    } else if cfg!(target_arch = "x86") {
        MDCPUArchitecture::PROCESSOR_ARCHITECTURE_INTEL
    } else {
        MDCPUArchitecture::PROCESSOR_ARCHITECTURE_AMD64
    } as u16;

    let cpuinfo_file = std::fs::File::open(path::PathBuf::from("/proc/cpuinfo"))?;

    let mut processor = None;
    // x86/_64 specific
    let mut vendor_id = None;
    let mut model = None;
    let mut stepping = None;
    let mut family = None;
    //

    for line in BufReader::new(cpuinfo_file).lines() {
        let line = line?;
        // Expected format: <field-name> <space>+ ':' <space> <value>
        // Note that:
        //   - empty lines happen.
        //   - <field-name> can contain spaces.
        //   - some fields have an empty <value>
        if line.trim().is_empty() {
            continue;
        }

        let mut liter = line.split(':').map(|x| x.trim());
        let field = liter.next().unwrap(); // guaranteed to have at least one item
        let value = if let Some(val) = liter.next() {
            val
        } else {
            continue;
        };

        let entry = match field {
            "processor" => &mut processor,
            "model" => &mut model,
            "stepping" => &mut stepping,
            "cpu family" => &mut family,
            "vendor_id" => {
                if vendor_id.is_none() && !value.is_empty() {
                    vendor_id = Some(value.to_owned());
                }
                continue;
            }
            _ => continue,
        };

        if entry.is_some() && field != "processor" {
            continue;
        }

        if let Ok(v) = value.parse::<i32>() {
            *entry = Some(v);
        }
    }

    // This holds the highest processor id which start from 0 so add 1 to get the actual count
    // This field is only a u8 which means it will not work great in high (artificially or otherwise)
    // contexts
    sys_info.number_of_processors = std::cmp::max(
        (processor.ok_or(CpuInfoError::NotAllProcEntriesFound)? + 1) as u8,
        u8::MAX,
    );

    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    {
        sys_info.processor_level = family.ok_or(CpuInfoError::NotAllProcEntriesFound)? as u16;
        sys_info.processor_revision = (model.ok_or(CpuInfoError::NotAllProcEntriesFound)? << 8
            | stepping.ok_or(CpuInfoError::NotAllProcEntriesFound)?)
            as u16;

        if let Some(vendor_id) = vendor_id {
            let mut slice = vendor_id.as_bytes();

            // SAFETY: CPU_INFORMATION is a block of bytes, which is actually
            // a union, including the X86 information that we actually want to
            // set
            let cpu_info: &mut MDCPUInformation =
                unsafe { &mut *sys_info.cpu.data.as_mut_ptr().cast() };

            for id_part in cpu_info.vendor_id.iter_mut() {
                let (int_bytes, rest) = slice.split_at(std::mem::size_of::<u32>());
                slice = rest;
                *id_part = match int_bytes.try_into() {
                    Ok(x) => u32::from_ne_bytes(x),
                    Err(_) => {
                        continue;
                    }
                };
            }
        }
    }

    Ok(())
}
