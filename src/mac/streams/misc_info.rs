use super::*;
use format::{MiscInfoFlags, MINIDUMP_MISC_INFO_2 as MDRawMiscInfo};
use std::{ffi::c_void, time::Duration};

#[repr(C)]
#[derive(Copy, Clone)]
struct TimeValue {
    seconds: i32,
    microseconds: i32,
}

impl From<TimeValue> for Duration {
    fn from(tv: TimeValue) -> Self {
        let mut seconds = tv.seconds as u64;
        let mut microseconds = tv.microseconds as u32;
        // This _probably_ will never happen, but this will avoid a panic in
        // Duration::new() if it does
        if tv.microseconds >= 1000000 {
            seconds += 1;
            microseconds -= 1000000;
        }

        Duration::new(seconds, microseconds * 1000)
    }
}

#[repr(C)]
struct MachTaskBasicInfo {
    virtual_size: usize,      // virtual memory size in bytes
    resident_size: usize,     // resident memory size in bytes
    resident_size_max: usize, // maximum resident memory size in bytes
    user_time: TimeValue,     // total user run time for terminated threads
    system_time: TimeValue,   // total system run time for terminated threads
    policy: i32,              // default policy for new threads
    suspend_count: i32,       // suspend count for task
}

impl mach::TaskInfo for MachTaskBasicInfo {
    const FLAVOR: u32 = mach::task_info::MACH_TASK_BASIC_INFO;
}

#[repr(C)]
struct TaskThreadsTimeInfo {
    user_time: TimeValue,   // total user run time for live threads
    system_time: TimeValue, // total system run time for live threads
}

impl mach::TaskInfo for TaskThreadsTimeInfo {
    const FLAVOR: u32 = mach::task_info::TASK_THREAD_TIMES_INFO;
}

impl MinidumpWriter {
    pub(crate) fn write_misc_info(
        &mut self,
        buffer: &mut DumpBuf,
        dumper: &TaskDumper,
    ) -> Result<MDRawDirectory, WriterError> {
        let mut info_section = MemoryWriter::<MDRawMiscInfo>::alloc(buffer)?;
        let dirent = MDRawDirectory {
            stream_type: MDStreamType::MiscInfoStream as u32,
            location: info_section.location(),
        };

        let pid = dumper.pid_for_task()?;

        let mut misc_info = MDRawMiscInfo {
            size_of_info: std::mem::size_of::<MDRawMiscInfo>() as u32,
            flags1: MiscInfoFlags::MINIDUMP_MISC1_PROCESS_ID.bits()
                | MiscInfoFlags::MINIDUMP_MISC1_PROCESS_TIMES.bits()
                | MiscInfoFlags::MINIDUMP_MISC1_PROCESSOR_POWER_INFO.bits(),
            process_id: pid as u32,
            process_create_time: 0,
            process_user_time: 0,
            process_kernel_time: 0,
            processor_max_mhz: 0,
            processor_current_mhz: 0,
            processor_mhz_limit: 0,
            processor_max_idle_state: 0,
            processor_current_idle_state: 0,
        };

        // Note that Breakpad is using `getrusage` to get process times, but that
        // can only get resource usage for the current process and/or children,
        // but since we're (most likely) running in a different process than the
        // one that has crashed, we instead use `proc_pidinfo` which allows us to
        // to retrieve the process time of the actual crashed process. Note that
        // this is _also_ different from how Crashpad retrieves the process times,
        // it uses sysctl with `CTL_KERN, KERN_PROC, KERN_PROC_PID`, however
        // the structs that are filled out by that for this info are not available
        // in libc, and frankly `proc_pidinfo` was better documented (well, relatively,
        // all Apple documentation is terrible)
        //
        // SAFETY: syscall
        misc_info.process_create_time = unsafe {
            let pid = dbg!(dumper.pid_for_task())?;

            // Breakpad was using an old method to retrieve this, let's try the
            // BSD method instead which is already implemented in libc
            let mut proc_info = std::mem::MaybeUninit::<libc::proc_bsdinfo>::uninit();
            let size = dbg!(std::mem::size_of::<libc::proc_bsdinfo>() as i32);
            if dbg!(
                libc::proc_pidinfo(
                    pid,
                    libc::PROC_PIDTBSDINFO,
                    0,
                    proc_info.as_mut_ptr().cast(),
                    size,
                ) == size
            ) {
                let proc_info = proc_info.assume_init();

                dbg!(proc_info.pbi_start_tvsec) as u32
            } else {
                0
            }
        };

        // The basic task info keeps the timings for all of the terminated threads
        let basic_info = dumper.task_info::<MachTaskBasicInfo>().ok();

        // THe thread times info keeps the timings for all of the living threads
        let thread_times_info = dumper.task_info::<TaskThreadsTimeInfo>().ok();

        let user_time = basic_info
            .as_ref()
            .map(|bi| Duration::from(bi.user_time))
            .unwrap_or_default()
            + thread_times_info
                .as_ref()
                .map(|tt| Duration::from(tt.user_time))
                .unwrap_or_default();
        let system_time = basic_info
            .as_ref()
            .map(|bi| Duration::from(bi.system_time))
            .unwrap_or_default()
            + thread_times_info
                .as_ref()
                .map(|tt| Duration::from(tt.system_time))
                .unwrap_or_default();

        misc_info.process_user_time = user_time.as_secs() as u32;
        misc_info.process_kernel_time = system_time.as_secs() as u32;

        // Note that neither of these two keys are present on aarch64, at least atm
        let max: u64 = mach::sysctl_by_name(b"hw.cpufrequency_max\0");
        let freq: u64 = mach::sysctl_by_name(b"hw.cpufrequency\0");

        let max = (max / 1000 * 1000) as u32;
        let current = (freq / 1000 * 1000) as u32;

        misc_info.processor_max_mhz = max;
        misc_info.processor_mhz_limit = max;
        misc_info.processor_current_mhz = current;

        info_section.set_value(buffer, misc_info)?;

        Ok(dirent)
    }
}
