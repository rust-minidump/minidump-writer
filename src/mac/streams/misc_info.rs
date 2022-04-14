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

#[repr(C)]
struct VmSpace {
    dummy: i32,
    dummy2: *const u8,
    dummy3: [i32; 5],
    dummy4: [*const u8; 3],
}

#[repr(C)]
struct ExternProc {
    starttime: libc::timeval, // process start time, actually a union, but that's an implementation detail
    vmspace: *const VmSpace,  // Address space
    sigacts: *const u8,       // Signal actions, state (PROC ONLY)
    flag: i32,                // P_* flags
    stat: i8,                 // S* process status
    pid: libc::pid_t,         // pid
    oppid: libc::pid_t,       // save parent pid during ptrace
    dupfd: i32,               // sideways return value from fdopen
    /* Mach related  */
    user_stack: *const u8,      // where user stack was allocated,
    exit_thread: *const c_void, // Which thread is exiting?
    debugger: i32,              // allow to debug
    sigwait: i32,               // indication to suspend
    /* scheduling */
    estcpu: u32,                // time averaged value of cpticks
    cpticks: i32,               // tick of cpu time
    pctcpu: u32,                // %cpu for this process during swtime
    wchan: *const c_void,       // sleep address
    wmesg: *const i8,           // reason for sleep
    swtime: u32,                // time swapped in or out
    slptime: u32,               // time since last blocked
    realtimer: libc::itimerval, // alarm timer
    rtime: libc::timeval,       // real time
    uticks: u64,                // statclock hits in user mode
    sticks: u64,                // statclock hits in system mode
    iticks: u64,                // statclock hits processing intr
    traceflag: i32,             // kernel trace points
    tracep: *const c_void,      // trace to vnode
    siglist: i32,               // DEPRECATED
    textvp: *const c_void,      // vnode of executable
    holdcnt: i32,               // if non-zero, don't swap
    sigmask: libc::sigset_t,    // DEPRECATED
    sigignore: libc::sigset_t,  // signals being ignored
    sigcatch: libc::sigset_t,   // signals being caught by user
    priority: u8,               // process priority
    usrpri: u8,                 // user-priority based on cpu and nice
    nice: i8,                   // process "nice" value
    comm: [i8; 16 /*MAXCOMLEN*/ + 1],
    pgrp: *const c_void, // pointer to process group
    addr: *const c_void, // kernel virtual addr of u-area (PROC ONLY)
    xstat: u16,          // exit status for wait; also stop signal
    acflag: u16,         // accounting flags
    ru: *const c_void,   // exit information
}

#[repr(C)]
struct Pcred {
    pc_lock: [i8; 72],       // opaque content
    pc_ucred: *const c_void, // current credentials
    ruid: libc::uid_t,       // real user id
    svuid: libc::uid_t,      // saved effective user id
    rgid: libc::gid_t,       // real group id
    svgid: libc::gid_t,      // saved effective group id
    refcnt: i32,             // number of references
}

#[repr(C)]
struct Ucred {
    refcnt: i32,      // reference count
    uid: libc::uid_t, // effective user id
    ngroups: i16,     // number of groups
    groups: [libc::gid_t; 16],
}

#[repr(C)]
struct EProc {
    paddr: *const c_void, // address of proc
    sess: *const c_void,  // session pointer
    pcred: Pcred,         // process credentials
    ucred: Ucred,         // current credentials
    vm: VmSpace,          // address space
    ppid: libc::pid_t,    // parent process id
    pgid: libc::gid_t,    // process group id
    jobc: i16,            // job control counter
    tdev: i32,            // controlling tty dev
    tpgid: libc::gid_t,   // tty process group id
    tsess: *const c_void, // tty session pointer
    wmesg: [i8; 8],       // wchan message
    xsize: i32,           // text size
    xrssize: i16,         // text rss
    xccount: i16,         // text references
    xswrss: i16,
    flag: i32,
    login: [i8; 12], // short setlogin() name
    spare: [i32; 4],
}

#[repr(C)]
struct KInfoProc {
    kp_proc: ExternProc,
    kp_eproc: EProc,
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
        // one that has crashed, we instead use the same method that Crashpad
        // uses to get the information for the actual crashed process which is
        // far more interesting and relevant
        //
        // SAFETY: syscall
        misc_info.process_create_time = unsafe {
            let pid = dumper.pid_for_task()?;

            // Breakpad was using an old method to retrieve this, let's try the
            // BSD method instead which is already implemented in libc
            let mut proc_info = std::mem::MaybeUninit::<libc::proc_bsdinfo>::uninit();
            let size = std::mem::size_of::<libc::proc_bsdinfo>() as i32;
            if libc::proc_pidinfo(
                pid,
                libc::PROC_PIDTBSDINFO,
                0,
                proc_info.as_mut_ptr().cast(),
                size,
            ) == size
            {
                let proc_info = proc_info.assume_init();

                proc_info.pbi_start_tvsec as u32
            } else {
                0
            }

            // let mut mib = [libc::CTL_KERN, libc::KERN_PROC, libc::KERN_PROC_PID, pid];
            // let mut kinfo_proc = std::mem::MaybeUninit::<KInfoProc>::zeroed();
            // let mut len = std::mem::size_of::<KInfoProc>();

            // if libc::sysctl(
            //     mib.as_mut_ptr().cast(),
            //     std::mem::size_of_val(&mib) as u32,
            //     kinfo_proc.as_mut_ptr().cast(),
            //     &mut len,
            // ) != 0
            // {
            //     return Err(std::io::Error::last_os_error().into());
            // }

            // let kinfo_proc = kinfo_proc.assume_init();

            // // This sysctl does not return an error if the pid was not found. 10.9.5
            // // xnu-2422.115.4/bsd/kern/kern_sysctl.c sysctl_prochandle() calls
            // // xnu-2422.115.4/bsd/kern/kern_proc.c proc_iterate(), which provides no
            // // indication of whether anything was done. To catch this, check that the PID
            // // actually matches the one that we requested
            // if kinfo_proc.kp_proc.p_pid != pid {
            //     0
            // } else {
            //     kinfo_proc.kp_proc.starttime.tv_sec as u32
            // }
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
