//! Contains various helpers to improve and expand on the bindings provided
//! by `mach2`

// Just exports all of the mach functions we use into a flat list
pub use mach2::{
    kern_return::{kern_return_t, KERN_SUCCESS},
    port::mach_port_name_t,
    task::{self, task_threads},
    task_info,
    thread_act::thread_get_state,
    traps::mach_task_self,
    vm::{mach_vm_deallocate, mach_vm_read, mach_vm_region_recurse},
    vm_region::vm_region_submap_info_64,
};

/// A Mach kernel error.
///
/// See <usr/include/mach/kern_return.h>.
#[derive(thiserror::Error, Debug)]
pub enum KernelError {
    #[error("specified address is not currently valid")]
    InvalidAddress = 1,
    #[error("specified memory is valid, but does not permit the required forms of access")]
    ProtectionFailure = 2,
    #[error("the address range specified is already in use, or no address range of the size specified could be found")]
    NoSpace = 3,
    #[error("the function requested was not applicable to this type of argument, or an argument is invalid")]
    InvalidArgument = 4,
    #[error("the function could not be performed")]
    Failure = 5,
    #[error("system resource could not be allocated to fulfill this request")]
    ResourceShortage = 6,
    #[error("the task in question does not hold receive rights for the port argument")]
    NotReceiver = 7,
    #[error("bogus access restriction")]
    NoAccess = 8,
    #[error(
        "during a page fault, the target address refers to a memory object that has been destroyed"
    )]
    MemoryFailure = 9,
    #[error(
        "during a page fault, the memory object indicated that the data could not be returned"
    )]
    MemoryError = 10,
    #[error("the receive right is already a member of the portset")]
    AlreadyInSet = 11,
    #[error("the receive right is not a member of a port set")]
    NotInSet = 12,
    #[error("the name already denotes a right in the task")]
    NameExists = 13,
    #[error("the operation was aborted")]
    Aborted = 14,
    #[error("the name doesn't denote a right in the task")]
    InvalidName = 15,
    #[error("target task isn't an active task")]
    InvalidTask = 16,
    #[error("the name denotes a right, but not an appropriate right")]
    InvalidRight = 17,
    #[error("a blatant range error")]
    InvalidValue = 18,
    #[error("operation would overflow limit on user-references")]
    UserRefsOverflow = 19,
    #[error("the supplied port capability is improper")]
    InvalidCapability = 20,
    #[error("the task already has send or receive rights for the port under another name")]
    RightExists = 21,
    #[error("target host isn't actually a host")]
    InvalidHost = 22,
    #[error("an attempt was made to supply 'precious' data for memory that is already present in a memory object")]
    MemoryPresent = 23,
    // These 2 are errors which should only ever be seen by the kernel itself
    //MemoryDataMoved = 24,
    //MemoryRestartCopy = 25,
    #[error("an argument applied to assert processor set privilege was not a processor set control port")]
    InvalidProcessorSet = 26,
    #[error("the specified scheduling attributes exceed the thread's limits")]
    PolicyLimit = 27,
    #[error("the specified scheduling policy is not currently enabled for the processor set")]
    InvalidPolicy = 28,
    #[error("the external memory manager failed to initialize the memory object")]
    InvalidObject = 29,
    #[error(
        "a thread is attempting to wait for an event for which there is already a waiting thread"
    )]
    AlreadyWaiting = 30,
    #[error("an attempt was made to destroy the default processor set")]
    DefaultSet = 31,
    #[error("an attempt was made to fetch an exception port that is protected, or to abort a thread while processing a protected exception")]
    ExceptionProtected = 32,
    #[error("a ledger was required but not supplied")]
    InvalidLedger = 33,
    #[error("the port was not a memory cache control port")]
    InvalidMemoryControl = 34,
    #[error("an argument supplied to assert security privilege was not a host security port")]
    InvalidSecurity = 35,
    #[error("thread_depress_abort was called on a thread which was not currently depressed")]
    NotDepressed = 36,
    #[error("object has been terminated and is no longer available")]
    Terminated = 37,
    #[error("lock set has been destroyed and is no longer available")]
    LockSetDestroyed = 38,
    #[error("the thread holding the lock terminated before releasing the lock")]
    LockUnstable = 39,
    #[error("the lock is already owned by another thread")]
    LockOwned = 40,
    #[error("the lock is already owned by the calling thread")]
    LockOwnedSelf = 41,
    #[error("semaphore has been destroyed and is no longer available")]
    SemaphoreDestroyed = 42,
    #[error("return from RPC indicating the target server was terminated before it successfully replied")]
    RpcServerTerminated = 43,
    #[error("terminate an orphaned activation")]
    RpcTerminateOrphan = 44,
    #[error("allow an orphaned activation to continue executing")]
    RpcContinueOrphan = 45,
    #[error("empty thread activation (No thread linked to it)")]
    NotSupported = 46,
    #[error("remote node down or inaccessible")]
    NodeDown = 47,
    #[error("a signalled thread was not actually waiting")]
    NotWaiting = 48,
    #[error("some thread-oriented operation (semaphore_wait) timed out")]
    OperationTimedOut = 49,
    #[error("during a page fault, indicates that the page was rejected as a result of a signature check")]
    CodesignError = 50,
    #[error("the requested property cannot be changed at this time")]
    PoicyStatic = 51,
    #[error("the provided buffer is of insufficient size for the requested data")]
    InsufficientBufferSize = 52,
    #[error("denied by security policy")]
    Denied = 53,
    #[error("the KC on which the function is operating is missing")]
    MissingKC = 54,
    #[error("the KC on which the function is operating is invalid")]
    InvalidKC = 55,
    #[error("a search or query operation did not return a result")]
    NotFound = 56,
}

impl From<mach2::kern_return::kern_return_t> for KernelError {
    fn from(kr: mach2::kern_return::kern_return_t) -> Self {
        use mach2::kern_return::*;

        match kr {
            KERN_INVALID_ADDRESS => Self::InvalidAddress,
            KERN_PROTECTION_FAILURE => Self::ProtectionFailure,
            KERN_NO_SPACE => Self::NoSpace,
            KERN_INVALID_ARGUMENT => Self::InvalidArgument,
            KERN_FAILURE => Self::Failure,
            KERN_RESOURCE_SHORTAGE => Self::ResourceShortage,
            KERN_NOT_RECEIVER => Self::NotReceiver,
            KERN_NO_ACCESS => Self::NoAccess,
            KERN_MEMORY_FAILURE => Self::MemoryFailure,
            KERN_MEMORY_ERROR => Self::MemoryError,
            KERN_ALREADY_IN_SET => Self::AlreadyInSet,
            KERN_NAME_EXISTS => Self::NameExists,
            KERN_INVALID_NAME => Self::InvalidName,
            KERN_INVALID_TASK => Self::InvalidTask,
            KERN_INVALID_RIGHT => Self::InvalidRight,
            KERN_INVALID_VALUE => Self::InvalidValue,
            KERN_UREFS_OVERFLOW => Self::UserRefsOverflow,
            KERN_INVALID_CAPABILITY => Self::InvalidCapability,
            KERN_RIGHT_EXISTS => Self::RightExists,
            KERN_INVALID_HOST => Self::InvalidHost,
            KERN_MEMORY_PRESENT => Self::MemoryPresent,
            KERN_INVALID_PROCESSOR_SET => Self::InvalidProcessorSet,
            KERN_POLICY_LIMIT => Self::PolicyLimit,
            KERN_INVALID_POLICY => Self::InvalidPolicy,
            KERN_INVALID_OBJECT => Self::InvalidObject,
            KERN_ALREADY_WAITING => Self::AlreadyWaiting,
            KERN_DEFAULT_SET => Self::DefaultSet,
            KERN_EXCEPTION_PROTECTED => Self::ExceptionProtected,
            KERN_INVALID_LEDGER => Self::InvalidLedger,
            KERN_INVALID_MEMORY_CONTROL => Self::InvalidMemoryControl,
            KERN_INVALID_SECURITY => Self::InvalidSecurity,
            KERN_NOT_DEPRESSED => Self::NotDepressed,
            KERN_TERMINATED => Self::Terminated,
            KERN_LOCK_SET_DESTROYED => Self::LockSetDestroyed,
            KERN_LOCK_UNSTABLE => Self::LockUnstable,
            KERN_LOCK_OWNED => Self::LockOwned,
            KERN_LOCK_OWNED_SELF => Self::LockOwnedSelf,
            KERN_SEMAPHORE_DESTROYED => Self::SemaphoreDestroyed,
            KERN_RPC_SERVER_TERMINATED => Self::RpcServerTerminated,
            KERN_RPC_TERMINATE_ORPHAN => Self::RpcTerminateOrphan,
            KERN_RPC_CONTINUE_ORPHAN => Self::RpcContinueOrphan,
            KERN_NOT_SUPPORTED => Self::NotSupported,
            KERN_NODE_DOWN => Self::NodeDown,
            KERN_NOT_WAITING => Self::NotWaiting,
            KERN_OPERATION_TIMED_OUT => Self::OperationTimedOut,
            KERN_CODESIGN_ERROR => Self::CodesignError,
            KERN_POLICY_STATIC => Self::PoicyStatic,
            52 => Self::InsufficientBufferSize,
            53 => Self::Denied,
            54 => Self::MissingKC,
            55 => Self::InvalidKC,
            56 => Self::NotFound,
            // This should never happen given a result from a mach call, but
            // in that case we just use `Failure` as the mach header itself
            // describes it as a catch all
            _ => Self::Failure,
        }
    }
}

// From /usr/include/mach/machine/thread_state.h
pub const THREAD_STATE_MAX: usize = 1296;

cfg_if::cfg_if! {
    if #[cfg(target_arch = "x86_64")] {
        /// x86_THREAD_STATE64 in /usr/include/mach/i386/thread_status.h
        pub const THREAD_STATE_FLAVOR: u32 = 4;

        pub type ArchThreadState = mach2::structs::x86_thread_state64_t;
    } else if #[cfg(target_arch = "aarch64")] {
        /// ARM_THREAD_STATE64 in /usr/include/mach/arm/thread_status.h
        pub const THREAD_STATE_FLAVOR: u32 = 6;

        // Missing from mach2 atm
        // _STRUCT_ARM_THREAD_STATE64 from /usr/include/mach/arm/_structs.h
        #[repr(C)]
        pub struct Arm64ThreadState {
            pub x: [u64; 29],
            pub fp: u64,
            pub lr: u64,
            pub sp: u64,
            pub pc: u64,
            pub cpsr: u32,
            __pad: u32,
        }

        pub type ArchThreadState = Arm64ThreadState;
    } else {
        compile_error!("unsupported target arch");
    }
}

pub struct ThreadState {
    pub state: [u32; THREAD_STATE_MAX],
    pub state_size: u32,
}

impl Default for ThreadState {
    fn default() -> Self {
        Self {
            state: [0u32; THREAD_STATE_MAX],
            state_size: (THREAD_STATE_MAX * std::mem::size_of::<u32>()) as u32,
        }
    }
}

impl ThreadState {
    /// Gets the program counter
    #[inline]
    pub fn pc(&self) -> u64 {
        cfg_if::cfg_if! {
            if #[cfg(target_arch = "x86_64")] {
                self.arch_state().__pc
            } else if #[cfg(target_arch = "aarch64")] {
                self.arch_state().pc
            }
        }
    }

    /// Gets the stack pointer
    #[inline]
    pub fn sp(&self) -> u64 {
        cfg_if::cfg_if! {
            if #[cfg(target_arch = "x86_64")] {
                self.arch_state().__sp
            } else if #[cfg(target_arch = "aarch64")] {
                self.arch_state().sp
            }
        }
    }

    /// Converts the raw binary blob into the architecture specific state
    #[inline]
    pub fn arch_state(&self) -> &ArchThreadState {
        // SAFETY: hoping the kernel isn't lying
        unsafe { &*(self.state.as_ptr().cast()) }
    }
}

/// Minimal trait that just pairs a structure that can be filled out by
/// [`mach2::task::task_info`] with the "flavor" that tells it the info we
/// actually want to retrieve
pub trait TaskInfo {
    /// One of the `MACH_*_TASK` integers. I assume it's very bad if you implement
    /// this trait and provide the wrong flavor for the struct
    const FLAVOR: u32;
}

// usr/include/mach-o/loader.h, the file type for the main executable image
const MH_EXECUTE: u32 = 0x2;
// usr/include/mach-o/loader.h, magic number for MachHeader
pub const MH_MAGIC_64: u32 = 0xfeedfacf;
// usr/include/mach-o/loader.h, command to map a segment
pub const LC_SEGMENT_64: u32 = 0x19;
// usr/include/mach-o/loader.h, dynamically linked shared lib ident
pub const LC_ID_DYLIB: u32 = 0xd;
// usr/include/mach-o/loader.h, the uuid
pub const LC_UUID: u32 = 0x1b;

// usr/include/mach-o/loader.h
#[repr(C)]
#[derive(Clone)]
pub struct MachHeader {
    pub magic: u32,         // mach magic number identifier
    pub cpu_type: i32,      // cpu_type_t cpu specifier
    pub cpu_sub_type: i32,  // cpu_subtype_t machine specifier
    pub file_type: u32,     // type of file
    pub num_commands: u32,  // number of load commands
    pub size_commands: u32, // size of all the load commands
    pub flags: u32,
    __reserved: u32,
}

// usr/include/mach-o/loader.h
#[repr(C)]
pub struct LoadCommandBase {
    pub cmd: u32,      // type of load command
    pub cmd_size: u32, // total size of the command in bytes
}

/*
 * The 64-bit segment load command indicates that a part of this file is to be
 * mapped into a 64-bit task's address space.  If the 64-bit segment has
 * sections then section_64 structures directly follow the 64-bit segment
 * command and their size is reflected in cmdsize.
 */
#[repr(C)]
pub struct SegmentCommand64 {
    cmd: u32,                   // type of load command
    cmd_size: u32,              // total size of the command in bytes
    pub segment_name: [u8; 16], // string name of the section
    pub vm_addr: u64,           // memory address the segment is mapped to
    pub vm_size: u64,           // total size of the segment
    pub file_off: u64,          // file offset of the segment
    pub file_size: u64,         // amount mapped from the file
    pub max_prot: i32,          // maximum VM protection
    pub init_prot: i32,         // initial VM protection
    pub num_sections: u32,      // number of sections in the segment
    pub flags: u32,
}

/*
 * Dynamically linked shared libraries are identified by two things.  The
 * pathname (the name of the library as found for execution), and the
 * compatibility version number.  The pathname must match and the compatibility
 * number in the user of the library must be greater than or equal to the
 * library being used.  The time stamp is used to record the time a library was
 * built and copied into user so it can be use to determined if the library used
 * at runtime is exactly the same as used to built the program.
 */
#[repr(C)]
pub struct Dylib {
    pub name: u32,                  // offset from the load command start to the pathname
    pub timestamp: u32,             // library's build time stamp
    pub current_version: u32,       // library's current version number
    pub compatibility_version: u32, // library's compatibility vers number
}

/*
 * A dynamically linked shared library (filetype == MH_DYLIB in the mach header)
 * contains a dylib_command (cmd == LC_ID_DYLIB) to identify the library.
 * An object that uses a dynamically linked shared library also contains a
 * dylib_command (cmd == LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB, or
 * LC_REEXPORT_DYLIB) for each library it uses.
 */
#[repr(C)]
pub struct DylibCommand {
    cmd: u32,         // type of load command
    cmd_size: u32,    // total size of the command in bytes, including pathname string
    pub dylib: Dylib, // library identification
}

/// The uuid load command contains a single 128-bit unique random number that
/// identifies an object produced by the static link editor.
#[repr(C)]
pub struct UuidCommand {
    cmd: u32,
    cmd_size: u32,
    pub uuid: [u8; 16],
}

/// A block of load commands for a particular image
pub struct LoadCommands {
    /// The block of memory containing all of the load commands
    pub buffer: Vec<u8>,
    /// The number of actual load commmands that _should_ be in the buffer
    pub count: u32,
}

impl LoadCommands {
    #[inline]
    pub fn iter(&self) -> LoadCommandsIter<'_> {
        LoadCommandsIter {
            buffer: &self.buffer,
            count: self.count,
        }
    }
}

pub enum LoadCommand<'buf> {
    Segment(&'buf SegmentCommand64),
    Dylib(&'buf DylibCommand),
    Uuid(&'buf UuidCommand),
}

pub struct LoadCommandsIter<'buf> {
    buffer: &'buf [u8],
    count: u32,
}

impl<'buf> Iterator for LoadCommandsIter<'buf> {
    type Item = LoadCommand<'buf>;

    fn next(&mut self) -> Option<Self::Item> {
        // SAFETY: we're interpreting raw bytes as C structs, we try and be safe
        unsafe {
            loop {
                if self.count == 0 || self.buffer.len() < std::mem::size_of::<LoadCommandBase>() {
                    return None;
                }

                let header = &*(self.buffer.as_ptr().cast::<LoadCommandBase>());

                // This would mean we've been lied to by the MachHeader and either
                // the size_commands field was too small, or the num_command was
                // too large
                if header.cmd_size as usize > self.buffer.len() {
                    return None;
                }

                let cmd = match header.cmd {
                    LC_SEGMENT_64 => Some(LoadCommand::Segment(
                        &*(self.buffer.as_ptr().cast::<SegmentCommand64>()),
                    )),
                    LC_ID_DYLIB => Some(LoadCommand::Dylib(
                        &*(self.buffer.as_ptr().cast::<DylibCommand>()),
                    )),
                    LC_UUID => Some(LoadCommand::Uuid(
                        &*(self.buffer.as_ptr().cast::<UuidCommand>()),
                    )),
                    // Just ignore any other load commands
                    _ => None,
                };

                self.count -= 1;
                self.buffer = &self.buffer[header.cmd_size as usize..];

                if let Some(cmd) = cmd {
                    return Some(cmd);
                }
            }
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let sz = self.count as usize;
        (sz, Some(sz))
    }
}

/// Retrieves an integer sysctl by name. Returns the default value if retrieval
/// fails.
pub fn sysctl_by_name<T: Sized + Default>(name: &[u8]) -> T {
    let mut out = T::default();
    let mut len = std::mem::size_of_val(&out);

    // SAFETY: syscall
    unsafe {
        if libc::sysctlbyname(
            name.as_ptr().cast(),
            (&mut out as *mut T).cast(),
            &mut len,
            std::ptr::null_mut(),
            0,
        ) != 0
        {
            // log?
            T::default()
        } else {
            out
        }
    }
}

/// Retrieves an `i32` sysctl by name and casts it to the specified integer type.
/// Returns the default value if retrieval fails or the value is out of bounds of
/// the specified integer type.
pub fn int_sysctl_by_name<T: TryFrom<i32> + Default>(name: &[u8]) -> T {
    let val = sysctl_by_name::<i32>(name);
    T::try_from(val).unwrap_or_default()
}

/// Retrieves a string sysctl by name. Returns an empty string if the retrieval
/// fails or the string can't be converted to utf-8.
pub fn sysctl_string(name: &[u8]) -> String {
    let mut buf_len = 0;

    // SAFETY: syscalls
    let string_buf = unsafe {
        // Retrieve the size of the string (including null terminator)
        if libc::sysctlbyname(
            name.as_ptr().cast(),
            std::ptr::null_mut(),
            &mut buf_len,
            std::ptr::null_mut(),
            0,
        ) != 0
            || buf_len <= 1
        {
            return String::new();
        }

        let mut buff = Vec::new();
        buff.resize(buf_len, 0);

        if libc::sysctlbyname(
            name.as_ptr().cast(),
            buff.as_mut_ptr().cast(),
            &mut buf_len,
            std::ptr::null_mut(),
            0,
        ) != 0
        {
            return String::new();
        }

        buff.pop(); // remove null terminator
        buff
    };

    String::from_utf8(string_buf).unwrap_or_default()
}
