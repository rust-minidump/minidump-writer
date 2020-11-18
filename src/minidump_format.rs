use crate::Result;
use std::io::{Cursor, Write};

#[repr(C)]
#[derive(Debug, Default, PartialEq)]
pub struct MDGUID {
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [u8; 8],
}

#[repr(C)]
#[derive(Debug, Default, PartialEq)]
pub struct MDVSFixedFileInfo {
    pub signature: u32,
    pub struct_version: u32,
    pub file_version_hi: u32,
    pub file_version_lo: u32,
    pub product_version_hi: u32,
    pub product_version_lo: u32,
    pub file_flags_mask: u32, /* Identifies valid bits in fileFlags */
    pub file_flags: u32,
    pub file_os: u32,
    pub file_type: u32,
    pub file_subtype: u32,
    pub file_date_hi: u32,
    pub file_date_lo: u32,
}

/* An MDRVA is an offset into the minidump file.  The beginning of the
 * MDRawHeader is at offset 0. */
type MDRVA = u32;

#[repr(C)]
#[derive(Debug, Default, PartialEq)]
pub struct MDLocationDescriptor {
    pub data_size: u32,
    pub rva: MDRVA,
}

#[repr(C)]
#[derive(Debug, Default, PartialEq)]
pub struct MDMemoryDescriptor {
    /* The base address of the memory range on the host that produced the
     * minidump. */
    pub start_of_memory_range: u64,
    pub memory: MDLocationDescriptor,
}

#[repr(C)]
#[derive(Debug, Default, PartialEq)]
pub struct MDRawHeader {
    pub signature: u32,
    pub version: u32,
    pub stream_count: u32,
    pub stream_directory_rva: MDRVA, /* A |stream_count|-sized array of
                                      * MDRawDirectory structures. */
    pub checksum: u32,        /* Can be 0.  In fact, that's all that's
                               * been found in minidump files. */
    pub time_date_stamp: u32, /* time_t */
    pub flags: u64,
}

#[repr(C)]
#[derive(Debug, Default, PartialEq)]
pub struct MDRawThread {
    pub thread_id: u32,
    pub suspend_count: u32,
    pub priority_class: u32,
    pub priority: u32,
    pub teb: u64, /* Thread environment block */
    pub stack: MDMemoryDescriptor,
    pub thread_context: MDLocationDescriptor, /* MDRawContext[CPU] */
}

pub type MDRawThreadList = Vec<MDRawThread>;

#[repr(C)]
#[derive(Debug, Default, PartialEq)]
pub struct MDRawModule {
    pub base_of_image: u64,
    pub size_of_image: u32,
    pub checksum: u32,          /* 0 if unknown */
    pub time_date_stamp: u32,   /* time_t */
    pub module_name_rva: MDRVA, /* MDString, pathname or filename */
    pub version_info: MDVSFixedFileInfo,

    /* The next field stores a CodeView record and is populated when a module's
     * debug information resides in a PDB file.  It identifies the PDB file. */
    pub cv_record: MDLocationDescriptor,

    /* The next field is populated when a module's debug information resides
     * in a DBG file.  It identifies the DBG file.  This field is effectively
     * obsolete with modules built by recent toolchains. */
    pub misc_record: MDLocationDescriptor,

    /* Alignment problem: reserved0 and reserved1 are defined by the platform
     * SDK as 64-bit quantities.  However, that results in a structure whose
     * alignment is unpredictable on different CPUs and ABIs.  If the ABI
     * specifies full alignment of 64-bit quantities in structures (as ppc
     * does), there will be padding between miscRecord and reserved0.  If
     * 64-bit quantities can be aligned on 32-bit boundaries (as on x86),
     * this padding will not exist.  (Note that the structure up to this point
     * contains 1 64-bit member followed by 21 32-bit members.)
     * As a workaround, reserved0 and reserved1 are instead defined here as
     * four 32-bit quantities.  This should be harmless, as there are
     * currently no known uses for these fields. */
    pub reserved0: [u32; 2],
    pub reserved1: [u32; 2],
}

/* The inclusion of a 64-bit type in MINIDUMP_MODULE forces the struct to
 * be tail-padded out to a multiple of 64 bits under some ABIs (such as PPC).
 * This doesn't occur on systems that don't tail-pad in this manner.  Define
 * this macro to be the usable size of the MDRawModule struct, and use it in
 * place of sizeof(MDRawModule). */
pub const MD_MODULE_SIZE: usize = 108;

#[repr(C)]
#[derive(Debug, Default, PartialEq)]
pub struct MDRawDirectory {
    pub stream_type: u32,
    pub location: MDLocationDescriptor,
}

/* For (MDRawHeader).signature and (MDRawHeader).version.  Note that only the
 * low 16 bits of (MDRawHeader).version are MD_HEADER_VERSION.  Per the
 * documentation, the high 16 bits are implementation-specific. */
pub const MD_HEADER_SIGNATURE: u32 = 0x504d444d; /* 'PMDM' */
/* MINIDUMP_SIGNATURE */
pub const MD_HEADER_VERSION: u32 = 0x0000a793; /* 42899 */
/* MINIDUMP_VERSION */

/* For (MDRawHeader).flags: */
pub enum MDType {
    /* MD_NORMAL is the standard type of minidump.  It includes full
     * streams for the thread list, module list, exception, system info,
     * and miscellaneous info.  A memory list stream is also present,
     * pointing to the same stack memory contained in the thread list,
     * as well as a 256-byte region around the instruction address that
     * was executing when the exception occurred.  Stack memory is from
     * 4 bytes below a thread's stack pointer up to the top of the
     * memory region encompassing the stack. */
    Normal = 0x00000000,
    WithDataSegs = 0x00000001,
    WithFullMemory = 0x00000002,
    WithHandleData = 0x00000004,
    FilterMemory = 0x00000008,
    ScanMemory = 0x00000010,
    WithUnloadedModules = 0x00000020,
    WithIndirectlyReferencedMemory = 0x00000040,
    FilterModulePaths = 0x00000080,
    WithProcessThreadData = 0x00000100,
    WithPrivateReadWriteMemory = 0x00000200,
    WithoutOptionalData = 0x00000400,
    WithFullMemoryInfo = 0x00000800,
    WithThreadInfo = 0x00001000,
    WithCodeSegs = 0x00002000,
    WithoutAuxilliarySegs = 0x00004000,
    WithFullAuxilliaryState = 0x00008000,
    WithPrivateWriteCopyMemory = 0x00010000,
    IgnoreInaccessibleMemory = 0x00020000,
    WithTokenInformation = 0x00040000,
}

/* For (MDRawDirectory).stream_type */
pub enum MDStreamType {
    UnusedStream = 0,
    ReservedStream0 = 1,
    ReservedStream1 = 2,
    ThreadListStream = 3, /* MDRawThreadList */
    ModuleListStream = 4, /* MDRawModuleList */
    MemoryListStream = 5, /* MDRawMemoryList */
    ExceptionStream = 6,  /* MDRawExceptionStream */
    SystemInfoStream = 7, /* MDRawSystemInfo */
    ThreadExListStream = 8,
    Memory64ListStream = 9,
    CommentStreamA = 10,
    CommentStreamW = 11,
    HandleDataStream = 12,
    FunctionTableStream = 13,
    UnloadedModuleListStream = 14,
    MiscInfoStream = 15,       /* MDRawMiscInfo */
    MemoryInfoListStream = 16, /* MDRawMemoryInfoList */
    ThreadInfoListStream = 17,
    HandleOperationListStream = 18,
    TokenStream = 19,
    JavascriptDataStream = 20,
    SystemMemoryInfoStream = 21,
    ProcessVmCountersStream = 22,
    LastReservedStream = 0x0000ffff,

    /* Breakpad extension types.  0x4767 = "Gg" */
    BreakpadInfoStream = 0x47670001,  /* MDRawBreakpadInfo  */
    AssertionInfoStream = 0x47670002, /* MDRawAssertionInfo */
    /* These are additional minidump stream values which are specific to
     * the linux breakpad implementation. */
    LinuxCpuInfo = 0x47670003,    /* /proc/cpuinfo      */
    LinuxProcStatus = 0x47670004, /* /proc/$x/status    */
    LinuxLsbRelease = 0x47670005, /* /etc/lsb-release   */
    LinuxCmdLine = 0x47670006,    /* /proc/$x/cmdline   */
    LinuxEnviron = 0x47670007,    /* /proc/$x/environ   */
    LinuxAuxv = 0x47670008,       /* /proc/$x/auxv      */
    LinuxMaps = 0x47670009,       /* /proc/$x/maps      */
    LinuxDsoDebug = 0x4767000A,   /* MDRawDebug{32,64}  */

    /* Crashpad extension types. 0x4350 = "CP"
     * See Crashpad's minidump/minidump_extensions.h. */
    CrashpadInfoStream = 0x43500001, /* MDRawCrashpadInfo  */
}

#[derive(Debug, PartialEq)]
pub struct SectionWriter<T: Default + Sized> {
    pub position: MDRVA,
    phantom: std::marker::PhantomData<T>,
}

impl<T> SectionWriter<T>
where
    T: Default + Sized,
{
    /// Create a slot for a type T in the buffer, we can fill right now with real values.
    pub fn alloc_with_val(buffer: &mut Cursor<Vec<u8>>, val: T) -> Result<Self> {
        // Get position of this value (e.g. before we add ourselves there)
        let position = buffer.position();
        let bytes = unsafe {
            std::slice::from_raw_parts(&val as *const T as *const u8, std::mem::size_of::<T>())
        };
        buffer.write_all(bytes)?;

        Ok(SectionWriter {
            position: position as u32,
            phantom: std::marker::PhantomData::<T> {},
        })
    }

    /// Create a slot for a type T in the buffer, we can fill later with real values.
    /// This function fills it with `Default::default()`, which is less performant than
    /// using uninitialized memory, but safe.
    pub fn alloc(buffer: &mut Cursor<Vec<u8>>) -> Result<Self> {
        // Filling out the buffer with default-values
        let val: T = Default::default();
        Self::alloc_with_val(buffer, val)
    }

    /// Write actual values in the buffer-slot we got during `alloc()`
    pub fn set_value(&mut self, buffer: &mut Cursor<Vec<u8>>, val: T) -> Result<()> {
        // Save whereever the current cursor stands in the buffer
        let curr_pos = buffer.position();

        // Write the actual value we want at our position that
        // was determined by `alloc()` into the buffer
        buffer.set_position(self.position as u64);
        let bytes = unsafe {
            std::slice::from_raw_parts(&val as *const T as *const u8, std::mem::size_of::<T>())
        };
        let res = buffer.write_all(bytes);

        // Resetting whereever we were before updating this
        // regardless of the write-result
        buffer.set_position(curr_pos);

        res?;
        Ok(())
    }

    pub fn location(&self) -> MDLocationDescriptor {
        MDLocationDescriptor {
            data_size: std::mem::size_of::<T>() as u32,
            rva: self.position,
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct SectionArrayWriter<T: Default + Sized> {
    pub position: MDRVA,
    array_size: usize,
    phantom: std::marker::PhantomData<T>,
}

impl<T> SectionArrayWriter<T>
where
    T: Default + Sized,
{
    /// Create a slot for a type T in the buffer, we can fill later with real values.
    /// This function fills it with `Default::default()`, which is less performant than
    /// using uninitialized memory, but safe.
    pub fn alloc_array(buffer: &mut Cursor<Vec<u8>>, array_size: usize) -> Result<Self> {
        // Get position of this value (e.g. before we add ourselves there)
        let position = buffer.position();
        for _ in 0..array_size {
            // Filling out the buffer with default-values
            let val: T = Default::default();
            let bytes = unsafe {
                std::slice::from_raw_parts(&val as *const T as *const u8, std::mem::size_of::<T>())
            };
            buffer.write_all(bytes)?;
        }

        Ok(SectionArrayWriter {
            position: position as u32,
            array_size,
            phantom: std::marker::PhantomData::<T> {},
        })
    }

    /// Write actual values in the buffer-slot we got during `alloc()`
    pub fn set_value_at(
        &mut self,
        buffer: &mut Cursor<Vec<u8>>,
        val: T,
        index: usize,
    ) -> Result<()> {
        // Save whereever the current cursor stands in the buffer
        let curr_pos = buffer.position();

        // Write the actual value we want at our position that
        // was determined by `alloc()` into the buffer
        buffer.set_position(self.position as u64 + (std::mem::size_of::<T>() * index) as u64);
        let bytes = unsafe {
            std::slice::from_raw_parts(&val as *const T as *const u8, std::mem::size_of::<T>())
        };
        let res = buffer.write_all(bytes);

        // Resetting whereever we were before updating this
        // regardless of the write-result
        buffer.set_position(curr_pos);

        res?;
        Ok(())
    }
}
