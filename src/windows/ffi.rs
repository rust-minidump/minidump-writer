pub type BOOL = i32;
pub const FALSE: BOOL = 0;

pub type HANDLE = isize;
pub type NTSTATUS = i32;

pub const STATUS_NONCONTINUABLE_EXCEPTION: NTSTATUS = -1073741787i32;

extern "system" {
    pub fn CloseHandle(hobject: HANDLE) -> BOOL;
}

// threading

#[allow(non_camel_case_types)]
pub type PROCESS_ACCESS_RIGHTS = u32;

pub const PROCESS_ALL_ACCESS: PROCESS_ACCESS_RIGHTS = 2097151u32;

#[allow(non_camel_case_types)]
pub type THREAD_ACCESS_RIGHTS = u32;

pub const THREAD_SUSPEND_RESUME: THREAD_ACCESS_RIGHTS = 2u32;
pub const THREAD_GET_CONTEXT: THREAD_ACCESS_RIGHTS = 8u32;
pub const THREAD_QUERY_INFORMATION: THREAD_ACCESS_RIGHTS = 64u32;

extern "system" {
    pub fn GetCurrentProcess() -> HANDLE;
    pub fn GetCurrentProcessId() -> u32;
    pub fn GetCurrentThread() -> HANDLE;
    pub fn GetCurrentThreadId() -> u32;
    pub fn OpenProcess(
        dwdesiredaccess: PROCESS_ACCESS_RIGHTS,
        binherithandle: BOOL,
        dwprocessid: u32,
    ) -> HANDLE;
    pub fn OpenThread(
        dwdesiredaccess: THREAD_ACCESS_RIGHTS,
        binherithandle: BOOL,
        dwthreadid: u32,
    ) -> HANDLE;
    pub fn ResumeThread(hthread: HANDLE) -> u32;
    pub fn SuspendThread(hthread: HANDLE) -> u32;
}

// context

#[allow(non_snake_case)]
#[repr(C)]
pub union ARM64_NT_NEON128 {
    pub Anonymous: ARM64_NT_NEON128_0,
    pub D: [f64; 2],
    pub S: [f32; 4],
    pub H: [u16; 8],
    pub B: [u8; 16],
}

impl ::core::marker::Copy for ARM64_NT_NEON128 {}
impl ::core::clone::Clone for ARM64_NT_NEON128 {
    fn clone(&self) -> Self {
        *self
    }
}

#[allow(non_snake_case)]
#[repr(C)]
pub struct ARM64_NT_NEON128_0 {
    pub Low: u64,
    pub High: i64,
}

impl ::core::marker::Copy for ARM64_NT_NEON128_0 {}
impl ::core::clone::Clone for ARM64_NT_NEON128_0 {
    fn clone(&self) -> Self {
        *self
    }
}

#[allow(non_snake_case)]
#[repr(C)]
#[cfg(target_arch = "aarch64")]
pub struct CONTEXT {
    pub ContextFlags: u32,
    pub Cpsr: u32,
    pub Anonymous: CONTEXT_0,
    pub Sp: u64,
    pub Pc: u64,
    pub V: [ARM64_NT_NEON128; 32],
    pub Fpcr: u32,
    pub Fpsr: u32,
    pub Bcr: [u32; 8],
    pub Bvr: [u64; 8],
    pub Wcr: [u32; 2],
    pub Wvr: [u64; 2],
}

#[cfg(target_arch = "aarch64")]
impl ::core::marker::Copy for CONTEXT {}
#[cfg(target_arch = "aarch64")]
impl ::core::clone::Clone for CONTEXT {
    fn clone(&self) -> Self {
        *self
    }
}

#[allow(non_snake_case)]
#[repr(C)]
#[cfg(target_arch = "aarch64")]
pub union CONTEXT_0 {
    pub Anonymous: CONTEXT_0_0,
    pub X: [u64; 31],
}

#[cfg(target_arch = "aarch64")]
impl ::core::marker::Copy for CONTEXT_0 {}
#[cfg(target_arch = "aarch64")]
impl ::core::clone::Clone for CONTEXT_0 {
    fn clone(&self) -> Self {
        *self
    }
}

#[allow(non_snake_case)]
#[repr(C)]
#[cfg(target_arch = "aarch64")]
pub struct CONTEXT_0_0 {
    pub X0: u64,
    pub X1: u64,
    pub X2: u64,
    pub X3: u64,
    pub X4: u64,
    pub X5: u64,
    pub X6: u64,
    pub X7: u64,
    pub X8: u64,
    pub X9: u64,
    pub X10: u64,
    pub X11: u64,
    pub X12: u64,
    pub X13: u64,
    pub X14: u64,
    pub X15: u64,
    pub X16: u64,
    pub X17: u64,
    pub X18: u64,
    pub X19: u64,
    pub X20: u64,
    pub X21: u64,
    pub X22: u64,
    pub X23: u64,
    pub X24: u64,
    pub X25: u64,
    pub X26: u64,
    pub X27: u64,
    pub X28: u64,
    pub Fp: u64,
    pub Lr: u64,
}

#[cfg(target_arch = "aarch64")]
impl ::core::marker::Copy for CONTEXT_0_0 {}
#[cfg(target_arch = "aarch64")]
impl ::core::clone::Clone for CONTEXT_0_0 {
    fn clone(&self) -> Self {
        *self
    }
}

#[allow(non_snake_case)]
#[repr(C)]
#[cfg(target_arch = "x86_64")]
pub struct CONTEXT {
    pub P1Home: u64,
    pub P2Home: u64,
    pub P3Home: u64,
    pub P4Home: u64,
    pub P5Home: u64,
    pub P6Home: u64,
    pub ContextFlags: u32,
    pub MxCsr: u32,
    pub SegCs: u16,
    pub SegDs: u16,
    pub SegEs: u16,
    pub SegFs: u16,
    pub SegGs: u16,
    pub SegSs: u16,
    pub EFlags: u32,
    pub Dr0: u64,
    pub Dr1: u64,
    pub Dr2: u64,
    pub Dr3: u64,
    pub Dr6: u64,
    pub Dr7: u64,
    pub Rax: u64,
    pub Rcx: u64,
    pub Rdx: u64,
    pub Rbx: u64,
    pub Rsp: u64,
    pub Rbp: u64,
    pub Rsi: u64,
    pub Rdi: u64,
    pub R8: u64,
    pub R9: u64,
    pub R10: u64,
    pub R11: u64,
    pub R12: u64,
    pub R13: u64,
    pub R14: u64,
    pub R15: u64,
    pub Rip: u64,
    pub Anonymous: CONTEXT_0,
    pub VectorRegister: [M128A; 26],
    pub VectorControl: u64,
    pub DebugControl: u64,
    pub LastBranchToRip: u64,
    pub LastBranchFromRip: u64,
    pub LastExceptionToRip: u64,
    pub LastExceptionFromRip: u64,
}

#[cfg(target_arch = "x86_64")]
impl ::core::marker::Copy for CONTEXT {}
#[cfg(target_arch = "x86_64")]
impl ::core::clone::Clone for CONTEXT {
    fn clone(&self) -> Self {
        *self
    }
}

#[allow(non_snake_case)]
#[repr(C)]
#[cfg(target_arch = "x86_64")]
pub union CONTEXT_0 {
    pub FltSave: XSAVE_FORMAT,
    pub Anonymous: CONTEXT_0_0,
}

#[cfg(target_arch = "x86_64")]
impl ::core::marker::Copy for CONTEXT_0 {}
#[cfg(target_arch = "x86_64")]
impl ::core::clone::Clone for CONTEXT_0 {
    fn clone(&self) -> Self {
        *self
    }
}

#[allow(non_snake_case)]
#[repr(C)]
#[cfg(target_arch = "x86_64")]
pub struct CONTEXT_0_0 {
    pub Header: [M128A; 2],
    pub Legacy: [M128A; 8],
    pub Xmm0: M128A,
    pub Xmm1: M128A,
    pub Xmm2: M128A,
    pub Xmm3: M128A,
    pub Xmm4: M128A,
    pub Xmm5: M128A,
    pub Xmm6: M128A,
    pub Xmm7: M128A,
    pub Xmm8: M128A,
    pub Xmm9: M128A,
    pub Xmm10: M128A,
    pub Xmm11: M128A,
    pub Xmm12: M128A,
    pub Xmm13: M128A,
    pub Xmm14: M128A,
    pub Xmm15: M128A,
}
#[cfg(target_arch = "x86_64")]
impl ::core::marker::Copy for CONTEXT_0_0 {}
#[cfg(target_arch = "x86_64")]
impl ::core::clone::Clone for CONTEXT_0_0 {
    fn clone(&self) -> Self {
        *self
    }
}

#[allow(non_snake_case)]
#[repr(C)]
#[cfg(target_arch = "x86")]
pub struct CONTEXT {
    pub ContextFlags: u32,
    pub Dr0: u32,
    pub Dr1: u32,
    pub Dr2: u32,
    pub Dr3: u32,
    pub Dr6: u32,
    pub Dr7: u32,
    pub FloatSave: FLOATING_SAVE_AREA,
    pub SegGs: u32,
    pub SegFs: u32,
    pub SegEs: u32,
    pub SegDs: u32,
    pub Edi: u32,
    pub Esi: u32,
    pub Ebx: u32,
    pub Edx: u32,
    pub Ecx: u32,
    pub Eax: u32,
    pub Ebp: u32,
    pub Eip: u32,
    pub SegCs: u32,
    pub EFlags: u32,
    pub Esp: u32,
    pub SegSs: u32,
    pub ExtendedRegisters: [u8; 512],
}

#[cfg(target_arch = "x86")]
impl ::core::marker::Copy for CONTEXT {}
#[cfg(target_arch = "x86")]
impl ::core::clone::Clone for CONTEXT {
    fn clone(&self) -> Self {
        *self
    }
}

#[allow(non_snake_case)]
#[repr(C)]
#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
pub struct FLOATING_SAVE_AREA {
    pub ControlWord: u32,
    pub StatusWord: u32,
    pub TagWord: u32,
    pub ErrorOffset: u32,
    pub ErrorSelector: u32,
    pub DataOffset: u32,
    pub DataSelector: u32,
    pub RegisterArea: [u8; 80],
    pub Cr0NpxState: u32,
}

#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
impl ::core::marker::Copy for FLOATING_SAVE_AREA {}
#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
impl ::core::clone::Clone for FLOATING_SAVE_AREA {
    fn clone(&self) -> Self {
        *self
    }
}

#[allow(non_snake_case)]
#[repr(C)]
#[cfg(target_arch = "x86")]
pub struct FLOATING_SAVE_AREA {
    pub ControlWord: u32,
    pub StatusWord: u32,
    pub TagWord: u32,
    pub ErrorOffset: u32,
    pub ErrorSelector: u32,
    pub DataOffset: u32,
    pub DataSelector: u32,
    pub RegisterArea: [u8; 80],
    pub Spare0: u32,
}

#[cfg(target_arch = "x86")]
impl ::core::marker::Copy for FLOATING_SAVE_AREA {}
#[cfg(target_arch = "x86")]
impl ::core::clone::Clone for FLOATING_SAVE_AREA {
    fn clone(&self) -> Self {
        *self
    }
}

#[allow(non_snake_case)]
#[repr(C)]
#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
pub struct XSAVE_FORMAT {
    pub ControlWord: u16,
    pub StatusWord: u16,
    pub TagWord: u8,
    pub Reserved1: u8,
    pub ErrorOpcode: u16,
    pub ErrorOffset: u32,
    pub ErrorSelector: u16,
    pub Reserved2: u16,
    pub DataOffset: u32,
    pub DataSelector: u16,
    pub Reserved3: u16,
    pub MxCsr: u32,
    pub MxCsr_Mask: u32,
    pub FloatRegisters: [M128A; 8],
    pub XmmRegisters: [M128A; 16],
    pub Reserved4: [u8; 96],
}

#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
impl ::core::marker::Copy for XSAVE_FORMAT {}
#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
impl ::core::clone::Clone for XSAVE_FORMAT {
    fn clone(&self) -> Self {
        *self
    }
}

#[allow(non_snake_case)]
#[repr(C)]
#[cfg(target_arch = "x86")]
pub struct XSAVE_FORMAT {
    pub ControlWord: u16,
    pub StatusWord: u16,
    pub TagWord: u8,
    pub Reserved1: u8,
    pub ErrorOpcode: u16,
    pub ErrorOffset: u32,
    pub ErrorSelector: u16,
    pub Reserved2: u16,
    pub DataOffset: u32,
    pub DataSelector: u16,
    pub Reserved3: u16,
    pub MxCsr: u32,
    pub MxCsr_Mask: u32,
    pub FloatRegisters: [M128A; 8],
    pub XmmRegisters: [M128A; 8],
    pub Reserved4: [u8; 224],
}

#[cfg(target_arch = "x86")]
impl ::core::marker::Copy for XSAVE_FORMAT {}
#[cfg(target_arch = "x86")]
impl ::core::clone::Clone for XSAVE_FORMAT {
    fn clone(&self) -> Self {
        *self
    }
}

// minidump

#[allow(non_camel_case_types)]
pub type MINIDUMP_TYPE = u32;

#[allow(non_upper_case_globals)]
pub const MiniDumpNormal: MINIDUMP_TYPE = 0u32;

#[allow(non_camel_case_types)]
pub type MINIDUMP_CALLBACK_ROUTINE = Option<
    unsafe extern "system" fn(
        callbackparam: *mut ::core::ffi::c_void,
        callbackinput: *const MINIDUMP_CALLBACK_INPUT,
        callbackoutput: *mut MINIDUMP_CALLBACK_OUTPUT,
    ) -> BOOL,
>;

#[repr(C, packed(4))]
pub struct MINIDUMP_CALLBACK_INPUT {
    dummy: u32,
}

impl ::core::marker::Copy for MINIDUMP_CALLBACK_INPUT {}
impl ::core::clone::Clone for MINIDUMP_CALLBACK_INPUT {
    fn clone(&self) -> Self {
        *self
    }
}

#[repr(C, packed(4))]
pub struct MINIDUMP_CALLBACK_OUTPUT {
    dummy: u32,
}

impl ::core::marker::Copy for MINIDUMP_CALLBACK_OUTPUT {}
impl ::core::clone::Clone for MINIDUMP_CALLBACK_OUTPUT {
    fn clone(&self) -> Self {
        *self
    }
}

#[allow(non_snake_case)]
#[repr(C)]
pub struct M128A {
    pub Low: u64,
    pub High: i64,
}

impl ::core::marker::Copy for M128A {}
impl ::core::clone::Clone for M128A {
    fn clone(&self) -> Self {
        *self
    }
}

#[allow(non_snake_case)]
#[repr(C, packed(4))]
pub struct MINIDUMP_CALLBACK_INFORMATION {
    pub CallbackRoutine: MINIDUMP_CALLBACK_ROUTINE,
    pub CallbackParam: *mut ::core::ffi::c_void,
}

impl ::core::marker::Copy for MINIDUMP_CALLBACK_INFORMATION {}
impl ::core::clone::Clone for MINIDUMP_CALLBACK_INFORMATION {
    fn clone(&self) -> Self {
        *self
    }
}

#[allow(non_snake_case)]
#[repr(C, packed(4))]
pub struct MINIDUMP_EXCEPTION_INFORMATION {
    pub ThreadId: u32,
    pub ExceptionPointers: *mut EXCEPTION_POINTERS,
    pub ClientPointers: BOOL,
}

#[allow(non_snake_case)]
#[repr(C)]
pub struct EXCEPTION_POINTERS {
    pub ExceptionRecord: *mut EXCEPTION_RECORD,
    pub ContextRecord: *mut CONTEXT,
}

#[allow(non_snake_case)]
#[repr(C)]
pub struct EXCEPTION_RECORD {
    pub ExceptionCode: NTSTATUS,
    pub ExceptionFlags: u32,
    pub ExceptionRecord: *mut EXCEPTION_RECORD,
    pub ExceptionAddress: *mut ::core::ffi::c_void,
    pub NumberParameters: u32,
    pub ExceptionInformation: [usize; 15],
}

impl ::core::marker::Copy for EXCEPTION_RECORD {}
impl ::core::clone::Clone for EXCEPTION_RECORD {
    fn clone(&self) -> Self {
        *self
    }
}

#[allow(non_snake_case)]
#[repr(C, packed(4))]
pub struct MINIDUMP_USER_STREAM {
    pub Type: u32,
    pub BufferSize: u32,
    pub Buffer: *mut ::core::ffi::c_void,
}
impl ::core::marker::Copy for MINIDUMP_USER_STREAM {}
impl ::core::clone::Clone for MINIDUMP_USER_STREAM {
    fn clone(&self) -> Self {
        *self
    }
}

#[allow(non_snake_case)]
#[repr(C, packed(4))]
pub struct MINIDUMP_USER_STREAM_INFORMATION {
    pub UserStreamCount: u32,
    pub UserStreamArray: *mut MINIDUMP_USER_STREAM,
}
impl ::core::marker::Copy for MINIDUMP_USER_STREAM_INFORMATION {}
impl ::core::clone::Clone for MINIDUMP_USER_STREAM_INFORMATION {
    fn clone(&self) -> Self {
        *self
    }
}

extern "system" {
    pub fn GetThreadContext(hthread: HANDLE, lpcontext: *mut CONTEXT) -> BOOL;
    pub fn MiniDumpWriteDump(
        hprocess: HANDLE,
        processid: u32,
        hfile: HANDLE,
        dumptype: MINIDUMP_TYPE,
        exceptionparam: *const MINIDUMP_EXCEPTION_INFORMATION,
        userstreamparam: *const MINIDUMP_USER_STREAM_INFORMATION,
        callbackparam: *const MINIDUMP_CALLBACK_INFORMATION,
    ) -> BOOL;
    pub fn RtlCaptureContext(contextrecord: *mut CONTEXT);
}
