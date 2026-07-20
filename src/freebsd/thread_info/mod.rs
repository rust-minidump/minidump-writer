use {
    super::{Pid, ProcessInspector},
    crate::serializers::*,
};

type Result<T> = std::result::Result<T, ThreadInfoError>;

#[derive(thiserror::Error, Debug, serde::Serialize)]
pub enum ThreadInfoError {
    #[error("Index out of bounds: Got {0}, only have {1}")]
    IndexOutOfBounds(usize, usize),
    #[error("ptrace operation failed")]
    PtraceError(
        #[source]
        #[serde(serialize_with = "serialize_io_error")]
        std::io::Error,
    ),
    #[error("Thread enumeration failed for process {0}")]
    ThreadEnumFailed(Pid),
}

cfg_if::cfg_if! {
    if #[cfg(target_arch = "x86_64")] {
        mod x86_64;
        pub mod x86_64_regs;
        pub type ThreadInfo = x86_64::ThreadInfoX86;
    }
}

impl ThreadInfo {
    pub fn create(
        process_inspector: &ProcessInspector,
        _process_id: Pid,
        thread_id: Pid,
    ) -> Result<Self> {
        let mut registers = Self::getregs(process_inspector, thread_id)?;
        let fpregs = Self::getfpregs(process_inspector, thread_id)?;
        Self::apply_fpregs_to_context(&mut registers, &fpregs);
        let stack_pointer = registers.rsp as usize;
        let name = process_inspector.get_thread_name(thread_id);

        Ok(Self {
            tid: thread_id,
            stack_pointer,
            name,
            registers,
            fpregs,
        })
    }
}
