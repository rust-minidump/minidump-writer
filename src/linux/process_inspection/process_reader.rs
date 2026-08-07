use super::{
    Error, ProcessInspector,
    maps_reader::{MappingInfo, MapsReaderError},
};
use crate::module_reader::ProcessModuleMemoryReader;

pub type ProcessHandle = libc::pid_t;

#[derive(Debug)]
pub struct ProcessReader<'a>(&'a dyn ProcessReaderBackend);

impl<'a> ProcessReader<'a> {
    /// Read memory from the process into the given buffer.
    ///
    /// Returns the number of bytes read.
    pub fn read(&self, src: usize, dst: &mut [u8]) -> Result<usize, CopyFromProcessError> {
        self.0.read_at(src, dst)
    }
    /// Find the address at which a module with the given name is loaded in the process.
    pub fn find_module(
        &self,
        module_name: &str,
    ) -> Result<ProcessModuleMemoryReader<'_>, FindModuleError> {
        MappingInfo::for_pid(
            self.0.process_inspector(),
            self.0
                .process_inspector()
                .pid()
                .map_err(FindModuleError::GetTargetPidFailed)?,
            None,
        )?
        .into_iter()
        .find_map(|m| {
            let mmem = ProcessModuleMemoryReader::new(self, m.start_address);
            let name = m.name.as_ref().and_then(|s| s.to_str())?;
            if name == module_name {
                return Some(mmem);
            }
            // Check whether the SO_NAME matches the module name.
            //
            // For now, only check the SO_NAME of Android APKS, because libraries may be mapped
            // directly from within an APK. See bug 1982902.
            #[cfg(target_os = "android")]
            if name.ends_with(".apk")
                && let Ok(so_name) = crate::module_reader::read_soname_from_module(&mmem)
                && so_name == name
            {
                return Some(mmem);
            }

            None
        })
        .ok_or(FindModuleError::ModuleNotFound)
    }
    pub(crate) fn new(backend: &'a dyn ProcessReaderBackend) -> Self {
        Self(backend)
    }
}

#[derive(Debug, thiserror::Error, serde::Serialize)]
pub enum CopyFromProcessError {
    #[error("an error occurred calling ProcessReader")]
    Backend(Error),
    #[error("an invalid argument was passed")]
    InvalidArgument,
}

#[derive(Debug, thiserror::Error, serde::Serialize)]
pub enum FindModuleError {
    #[error("Module not found")]
    ModuleNotFound,
    #[error("Failed to read process module mappings")]
    MappingError(#[from] MapsReaderError),
    #[error("Failed to get PID of target process")]
    GetTargetPidFailed(#[source] Error),
}

pub(crate) trait ProcessReaderBackend: core::fmt::Debug {
    fn process_inspector(&self) -> &dyn ProcessInspector;
    fn read_at(&self, src: usize, dst: &mut [u8]) -> Result<usize, CopyFromProcessError>;
}
