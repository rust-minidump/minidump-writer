use {
    super::super::{
        Pid, auxv::AuxvError, maps_reader::MapsReaderError, module_reader::ModuleReaderError,
    },
    super::{
        app_memory_stream::SectionAppMemoryError, exception_stream::SectionExceptionStreamError,
        handle_data_stream::SectionHandleDataStreamError, mappings::SectionMappingsError,
        memory_info_list_stream::SectionMemInfoListError, memory_list_stream::SectionMemListError,
        systeminfo_stream::SectionSystemInfoError, thread_list_stream::SectionThreadListError,
        thread_names_stream::SectionThreadNamesError,
    },
    crate::{
        dir_section::FileWriterError, mem_writer::MemoryWriterError,
        serializers::serialize_generic_error, serializers::serialize_io_error,
    },
    error_graph::ErrorList,
    thiserror::Error,
};

#[derive(Debug, Error, serde::Serialize)]
pub enum WriterError {
    #[error("Error during init phase")]
    InitError(#[from] InitError),
    #[error("Failed to write to memory")]
    MemoryWriterError(#[from] MemoryWriterError),
    #[error("Failed to write to file")]
    FileWriterError(#[from] FileWriterError),
    #[error("Failed to get current timestamp when writing header of minidump")]
    SystemTimeError(
        #[from]
        #[serde(serialize_with = "serialize_generic_error")]
        std::time::SystemTimeError,
    ),
    #[error("Failed to continue process")]
    ContinueProcessError(#[from] ContinueProcessError),
    #[error("Failed when writing section ThreadList")]
    SectionThreadListError(#[from] SectionThreadListError),
    #[error("Failed when writing section Mappings")]
    SectionMappingsError(#[from] SectionMappingsError),
    #[error("Failed when writing section MemList")]
    SectionMemListError(#[from] SectionMemListError),
    #[error("Failed when writing section ExceptionStream")]
    SectionExceptionStreamError(#[from] SectionExceptionStreamError),
    #[error("Failed when writing section AppMemory")]
    SectionAppMemoryError(#[from] SectionAppMemoryError),
    #[error("Failed when writing section SystemInfo")]
    SectionSystemInfoError(#[from] SectionSystemInfoError),
    #[error("Failed when writing section MemoryInfoList")]
    SectionMemInfoListError(#[from] SectionMemInfoListError),
    #[error("Failed when writing section ThreadNameList")]
    SectionThreadNamesError(#[from] SectionThreadNamesError),
    #[error("Failed when writing section HandleDataStream")]
    SectionHandleDataStreamError(#[from] SectionHandleDataStreamError),
    #[error("Errors occurred while initializing")]
    InitErrors(#[source] ErrorList<InitError>),
    #[error("Errors occurred while resuming threads")]
    ResumeThreadsErrors(#[source] ErrorList<WriterError>),
    #[error("Errors occurred while writing the thread list")]
    WriteThreadListErrors(#[source] ErrorList<SectionThreadListError>),
    #[error("Errors occurred while writing system info")]
    WriteSystemInfoErrors(#[source] ErrorList<SectionSystemInfoError>),
    #[error("Failed writing handle data stream")]
    WriteHandleDataStreamFailed(#[source] SectionHandleDataStreamError),
    #[error("Failed to convert soft error list to JSON")]
    ConvertToJsonFailed(
        #[source]
        #[serde(skip)]
        serde_json::Error,
    ),
    #[error("Skipped thread {0} due to invalid stack pointer")]
    DetachSkippedThread(Pid),
    #[error("No mapping for stack pointer found")]
    NoStackPointerMapping,
    #[error("Mapping has no ELF base")]
    NotAModuleMapping,
    #[error("Could not read value from module")]
    ModuleReaderError(#[from] ModuleReaderError),
    #[error("Failed integer conversion")]
    TryFromIntError(
        #[from]
        #[serde(skip)]
        std::num::TryFromIntError,
    ),
    #[error("Failed slice conversion")]
    TryFromSliceError(
        #[from]
        #[serde(skip)]
        std::array::TryFromSliceError,
    ),
    #[error("Maps reader error")]
    MapsReaderError(#[from] MapsReaderError),
    #[error("failed to suspend thread")]
    SuspendThreadFailed(#[source] super::super::process_inspection::Error),
    #[error("failed to resume thread")]
    ResumeThreadFailed(#[source] super::super::process_inspection::Error),
}

#[derive(Debug, Error, serde::Serialize)]
pub enum InitError {
    #[error("Failed to stop the target process")]
    StopProcessFailed(#[from] StopProcessError),
    #[error("IO error for file {0}")]
    IOError(
        String,
        #[source]
        #[serde(serialize_with = "serialize_io_error")]
        std::io::Error,
    ),
    #[error("Ptrace does not function within the same process")]
    CannotPtraceSameProcess,
    #[error("failed to enumerate threads")]
    ThreadEnumFailed(#[source] super::super::process_inspection::Error),
    #[error("Failed filling missing Auxv info")]
    FillMissingAuxvInfoFailed(#[source] AuxvError),
    #[error("Failed to enumerate threads")]
    EnumerateThreadsFailed(#[source] Box<InitError>),
    #[error("Failed to aggregate process mappings")]
    AggregateMappingsFailed(#[source] MapsReaderError),
    #[error("Failed to enumerate process mappings")]
    EnumerateMappingsFailed(#[source] Box<InitError>),
    #[error("Errors occurred while suspending threads")]
    SuspendThreadsErrors(#[source] ErrorList<WriterError>),
    #[error("No threads left to suspend out of {0}")]
    SuspendNoThreadsLeft(usize),
    #[error("Crash thread does not reference principal mapping")]
    PrincipalMappingNotReferenced,
    #[error("Failed to read the page size")]
    PageSizeError(
        #[source]
        #[serde(serialize_with = "serialize_io_error")]
        std::io::Error,
    ),
}

#[derive(Debug, Error, serde::Serialize)]
pub enum StopProcessError {
    #[error("Failed to stop the process")]
    Stop(
        #[source]
        #[serde(serialize_with = "serialize_io_error")]
        std::io::Error,
    ),
}

#[derive(Debug, Error, serde::Serialize)]
pub enum ContinueProcessError {
    #[error("Failed to continue the process")]
    Continue(
        #[source]
        #[serde(serialize_with = "serialize_io_error")]
        std::io::Error,
    ),
}
