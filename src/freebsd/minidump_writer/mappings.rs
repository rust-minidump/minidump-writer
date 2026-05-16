use {
    super::*,
    crate::mem_writer::{MemoryArrayWriter, MemoryWriter, write_string_to_location},
};

#[derive(Debug, thiserror::Error, serde::Serialize)]
pub enum SectionMappingsError {
    #[error("Failed to write to memory")]
    MemoryWriterError(#[from] crate::mem_writer::MemoryWriterError),
}

impl MinidumpWriter {
    pub fn write_mappings(
        &mut self,
        buffer: &mut DumpBuf,
    ) -> Result<MDRawDirectory, SectionMappingsError> {
        let mut modules = Vec::new();

        for map_idx in 0..self.mappings.len() {
            if !self.mappings[map_idx].is_interesting()
                || self.mappings[map_idx].is_contained_in(&self.user_mapping_list)
            {
                continue;
            }

            let crate::freebsd::module_reader::BuildId(identifier) = self
                .from_process_memory_for_index(map_idx)
                .or_else(|e| {
                    use crate::freebsd::module_reader::ReadFromModule;
                    if let Some(path) = &self.mappings[map_idx].name {
                        let path = std::path::Path::new(path);
                        if path.exists() {
                            return crate::freebsd::module_reader::BuildId::read_from_file(path)
                                .map_err(errors::WriterError::ModuleReaderError);
                        }
                    }
                    Err(e)
                })
                .unwrap_or_else(|_| crate::freebsd::module_reader::BuildId(Vec::new()));

            if identifier.is_empty() || identifier.iter().all(|&x| x == 0) {
                continue;
            }

            let module = fill_raw_module(buffer, &self.mappings[map_idx], &identifier)?;
            modules.push(module);
        }

        for user in &self.user_mapping_list {
            let module = fill_raw_module(buffer, user, &[])?;
            modules.push(module);
        }

        let list_header = MemoryWriter::<u32>::alloc_with_val(buffer, modules.len() as u32)?;

        let mut dirent = MDRawDirectory {
            stream_type: MDStreamType::ModuleListStream as u32,
            location: list_header.location(),
        };

        if !modules.is_empty() {
            let mapping_list = MemoryArrayWriter::<MDRawModule>::alloc_from_iter(buffer, modules)?;
            dirent.location.data_size += mapping_list.location().data_size;
        }

        Ok(dirent)
    }
}

fn fill_raw_module(
    buffer: &mut DumpBuf,
    mapping: &crate::freebsd::maps_reader::MappingInfo,
    identifier: &[u8],
) -> Result<MDRawModule, SectionMappingsError> {
    let cv_record = if identifier.is_empty() {
        Default::default()
    } else {
        let cv_signature = crate::minidump_format::format::CvSignature::Elf as u32;
        let array_size = std::mem::size_of_val(&cv_signature) + identifier.len();

        let mut sig_section = MemoryArrayWriter::<u8>::alloc_array(buffer, array_size)?;
        for (index, val) in cv_signature
            .to_ne_bytes()
            .iter()
            .chain(identifier.iter())
            .enumerate()
        {
            sig_section.set_value_at(buffer, *val, index)?;
        }
        sig_section.location()
    };

    let name_header = if let Some(name) = &mapping.name {
        write_string_to_location(buffer, &name.to_string_lossy())?
    } else {
        MDLocationDescriptor {
            data_size: 0,
            rva: 0,
        }
    };

    Ok(MDRawModule {
        base_of_image: mapping.start_address as u64,
        // The mapping size fits in u32 for the minidump format.
        // Real-world mappings are much smaller than u32::MAX.
        size_of_image: mapping.size as u32,
        cv_record,
        module_name_rva: name_header.rva,
        ..Default::default()
    })
}
