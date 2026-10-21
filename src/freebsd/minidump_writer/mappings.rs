use {
    super::*,
    crate::{
        freebsd::maps_reader::MappingInfo,
        mem_writer::{MemoryArrayWriter, MemoryWriter, write_string_to_location},
        module_reader::{BuildId, ReadFromModule},
    },
};

#[derive(Debug, thiserror::Error, serde::Serialize)]
pub enum SectionMappingsError {
    #[error("Failed to write to memory")]
    MemoryWriterError(#[from] crate::mem_writer::MemoryWriterError),
}

impl MinidumpWriter {
    pub fn write_mappings(
        &self,
        buffer: &mut DumpBuf,
    ) -> Result<MDRawDirectory, SectionMappingsError> {
        let mut modules = Vec::new();

        for (map_idx, mapping) in self.mappings.iter().enumerate() {
            let contained_in_user_list = self.user_mapping_list.iter().any(|user| {
                mapping.start_address >= user.info.start_address
                    && mapping.end_address() <= user.info.end_address()
            });
            if !mapping.is_interesting() || contained_in_user_list {
                continue;
            }

            let BuildId(identifier) = self
                .from_process_memory_for_index(map_idx)
                .or_else(|e| {
                    if let Some(path) = &mapping.name
                        && std::path::Path::new(path).exists()
                    {
                        return BuildId::read_from_file(std::path::Path::new(path))
                            .map_err(errors::WriterError::ModuleReaderError);
                    }
                    Err(e)
                })
                .unwrap_or_else(|_| BuildId(Vec::new()));

            if identifier.is_empty() || identifier.iter().all(|&x| x == 0) {
                continue;
            }

            modules.push(fill_raw_module(buffer, mapping, &identifier)?);
        }

        for user in &self.user_mapping_list {
            let module = fill_raw_module(
                buffer,
                &user.info,
                user.identifier.as_deref().unwrap_or(&[]),
            )?;
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
    mapping: &MappingInfo,
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
        // Truncation is safe: real-world images are far below u32::MAX.
        size_of_image: mapping.size as u32,
        cv_record,
        module_name_rva: name_header.rva,
        ..Default::default()
    })
}
