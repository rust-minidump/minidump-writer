use crate::errors::BuildIdReaderError as Error;
use crate::minidump_format::GUID;
use goblin::{
    container::{Container, Ctx, Endian},
    elf,
};

const NOTE_SECTION_NAME: &[u8] = b".note.gnu.build-id\0";

pub trait ModuleMemory {
    type Memory: std::ops::Deref<Target = [u8]>;

    fn read_module_memory(&self, offset: u64, length: u64) -> std::io::Result<Self::Memory>;
}

impl<'a> ModuleMemory for &'a [u8] {
    type Memory = Self;

    fn read_module_memory(&self, offset: u64, length: u64) -> std::io::Result<Self::Memory> {
        self.get(offset as usize..(offset + length) as usize)
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    format!("{} out of bounds", offset + length),
                )
            })
    }
}

fn read<T: ModuleMemory>(mem: &T, offset: u64, length: u64) -> Result<T::Memory, Error> {
    mem.read_module_memory(offset, length)
        .map_err(|error| Error::ReadModuleMemory {
            offset,
            length,
            error,
        })
}

fn is_executable_section(header: &elf::SectionHeader) -> bool {
    header.sh_type == elf::section_header::SHT_PROGBITS
        && header.sh_flags & u64::from(elf::section_header::SHF_ALLOC) != 0
        && header.sh_flags & u64::from(elf::section_header::SHF_EXECINSTR) != 0
}

/// Return bytes to use as a build id, computed by hashing the given data.
///
/// This provides `size_of::<GUID>` bytes to keep identifiers produced by this function compatible
/// with other build ids.
fn build_id_from_bytes(data: &[u8]) -> Vec<u8> {
    // Only provide mem::size_of(MDGUID) bytes to keep identifiers produced by this
    // function backwards-compatible.
    data.chunks(std::mem::size_of::<GUID>()).fold(
        vec![0u8; std::mem::size_of::<GUID>()],
        |mut bytes, chunk| {
            bytes
                .iter_mut()
                .zip(chunk.iter())
                .for_each(|(b, c)| *b ^= *c);
            bytes
        },
    )
}

pub fn read_build_id(module_memory: impl ModuleMemory) -> Result<Vec<u8>, Error> {
    let reader = ElfBuildIdReader::new(module_memory)?;
    let program_headers = match reader.read_from_program_headers() {
        Ok(v) => return Ok(v),
        Err(e) => Box::new(e),
    };
    let section = match reader.read_from_section() {
        Ok(v) => return Ok(v),
        Err(e) => Box::new(e),
    };
    let generated = match reader.generate_from_text() {
        Ok(v) => return Ok(v),
        Err(e) => Box::new(e),
    };
    Err(Error::Aggregate {
        program_headers,
        section,
        generated,
    })
}

pub struct ElfBuildIdReader<T> {
    module_memory: T,
    header: elf::Header,
    context: Ctx,
}

impl<T: ModuleMemory> ElfBuildIdReader<T> {
    pub fn new(module_memory: T) -> Result<Self, Error> {
        // We could use `Ctx::default()` (which defaults to the native system), however to be extra
        // permissive we'll just use a 64-bit ("Big") context which would result in the largest
        // possible header size.
        let header_size = elf::Header::size(Ctx::new(Container::Big, Endian::default()));
        let header_data = read(&module_memory, 0, header_size as u64)?;
        let header = elf::Elf::parse_header(&header_data)?;
        let context = Ctx::new(header.container()?, header.endianness()?);
        Ok(ElfBuildIdReader {
            module_memory,
            header,
            context,
        })
    }

    /// Read the build id from a program header note.
    pub fn read_from_program_headers(&self) -> Result<Vec<u8>, Error> {
        if self.header.e_phoff == 0 {
            return Err(Error::NoProgramHeaderNote);
        }
        let program_headers_data = read(
            &self.module_memory,
            self.header.e_phoff,
            self.header.e_phentsize as u64 * self.header.e_phnum as u64,
        )?;
        let program_headers = elf::ProgramHeader::parse(
            &program_headers_data,
            0,
            self.header.e_phnum as usize,
            self.context,
        )?;
        for header in program_headers {
            if header.p_type != elf::program_header::PT_NOTE {
                continue;
            }
            if let Ok(Some(result)) =
                self.find_build_id_note(header.p_offset, header.p_filesz, header.p_align)
            {
                return Ok(result);
            }
        }
        Err(Error::NoProgramHeaderNote)
    }

    /// Read the build id from a notes section.
    pub fn read_from_section(&self) -> Result<Vec<u8>, Error> {
        let section_headers = self.read_section_headers()?;

        let strtab_section_header = section_headers
            .get(self.header.e_shstrndx as usize)
            .ok_or(Error::NoStrTab)?;

        for header in &section_headers {
            let sh_name = header.sh_name as u64;
            if sh_name >= strtab_section_header.sh_size {
                log::warn!("invalid sh_name offset");
                continue;
            }
            if sh_name + NOTE_SECTION_NAME.len() as u64 >= strtab_section_header.sh_size {
                // This can't be a match.
                continue;
            }
            let name = read(
                &self.module_memory,
                strtab_section_header.sh_offset + sh_name,
                NOTE_SECTION_NAME.len() as u64,
            )?;
            if NOTE_SECTION_NAME == &*name {
                return match self.find_build_id_note(
                    header.sh_offset,
                    header.sh_size,
                    header.sh_addralign,
                ) {
                    Ok(Some(v)) => Ok(v),
                    Ok(None) => Err(Error::NoSectionNote),
                    Err(e) => Err(e),
                };
            }
        }

        Err(Error::NoSectionNote)
    }

    /// Generate a build id by hashing the first page of the text section.
    pub fn generate_from_text(&self) -> Result<Vec<u8>, Error> {
        let Some(text_header) = self
            .read_section_headers()?
            .into_iter()
            .find(is_executable_section)
        else {
            return Err(Error::NoTextSection);
        };

        // Take at most one page of the text section (we assume page size is 4096 bytes).
        let len = std::cmp::min(4096, text_header.sh_size);
        let text_data = read(&self.module_memory, text_header.sh_offset, len)?;
        Ok(build_id_from_bytes(&text_data))
    }

    fn read_section_headers(&self) -> Result<elf::SectionHeaders, Error> {
        if self.header.e_shoff == 0 {
            return Err(Error::NoSections);
        }

        // FIXME Until a version following goblin 0.8.0 is published (with
        // `SectionHeader::parse_from`), we read one extra byte preceding the sections so that
        // `SectionHeader::parse` doesn't return immediately due to a 0 offset.

        let section_headers_data = read(
            &self.module_memory,
            self.header.e_shoff - 1,
            self.header.e_shentsize as u64 * self.header.e_shnum as u64 + 1,
        )?;
        let section_headers = elf::SectionHeader::parse(
            &section_headers_data,
            1,
            self.header.e_shnum as usize,
            self.context,
        )?;
        Ok(section_headers)
    }

    fn find_build_id_note(
        &self,
        offset: u64,
        size: u64,
        alignment: u64,
    ) -> Result<Option<Vec<u8>>, Error> {
        let notes = read(&self.module_memory, offset, size)?;
        for note in (elf::note::NoteDataIterator {
            data: &notes,
            // Note that `NoteDataIterator::size` is poorly named, it is actually an end offset. In
            // this case since our start offset is 0 we still set it to the size.
            size: size as usize,
            offset: 0,
            ctx: (alignment as usize, self.context),
        }) {
            let Ok(note) = note else { break };
            if note.name == "GNU" && note.n_type == elf::note::NT_GNU_BUILD_ID {
                return Ok(Some(note.desc.to_owned()));
            }
        }
        Ok(None)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    /// This is a small (but valid) 64-bit little-endian elf executable with the following layout:
    /// * ELF header
    /// * program header: text segment
    /// * program header: note
    /// * section header: null
    /// * section header: .text
    /// * section header: .note.gnu.build-id
    /// * section header: .shstrtab
    /// * note header (build id note)
    /// * shstrtab
    /// * program (calls exit(0))
    const TINY_ELF: &[u8] = &[
        0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x02, 0x00, 0x3e, 0x00, 0x01, 0x00, 0x00, 0x00, 0xf4, 0x01, 0x40, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xb0, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x38, 0x00, 0x02, 0x00, 0x40, 0x00,
        0x04, 0x00, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0xf4, 0x01, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0xf4, 0x01, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xb0, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0xb0, 0x01, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0xf4, 0x01, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf4, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0xb0, 0x01, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0xb0, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1a, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xd0, 0x01, 0x40, 0x00, 0x00, 0x00,
        0x00, 0x00, 0xd0, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x24, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00,
        0x00, 0x10, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x47, 0x4e, 0x55, 0x00, 0x01, 0x02,
        0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x00,
        0x2e, 0x74, 0x65, 0x78, 0x74, 0x00, 0x2e, 0x6e, 0x6f, 0x74, 0x65, 0x2e, 0x67, 0x6e, 0x75,
        0x2e, 0x62, 0x75, 0x69, 0x6c, 0x64, 0x2d, 0x69, 0x64, 0x00, 0x2e, 0x73, 0x68, 0x73, 0x74,
        0x72, 0x74, 0x61, 0x62, 0x00, 0x6a, 0x3c, 0x58, 0x31, 0xff, 0x0f, 0x05,
    ];

    #[test]
    fn program_headers() {
        let reader = ElfBuildIdReader::new(TINY_ELF).unwrap();
        let id = reader.read_from_program_headers().unwrap();
        assert_eq!(
            id,
            vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]
        );
    }

    #[test]
    fn section() {
        let reader = ElfBuildIdReader::new(TINY_ELF).unwrap();
        let id = reader.read_from_section().unwrap();
        assert_eq!(
            id,
            vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]
        );
    }

    #[test]
    fn text_hash() {
        let reader = ElfBuildIdReader::new(TINY_ELF).unwrap();
        let id = reader.generate_from_text().unwrap();
        assert_eq!(
            id,
            vec![0x6a, 0x3c, 0x58, 0x31, 0xff, 0x0f, 0x05, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
    }
}
