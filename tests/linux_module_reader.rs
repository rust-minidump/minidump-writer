use minidump_writer::module_reader::*;

/// This is a small (but valid) 64-bit little-endian elf executable with the following layout:
/// * ELF header
/// * program header: text segment
/// * program header: note
/// * program header: dynamic
/// * section header: null
/// * section header: .text
/// * section header: .note.gnu.build-id
/// * section header: .shstrtab
/// * section header: .dynamic
/// * section header: .dynstr
/// * note header (build id note)
/// * shstrtab
/// * dynamic (SONAME/STRTAB/STRSZ)
/// * dynstr (SONAME string = libfoo.so.1)
/// * program (calls exit(0))
const TINY_ELF: &[u8] = include_bytes!("tiny.elf");

#[test]
fn build_id_program_headers() {
    let mut reader = ModuleReader::new(TINY_ELF.into()).unwrap();
    let id = reader.build_id_from_program_headers().unwrap();
    assert_eq!(id, &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
}

#[test]
fn build_id_section() {
    let mut reader = ModuleReader::new(TINY_ELF.into()).unwrap();
    let id = reader.build_id_from_section().unwrap();
    assert_eq!(id, &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
}

#[test]
fn build_id_text_hash() {
    let mut reader = ModuleReader::new(TINY_ELF.into()).unwrap();
    let id = reader.build_id_generate_from_text().unwrap();
    assert_eq!(
        id,
        &[
            0x6a, 0x3c, 0x58, 0x31, 0xff, 0x0f, 0x05, 0, 0, 0, 0, 0, 0, 0, 0, 0
        ]
    );
}

#[test]
fn soname_program_headers() {
    let mut reader = ModuleReader::new(TINY_ELF.into()).unwrap();
    let soname = reader.soname_from_program_headers().unwrap();
    assert_eq!(soname, "libfoo.so.1");
}

#[test]
fn soname_section() {
    let mut reader = ModuleReader::new(TINY_ELF.into()).unwrap();
    let soname = reader.soname_from_sections().unwrap();
    assert_eq!(soname, "libfoo.so.1");
}
