use {
    super::{AuxvError, AuxvPair, AuxvType},
    byteorder::{NativeEndian, ReadBytesExt},
    std::io::Read,
};

pub struct AuxvIter<R> {
    input: R,
    keep_going: bool,
}

impl<R> AuxvIter<R> {
    pub fn new(input: R) -> Self {
        Self {
            input,
            keep_going: true,
        }
    }
}

impl<R: Read> Iterator for AuxvIter<R> {
    type Item = Result<AuxvPair, AuxvError>;

    fn next(&mut self) -> Option<Self::Item> {
        if !self.keep_going {
            return None;
        }
        self.keep_going = false;

        let key = match read_auxv_type(&mut self.input) {
            Ok(k) => k,
            Err(e) => return Some(Err(AuxvError::IOError(e))),
        };
        let value = match read_auxv_type(&mut self.input) {
            Ok(v) => v,
            Err(e) => return Some(Err(AuxvError::IOError(e))),
        };

        if key == libc::AT_NULL as AuxvType {
            return None;
        }

        self.keep_going = true;
        Some(Ok(AuxvPair { key, value }))
    }
}

fn read_auxv_type<R: Read>(mut reader: R) -> std::io::Result<AuxvType> {
    match std::mem::size_of::<AuxvType>() {
        4 => reader.read_u32::<NativeEndian>().map(|u| u as AuxvType),
        8 => reader.read_u64::<NativeEndian>().map(|u| u as AuxvType),
        x => panic!("Unexpected type width: {x}"),
    }
}
