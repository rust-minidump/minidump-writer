use super as transport;
use super::remote;
use core::{marker::PhantomData, ops::Range};
use remote::{backend, executor, io};
use serde::{Deserialize, Serialize};
use transport::{DeserializeError, SerializeError};

pub use postcard::Error;

// Postcard requires an extra scratch buffer for deserializing a few fixed-size types.
// f64 is the largest type it does this for.
const MAX_TEMP_LEN: usize = size_of::<f64>();

/// The backend side of a Postcard transport
///
/// See remote/wire.rs `operations!()` macro for notes on buffer sizing
#[derive(Debug)]
pub struct Backend<Io, Buf> {
    io: Io,
    output_buf: Buf,
}

impl<Io, Buf> Backend<Io, Buf> {
    pub fn new(io: Io, output_buf: Buf) -> Self {
        Self { io, output_buf }
    }
}

impl<Io, Buf> backend::Transport for Backend<Io, Buf>
where
    Io: io::Io,
    Buf: AsMut<[u8]> + core::fmt::Debug,
{
    fn send_request<'output, Req: Serialize, Resp: Deserialize<'output>>(
        &'output mut self,
        req: Req,
    ) -> Result<Resp, backend::transport::Error> {
        serialize_to_io(&mut self.io, req).map_err(backend::transport::Error::SerializeRequest)?;
        deserialize_from_io(&mut self.io, self.output_buf.as_mut())
            .map_err(backend::transport::Error::DeserializeResponse)
    }
}

/// The executor side of a Postcard transport
///
/// See remote/wire.rs `operations!()` macro for notes on buffer sizing
#[derive(Debug)]
pub struct Executor<Io, Buf> {
    io: Io,
    args_buf: Buf,
}

impl<Io, Buf> Executor<Io, Buf> {
    pub fn new(io: Io, args_buf: Buf) -> Self {
        Self { io, args_buf }
    }
}

impl<Io, Buf> executor::Transport for Executor<Io, Buf>
where
    Io: io::Io,
    Buf: AsMut<[u8]> + core::fmt::Debug,
{
    fn read_request<'args, D: Deserialize<'args>>(
        &'args mut self,
    ) -> Result<D, executor::transport::Error> {
        deserialize_from_io(&mut self.io, self.args_buf.as_mut())
            .map_err(executor::transport::Error::DeserializeRequest)
    }

    fn write_response<S: Serialize>(&mut self, resp: S) -> Result<(), executor::transport::Error> {
        serialize_to_io(&mut self.io, resp).map_err(executor::transport::Error::SerializeResponse)
    }
}

fn serialize_to_io<Io: io::Io, S: Serialize>(io: &mut Io, s: S) -> Result<(), SerializeError> {
    let mut serializer = postcard::Serializer {
        output: SerFlavor::new(io),
    };
    match s.serialize(&mut serializer) {
        Ok(()) => Ok(()),
        Err(e) => {
            let e = postcard::ser_flavors::Flavor::finalize(serializer.output)
                .unwrap()
                .unwrap_or(SerializeError::Postcard(e));
            Err(e)
        }
    }
}

fn deserialize_from_io<'output, Io: io::Io, D: Deserialize<'output>>(
    io: &'output mut Io,
    buf: &'output mut [u8],
) -> Result<D, DeserializeError> {
    let mut deserializer = postcard::Deserializer::from_flavor(DeFlavor::new(io, buf));
    match D::deserialize(&mut deserializer) {
        Ok(d) => Ok(d),
        Err(e) => {
            let e = deserializer
                .finalize()
                .unwrap()
                .unwrap_or(DeserializeError::Postcard(e));
            Err(e)
        }
    }
}

///////////////////////////////////////////////////////////////////////////////////////////////////
//
// So... What's the deal with us returning `postcard::Error::NotYetImplemented` below?
// ===================================================================================
//
// The Postcard wire format is awesome, but the way it propagates errors is... Less awesome.
// (To be fair - the authors are aware and are trying to fix this in v2).
//
// We need a way to smuggle errors past Postcard's `Error` unit enum, so when an error
// occurs we record the real cause in a field of our flavor structs and return
// `NotYetImplemented` because it's an error Postcard would never actually return (since we don't
// use any of its unimplemented functionality).
//
// On the other end, after the Serde call completes, we call `finalize()` to unwrap our flavor
// object, allowing us to read the real error that occurred (if any).
//
///////////////////////////////////////////////////////////////////////////////////////////////////

struct SerFlavor<'io, Io> {
    io: &'io mut Io,
    error: Option<SerializeError>,
}

impl<'io, Io> SerFlavor<'io, Io> {
    pub fn new(io: &'io mut Io) -> Self {
        Self { io, error: None }
    }
}

impl<'io, Io: io::Io> postcard::ser_flavors::Flavor for SerFlavor<'io, Io> {
    type Output = Option<SerializeError>;

    fn try_push(&mut self, data: u8) -> postcard::Result<()> {
        match self.io.write_all(&[data]) {
            Ok(()) => Ok(()),
            Err(e) => {
                self.error = Some(SerializeError::Io(e));
                Err(postcard::Error::NotYetImplemented)
            }
        }
    }

    fn finalize(self) -> postcard::Result<Self::Output> {
        Ok(self.error)
    }

    fn try_extend(&mut self, data: &[u8]) -> postcard::Result<()> {
        match self.io.write_all(data) {
            Ok(()) => Ok(()),
            Err(e) => {
                self.error = Some(SerializeError::Io(e));
                Err(postcard::Error::NotYetImplemented)
            }
        }
    }
}

struct DeFlavor<'io, 'buf, Io> {
    inner: DeFlavorInner<'io, 'buf, Io>,
    error: Option<DeserializeError>,
}

impl<'io, 'buf, Io> DeFlavor<'io, 'buf, Io> {
    fn new(io: &'io mut Io, buf: &'buf mut [u8]) -> Self {
        Self {
            inner: DeFlavorInner {
                io,
                alloc_buf: BumpAllocator::new(buf),
                temp_buf: [0u8; MAX_TEMP_LEN],
            },
            error: None,
        }
    }
    fn with_inner<'a, F, T>(&'a mut self, f: F) -> postcard::Result<T>
    where
        F: FnOnce(&'a mut DeFlavorInner<'io, 'buf, Io>) -> Result<T, DeserializeError>,
    {
        let (inner, error) = (&mut self.inner, &mut self.error);

        match f(inner) {
            Ok(t) => Ok(t),
            Err(e) => {
                *error = Some(e);
                Err(Error::NotYetImplemented)
            }
        }
    }
}

impl<'io, 'buf, Io: io::Io> postcard::de_flavors::Flavor<'buf> for DeFlavor<'io, 'buf, Io>
where
    Self: 'buf,
{
    type Remainder = Option<DeserializeError>;

    type Source = ();

    fn pop(&mut self) -> postcard::Result<u8> {
        self.with_inner(|inner| inner.pop())
    }

    fn try_take_n(&mut self, ct: usize) -> postcard::Result<&'buf [u8]> {
        self.with_inner(|inner| inner.try_take_n(ct))
    }

    fn finalize(self) -> postcard::Result<Self::Remainder> {
        Ok(self.error)
    }

    fn try_take_n_temp<'a>(&'a mut self, ct: usize) -> postcard::Result<&'a [u8]>
    where
        'buf: 'a,
    {
        self.with_inner(|inner| inner.try_take_n_temp(ct))
    }
}

struct DeFlavorInner<'io, 'buf, Io> {
    io: &'io mut Io,
    alloc_buf: BumpAllocator<'buf>,
    temp_buf: [u8; MAX_TEMP_LEN],
}

impl<'io, 'buf, Io: io::Io> DeFlavorInner<'io, 'buf, Io>
where
    Self: 'buf,
{
    fn pop(&mut self) -> Result<u8, DeserializeError> {
        let mut buf = [0u8];
        self.io.read_exact(&mut buf).map_err(DeserializeError::Io)?;
        Ok(buf[0])
    }

    fn try_take_n(&mut self, ct: usize) -> Result<&'buf [u8], DeserializeError> {
        let buf = self
            .alloc_buf
            .allocate(ct)
            .ok_or(DeserializeError::BufferTooSmall)?;
        self.io.read_exact(buf).map_err(DeserializeError::Io)?;
        Ok(buf)
    }

    fn try_take_n_temp<'a>(&'a mut self, ct: usize) -> Result<&'a [u8], DeserializeError>
    where
        'buf: 'a,
    {
        let buf = self
            .temp_buf
            .get_mut(0..ct)
            .ok_or(DeserializeError::BufferTooSmall)?;
        self.io.read_exact(buf).map_err(DeserializeError::Io)?;
        Ok(buf)
    }
}

struct BumpAllocator<'buf> {
    start: *mut u8,
    end: *mut u8,
    phantom: PhantomData<&'buf mut [u8]>,
}

impl<'buf> BumpAllocator<'buf> {
    pub fn new(buf: &'buf mut [u8]) -> Self {
        let Range { start, end } = buf.as_mut_ptr_range();
        Self {
            start,
            end,
            phantom: PhantomData,
        }
    }
    pub fn allocate(&mut self, n: usize) -> Option<&'buf mut [u8]> {
        let bytes_left = (self.end as usize) - (self.start as usize);
        if bytes_left < n {
            return None;
        }
        unsafe {
            let buf = core::slice::from_raw_parts_mut(self.start, n);
            self.start = self.start.add(n);
            Some(buf)
        }
    }
}
