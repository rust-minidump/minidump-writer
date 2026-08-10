use super::remote;
use remote::wire;
use serde::{Deserialize, Serialize};

#[cfg(feature = "postcard")]
pub use wire::transport::postcard::Executor as Postcard;

pub trait Transport: core::fmt::Debug {
    fn read_request<'args, D: Deserialize<'args>>(
        &'args mut self,
    ) -> core::result::Result<D, Error>;
    fn write_response<S: Serialize>(&mut self, resp: S) -> core::result::Result<(), Error>;
}

#[derive(Debug, thiserror::Error, Deserialize, Serialize)]
pub enum Error {
    #[error("an error occurred deserializing the request")]
    DeserializeRequest(#[source] wire::transport::DeserializeError),
    #[error("an error occurred serializing the response")]
    SerializeResponse(#[source] wire::transport::SerializeError),
}
