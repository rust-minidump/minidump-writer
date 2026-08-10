use super::remote;
use remote::wire;
use serde::{Deserialize, Serialize};

#[cfg(feature = "postcard")]
pub use wire::transport::postcard::Backend as Postcard;

pub trait Transport: core::fmt::Debug {
    fn send_request<'output, Req: Serialize, Resp: Deserialize<'output>>(
        &'output mut self,
        req: Req,
    ) -> core::result::Result<Resp, Error>;
}

#[derive(Debug, thiserror::Error, Deserialize, Serialize)]
pub enum Error {
    #[error("an error occurred serializing the request")]
    SerializeRequest(#[source] wire::transport::SerializeError),
    #[error("an error occurred deserializing the response")]
    DeserializeResponse(#[source] wire::transport::DeserializeError),
}
