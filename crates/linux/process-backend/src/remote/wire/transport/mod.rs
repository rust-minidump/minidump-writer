use super::remote;
use remote::io;

#[cfg(feature = "postcard")]
pub(crate) mod postcard;

#[derive(Debug, thiserror::Error, serde::Deserialize, serde::Serialize)]
pub enum SerializeError {
    #[cfg(feature = "postcard")]
    #[error("a Postcard-specific serialize error occurred")]
    Postcard(#[source] postcard::Error),
    #[error("an I/O occurred during serialization")]
    Io(#[source] io::Error),
}

#[derive(Debug, thiserror::Error, serde::Deserialize, serde::Serialize)]
pub enum DeserializeError {
    #[cfg(feature = "postcard")]
    #[error("a Postcard-specific deserialize error occurred")]
    Postcard(#[source] postcard::Error),
    #[error("an I/O occurred during deserialization")]
    Io(#[source] io::Error),
    #[error("the I/O buffer was too small")]
    BufferTooSmall,
}
