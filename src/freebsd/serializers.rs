//! Functions used by Serde to serialize types that we don't own (and thus can't implement
//! [Serialize] for)

use {crate::serializers::*, serde::Serializer};

/// Serialize [goblin::error::Error]
pub fn serialize_goblin_error<S: Serializer>(
    error: &goblin::error::Error,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serialize_generic_error(error, serializer)
}

/// Serialize [std::string::FromUtf8Error]
#[allow(dead_code)]
pub fn serialize_from_utf8_error<S: Serializer>(
    error: &std::string::FromUtf8Error,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serialize_generic_error(error, serializer)
}

/// Serialize [std::time::SystemTimeError]
#[allow(dead_code)]
pub fn serialize_system_time_error<S: Serializer>(
    error: &std::time::SystemTimeError,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serialize_generic_error(error, serializer)
}

pub fn serialize_io_error<S: Serializer>(
    error: &std::io::Error,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serialize_generic_error(error, serializer)
}
