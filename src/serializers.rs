//! Functions used by Serde to serialize types that we don't own (and thus can't implement
//! [Serialize] for)

use serde::Serializer;
/// Useful for types that implement [Error][std::error::Error] and don't need any special
/// treatment.
fn serialize_generic_error<S: Serializer, E: std::error::Error>(
    error: &E,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    // I guess we'll have to see if it's more useful to store the debug representation of a
    // foreign error type or something else (like maybe iterating its error chain into a
    // list?)
    let dbg = format!("{error:#?}");
    serializer.serialize_str(&dbg)
}
/// Serialize [std::io::Error]
pub fn serialize_io_error<S: Serializer>(
    error: &std::io::Error,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serialize_generic_error(error, serializer)
}
/// Serialize [goblin::error::Error]
pub fn serialize_goblin_error<S: Serializer>(
    error: &goblin::error::Error,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serialize_generic_error(error, serializer)
}
/// Serialize [nix::Error]
pub fn serialize_nix_error<S: Serializer>(
    error: &nix::Error,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serialize_generic_error(error, serializer)
}
/// Serialize [procfs_core::ProcError]
pub fn serialize_proc_error<S: Serializer>(
    error: &procfs_core::ProcError,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serialize_generic_error(error, serializer)
}
/// Serialize [std::string::FromUtf8Error]
pub fn serialize_from_utf8_error<S: Serializer>(
    error: &std::string::FromUtf8Error,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serialize_generic_error(error, serializer)
}
/// Serialize [std::time::SystemTimeError]
pub fn serialize_system_time_error<S: Serializer>(
    error: &std::time::SystemTimeError,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serialize_generic_error(error, serializer)
}
/// Serialize [scroll::Error]
pub fn serialize_scroll_error<S: Serializer>(
    error: &scroll::Error,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serialize_generic_error(error, serializer)
}
