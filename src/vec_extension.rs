//! Vec extension functions/methods.

/// We need a TryReserveError that is serializable, so we create one here.
#[derive(Debug, thiserror::Error, serde::Serialize)]
#[error("{}", .0)]
pub struct TryReserveError(String);

impl From<std::collections::TryReserveError> for TryReserveError {
    fn from(value: std::collections::TryReserveError) -> Self {
        Self(value.to_string())
    }
}

pub fn vec_with_capacity<T>(capacity: usize) -> Result<Vec<T>, TryReserveError> {
    let mut v = Vec::new();
    v.try_reserve_exact(capacity)?;
    Ok(v)
}
