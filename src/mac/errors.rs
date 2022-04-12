use thiserror::Error;

use mach2::kern_return::kern_return_t;

#[derive(Debug, Error)]
pub enum WriterError {
    #[error("kernel error ({})", _0)]
    Kernel(kern_return_t),
}

#[inline]
pub(crate) fn kern_ret(func: impl FnOnce() -> kern_return_t) -> Result<(), WriterError> {
    let res = func();

    if res == KERN_SUCCESS {
        Ok(())
    } else {
        Err(WriterError::Kerne(res))
    }
}
