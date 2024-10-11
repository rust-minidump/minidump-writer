//! Handling of "soft errors" while generating the minidump

/// Encapsulates a list of "soft error"s
///
/// A "soft error" is an error that is encounted while generating the minidump that doesn't
/// totally prevent the minidump from being useful, but it may have missing or invalid
/// information.
///
/// It should be returned by a function when the function was able to at-least partially achieve
/// its goals, and when further use of functions in the same API is permissible and can still be
/// at-least partially functional.
///
/// Admittedly, this concept makes layers of abstraction a bit more difficult, as something that
/// is considered "soft" by one layer may be a deal-breaker for the layer above it, or visa-versa
/// -- an error that a lower layer considers a total failure might just be a nuissance for the layer
/// above it.
///
/// An example of the former might be the act of suspending all the threads -- The `PTraceDumper``
/// API will actually work just fine even if none of the threads are suspended, so it only returns
/// a soft error; however, the dumper itself considers it to be a critical failure if not even one
/// thread could be stopped.
///
/// An example of the latter might trying to stop the process -- Being unable to send SIGSTOP to
/// the process would be considered a critical failure by `stop_process()`, but merely an
/// inconvenience by the code that's calling it.
#[must_use]
pub struct SoftErrorList<E> {
    errors: Vec<E>,
}

impl<E> SoftErrorList<E> {
    /// Returns `Some(Self)` if the list contains at least one soft error
    pub fn some(self) -> Option<Self> {
        if !self.is_empty() {
            Some(self)
        } else {
            None
        }
    }
    /// Returns `true` if the list is empty
    pub fn is_empty(&self) -> bool {
        self.errors.is_empty()
    }
    /// Add a soft error to the list
    pub fn push(&mut self, error: E) {
        self.errors.push(error);
    }
}

impl<E> Default for SoftErrorList<E> {
    fn default() -> Self {
        Self { errors: Vec::new() }
    }
}

impl<E: std::error::Error> SoftErrorList<E> {
    // Helper function for the Debug and Display traits
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>, write_sources: bool) -> std::fmt::Result {
        writeln!(f, "one or more soft errors occurred:")?;
        writeln!(f)?;
        for (i, e) in self.errors.iter().enumerate() {
            writeln!(f, "  {i}:")?;

            for line in e.to_string().lines() {
                writeln!(f, "    {line}")?;
            }

            writeln!(f)?;

            if write_sources {
                let mut source = e.source();
                while let Some(e) = source {
                    writeln!(f, "    caused by:")?;

                    for line in e.to_string().lines() {
                        writeln!(f, "      {line}")?;
                    }

                    writeln!(f)?;

                    source = e.source();
                }
            }
        }
        Ok(())
    }
}

impl<E: std::error::Error> std::fmt::Debug for SoftErrorList<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.fmt(f, true)
    }
}

impl<E: std::error::Error> std::fmt::Display for SoftErrorList<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.fmt(f, false)
    }
}

impl<E: std::error::Error> std::error::Error for SoftErrorList<E> {}
