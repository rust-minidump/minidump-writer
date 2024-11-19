//! Encapsulates a list of "soft error"s
//!
//! A "soft error" is an error that is encounted while generating the minidump that doesn't
//! totally prevent the minidump from being useful, but it may have missing or invalid
//! information.
//!
//! It should be returned by a function when the function was able to at-least partially achieve
//! its goals, and when further use of functions in the same API is permissible and can still be
//! at-least partially functional.
//!
//! Admittedly, this concept makes layers of abstraction a bit more difficult, as something that
//! is considered "soft" by one layer may be a deal-breaker for the layer above it, or visa-versa
//! -- an error that a lower layer considers a total failure might just be a nuissance for the layer
//! above it.
//!
//! An example of the former might be the act of suspending all the threads -- The `PTraceDumper``
//! API will actually work just fine even if none of the threads are suspended, so it only returns
//! a soft error; however, the dumper itself considers it to be a critical failure if not even one
//! thread could be stopped.
//!
//! An example of the latter might trying to stop the process -- Being unable to send SIGSTOP to
//! the process would be considered a critical failure by `stop_process()`, but merely an
//! inconvenience by the code that's calling it.

use serde::Serialize;

/// Holds a list of soft errors. See module-level docs.
#[derive(Debug)]
pub struct SoftErrorList<E> {
    errors: Vec<E>,
}

impl SoftErrorList<()> {
    /// Create a sublist that will never be used
    ///
    /// Useful when calling a function that returns soft errors, but the caller doesn't care.
    pub fn null_sublist<T>() -> SoftErrorSublist<'static, T> {
        SoftErrorSublist {
            list: SoftErrorList::default(),
            sink: None,
        }
    }
}

impl<E> SoftErrorList<E> {
    /// Returns true if there are no errors in the list
    pub fn is_empty(&self) -> bool {
        self.errors.is_empty()
    }
    /// Returns the number of errors in the list
    pub fn len(&self) -> usize {
        self.errors.len()
    }
    /// Add a new error to the end of the list
    pub fn push(&mut self, error: E) {
        self.errors.push(error);
    }
    /// Immutable iteration of the list items
    pub fn iter(&self) -> impl Iterator<Item = &E> {
        self.errors.iter()
    }
    /// Mutable iteration of the list items
    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut E> {
        self.errors.iter_mut()
    }
    /// Create a sublist that will be inserted directly into the caller's error list
    ///
    /// Useful for a group of highly-cohesive functions that should all return one list of soft
    /// errors
    pub fn inserted_sublist<'a>(&'a mut self) -> SoftErrorSublist<'a, E> {
        SoftErrorSublist {
            list: SoftErrorList::default(),
            sink: Some(Box::new(SimplePush { target: self })),
        }
    }
    /// Create a sublist that will be mapped into a single error in the caller's error list
    ///
    /// This is useful to bridge abstraction boundaries, where an entire list of soft errors that
    /// occurred during a subfunction are wrapped up in a single error item on the caller's side
    /// and pushed into the caller's error list.
    pub fn map_sublist<'a, T, F>(&'a mut self, map_fn: F) -> SoftErrorSublist<'a, T>
    where
        F: FnOnce(SoftErrorList<T>) -> E + 'a,
    {
        SoftErrorSublist {
            list: SoftErrorList::default(),
            sink: Some(Box::new(MapPush {
                map_fn,
                target: self,
            })),
        }
    }
}

impl<E: Serialize> SoftErrorList<E> {
    pub fn to_json(&self) -> Result<serde_json::Value, serde_json::Error> {
        serde_json::to_value(self)
    }
}

impl<E: Serialize> Serialize for SoftErrorList<E> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.errors.serialize(serializer)
    }
}

impl<E> Default for SoftErrorList<E> {
    fn default() -> Self {
        Self { errors: Vec::new() }
    }
}

impl<E: std::error::Error> std::fmt::Display for SoftErrorList<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "one or more soft errors occurred:")?;
        writeln!(f)?;
        for (i, e) in self.errors.iter().enumerate() {
            writeln!(f, "  {i}:")?;

            for line in e.to_string().lines() {
                writeln!(f, "    {line}")?;
            }

            writeln!(f)?;

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
        Ok(())
    }
}

impl<E: std::error::Error> std::error::Error for SoftErrorList<E> {}

impl<E> IntoIterator for SoftErrorList<E> {
    type Item = <Vec<E> as IntoIterator>::Item;
    type IntoIter = <Vec<E> as IntoIterator>::IntoIter;
    fn into_iter(self) -> Self::IntoIter {
        self.errors.into_iter()
    }
}

/// A sublist that will be merged into the caller's error list on [Drop]
///
/// Every sublist holds a reference to the caller's error list for its lifetime. When the sublist
/// goes out of scope, it will be merged into the caller's error list using whatever strategy the
/// caller asked for. Current strategies are: "do nothing and silently drop", "directly push every
/// sublist error into caller error", and "map sublist into a single item in caller's error list".
pub struct SoftErrorSublist<'a, E> {
    list: SoftErrorList<E>,
    sink: Option<Box<dyn ErrorListSink<E> + 'a>>,
}

/// Will move the sublist into whatever [ErrorListSink] was passed in during creation
impl<'a, E> Drop for SoftErrorSublist<'a, E> {
    fn drop(&mut self) {
        if !self.list.is_empty() {
            let list = std::mem::take(&mut self.list);
            let sink = self.sink.take().unwrap();
            sink.sink(list);
        }
    }
}

impl<'a, E> std::ops::Deref for SoftErrorSublist<'a, E> {
    type Target = SoftErrorList<E>;
    fn deref(&self) -> &Self::Target {
        &self.list
    }
}

impl<'a, E> std::ops::DerefMut for SoftErrorSublist<'a, E> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.list
    }
}

/// Something that can accept a [SoftErrorList]
///
/// Will be implemented by the different strategies for merging a sublist into its caller's
/// object.
trait ErrorListSink<E> {
    fn sink(self: Box<Self>, list: SoftErrorList<E>);
}

/// An ErrorListSink that will use a mapping function to convert the list to the caller's error
/// type and push it on their list.
struct MapPush<'a, F, TargetErr> {
    map_fn: F,
    target: &'a mut SoftErrorList<TargetErr>,
}

impl<'a, F, SourceErr, TargetErr> ErrorListSink<SourceErr> for MapPush<'a, F, TargetErr>
where
    F: FnOnce(SoftErrorList<SourceErr>) -> TargetErr,
{
    fn sink(self: Box<Self>, list: SoftErrorList<SourceErr>) {
        let target_error = (self.map_fn)(list);
        self.target.push(target_error);
    }
}

/// An ErrorListSink that will simply push all items in the list onto the caller's error list
/// without any conversion.
struct SimplePush<'a, E> {
    target: &'a mut SoftErrorList<E>,
}

impl<'a, E> ErrorListSink<E> for SimplePush<'a, E> {
    fn sink(self: Box<Self>, list: SoftErrorList<E>) {
        self.target.errors.extend(list.errors);
    }
}

/// Functions used by Serde to serialize types that we don't own (and thus can't implement
/// [Serialize] for)
pub mod serializers {
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
}

#[cfg(test)]
mod test {
    use super::*;

    #[derive(Debug)]
    enum OuterError {
        Outer,
        Middle(SoftErrorList<MiddleError>),
    }

    #[derive(Debug)]
    enum MiddleError {
        Middle,
        Inner(SoftErrorList<InnerError>),
    }

    #[derive(Debug)]
    enum InnerError {
        Foobar,
    }

    #[test]
    fn basic() {
        let mut soft_errors = SoftErrorList::default();
        soft_errors.push(OuterError::Outer);
        middle(soft_errors.map_sublist(OuterError::Middle));
        soft_errors.push(OuterError::Outer);

        // Check outer
        let mut outer_it = soft_errors.into_iter();
        assert!(matches!(outer_it.next(), Some(OuterError::Outer)));
        let Some(OuterError::Middle(middle)) = outer_it.next() else {
            panic!();
        };
        assert!(matches!(outer_it.next(), Some(OuterError::Outer)));

        // Check middle
        let mut middle_it = middle.into_iter();
        assert!(matches!(middle_it.next(), Some(MiddleError::Middle)));
        let Some(MiddleError::Inner(inner)) = middle_it.next() else {
            panic!();
        };
        assert!(matches!(middle_it.next(), Some(MiddleError::Middle)));

        // Check inner
        let mut inner_it = inner.into_iter();
        assert!(matches!(inner_it.next(), Some(InnerError::Foobar)));
    }

    fn middle(mut soft_errors: SoftErrorSublist<'_, MiddleError>) {
        soft_errors.push(MiddleError::Middle);
        inner(soft_errors.map_sublist(MiddleError::Inner));
        soft_errors.push(MiddleError::Middle);
    }

    fn inner(mut soft_errors: SoftErrorSublist<'_, InnerError>) {
        soft_errors.push(InnerError::Foobar);
    }
}
