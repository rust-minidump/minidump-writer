//! Allows testing code to configure intentional failures at various codepaths
//!
//! It is often useful during testing to force certain codepaths to return an error even if they
//! would have otherwise succeeded.
//!
//! There are several macros that will be defined at the crate level that can be used by code that
//! should be tested:
//!
//! -   `if_fail_enabled_else!(name, expr_if_enabled, expr_if_disabled)`: Evaluates to the first
//!     expression if fail `name` is enabled, otherwise evaluates to the second expression.
//!
//! -   `if_fail_enabled!(name, stmt)`: If fail `name` is enabled, will execute the given
//!     statement.
//!
//! -   `return_err_if_fail_enabled(name, err_expr)`: If fail `name` is enabled, will perform a
//!     `return Err(err_expr.into())`.
//!
//! All of the above macros are no-op if the `fail-enabled` feature is not enabled.
//!
//! # Testing Code
//!
//! Testing code will generally use the global [Config] object via [Config::get]. Calling the
//! [client][Config::client] function will return a [FailClient] object. This object is
//! protected by a mutex so that only one such object can exist in the process at a time. This
//! is necessary because tests in the same source file run concurrently with each other.
//!
//! When the [FailClient] is dropped, all enabled fails will be disabled. This ensures the next
//! test will start with a fresh state.

#[cfg(feature = "fail-enabled")]
mod active;
#[cfg(feature = "fail-enabled")]
pub use active::*;

#[cfg(not(feature = "fail-enabled"))]
mod inactive;
