use std::sync::{LazyLock, Mutex, MutexGuard};

/// Evaluates to the second argument if fail is enabled, otherwise the third argument.
#[macro_export]
macro_rules! if_fail_enabled_else(($n: ident, $enabled: expr, $disabled: expr $(,)?) => {{
    if $crate::fail_enabled::Config::get().fail_enabled(crate::fail_enabled::FailName::$n) {
        $enabled
    } else {
        $disabled
    }
}});

/// Executes the given statement if fail is enabled
#[macro_export]
macro_rules! if_fail_enabled(($n: ident, $e: expr $(,)?) => {{
    $crate::if_fail_enabled_else!($n, $e, ());
}});

/// Returns the given error type (converted with into()) if fail is enabled
#[macro_export]
macro_rules! return_err_if_fail_enabled(($n: ident, $f: expr $(,)?) => {{
    crate::if_fail_enabled!($n, return Err($f.into()));
}});

/// Defines a set of flags that can be safely read and written from multiple threads
macro_rules! atomic_flags(($s: ident<Name = $n: ident> {
    $($f: ident,)+
}) => {
    /// The names of the supported atomic flags
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum $n {
        $($f,)+
    }

    impl $n {
        /// The total number of flags
        pub const COUNT: usize = last_ident!($n, $($f),+) as usize + 1;
    }

    /// An array of AtomicBool that holds the values for all the flags
    #[derive(Debug, Default)]
    pub struct $s([core::sync::atomic::AtomicBool; $n::COUNT]);

    impl $s {
        /// Determine whether a flag is enabled
        pub fn get(&self, flag: $n) -> bool {
            self.0[flag as usize].load(core::sync::atomic::Ordering::Acquire)
        }
        /// Set whether a flag is enabled
        pub fn set(&self, flag: $n, value: bool) {
            self.0[flag as usize].store(value, core::sync::atomic::Ordering::Release)
        }
        /// Disable all flags
        pub fn clear(&self) {
            for flag in &self.0 {
                flag.store(false, core::sync::atomic::Ordering::Release);
            }
        }
        /// Test whether all flags are disabled
        pub fn all_clear(&self) -> bool {
            for flag in &self.0 {
                let value = flag.load(core::sync::atomic::Ordering::Acquire);
                if value {
                    return false;
                }
            }
            true
        }
    }
});

/// Retrieves the last identifier passed to it
///
/// Useful to determine the name of the last entry in an enum.
macro_rules! last_ident {
    {$n: ident, $first: ident, $($tail: ident),+} => {
        last_ident!($n, $($tail),+)
    };
    {$n: ident, $last: ident} => {
        $n::$last
    };
}

atomic_flags!(FailEnabledFlags<Name = FailName> {
    StopProcess,
    FillMissingAuxvInfo,
    ThreadName,
    SuspendThreads,
    CpuInfoFileOpen,
});

/// Configuration for the fail_enabled module
///
/// Generally there will only be one of these that can be obtained via [Config::get()]
#[derive(Debug, Default)]
pub struct Config {
    fail_enabled_flags: FailEnabledFlags,
    client_mutex: Mutex<()>,
}

impl Config {
    /// Get a reference to the global object
    pub fn get() -> &'static Config {
        static INSTANCE: LazyLock<Config> = LazyLock::new(Config::default);
        &INSTANCE
    }
    /// Return an exclusive client that a test can use to set its fail config
    ///
    /// As long as the returned object is held, no other test can mutate the fail enabled flags
    pub fn client(&self) -> FailClient<'_> {
        // We don't care if the lock gets poisoned, since this mutex isn't protecting any data
        let _guard = match self.client_mutex.lock() {
            Ok(guard) => guard,
            Err(e) => e.into_inner(),
        };
        assert!(
            self.fail_enabled_flags.all_clear(),
            "flags were not properly cleared by last client"
        );
        FailClient {
            config: self,
            _guard,
        }
    }
    /// Check to see if a given fail is enabled
    ///
    /// Used by all the macros in this module
    pub(crate) fn fail_enabled(&self, fail: FailName) -> bool {
        self.fail_enabled_flags.get(fail)
    }
}

/// An exclusive client that can change the fail flags
///
/// It is protected by a mutex so that only one test may ever hold this at a time.
#[derive(Debug)]
pub struct FailClient<'a> {
    config: &'a Config,
    _guard: MutexGuard<'a, ()>,
}

impl<'a> FailClient<'a> {
    /// Change whether a fail is enabled or not
    pub fn set_fail_enabled(&self, fail: FailName, enabled: bool) {
        self.config.fail_enabled_flags.set(fail, enabled);
    }
}

/// Will disable all fails
impl<'a> Drop for FailClient<'a> {
    fn drop(&mut self) {
        self.config.fail_enabled_flags.clear();
    }
}
