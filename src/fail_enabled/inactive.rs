#[macro_export]
macro_rules! if_fail_enabled_else(($n: ident, $enabled: expr, $disabled: expr $(,)?) => {$disabled});

#[macro_export]
macro_rules! if_fail_enabled(($n: ident, $e: expr $(,)?) => {});

#[macro_export]
macro_rules! return_err_if_fail_enabled(($n: ident, $f: expr $(,)?) => {});
