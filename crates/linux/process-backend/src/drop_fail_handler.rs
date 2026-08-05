use core::sync::atomic::{AtomicPtr, Ordering};

static HANDLER: AtomicPtr<Handler> = AtomicPtr::new(core::ptr::null_mut());

pub struct Handler {
    pub(crate) f: for<'a> fn(core::fmt::Arguments<'a>),
}

impl Handler {
    pub const fn new(f: for<'a> fn(core::fmt::Arguments<'a>)) -> Self {
        Self { f }
    }
    pub fn install_global(&'static self) {
        HANDLER.store((self as *const Handler).cast_mut(), Ordering::Release);
    }
}

pub(crate) fn get() -> Option<&'static Handler> {
    let ptr: *const Handler = HANDLER.load(Ordering::Acquire).cast_const();
    if ptr.is_null() {
        None
    } else {
        Some(unsafe { &*ptr })
    }
}

macro_rules! report_drop_failed(($($arg: tt)*) => {{
    if let Some(handler) = $crate::drop_fail_handler::get() {
        (handler.f)(::core::format_args!($($arg)*));
    }
}});
