use std::sync::atomic::{AtomicBool, Ordering};

pub trait ResultExt {
    fn cancel(self, cancelled: &AtomicBool) -> Self;
}

impl<A, B> ResultExt for Result<A, B> {
    fn cancel(self, cancelled: &AtomicBool) -> Self {
        if self.is_err() {
            cancelled.store(true, Ordering::Release);
        }
        self
    }
}

pub trait OptionExt<T> {
    fn is_none_or(self, f: impl FnOnce(T) -> bool) -> bool;
}

impl<T> OptionExt<T> for Option<T> {
    fn is_none_or(self, f: impl FnOnce(T) -> bool) -> bool {
        match self {
            None => true,
            Some(t) => f(t),
        }
    }
}
