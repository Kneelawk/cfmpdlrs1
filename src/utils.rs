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
