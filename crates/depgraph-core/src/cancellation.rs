use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};

use tokio::sync::watch;

#[derive(Debug, Clone, Default)]
pub struct CancellationToken {
    inner: Arc<CancellationState>,
}

#[derive(Debug)]
struct CancellationState {
    cancelled: AtomicBool,
    changed: watch::Sender<bool>,
    completion: Mutex<()>,
}

impl Default for CancellationState {
    fn default() -> Self {
        let (changed, _) = watch::channel(false);
        Self {
            cancelled: AtomicBool::new(false),
            changed,
            completion: Mutex::new(()),
        }
    }
}

impl CancellationToken {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cancel(&self) -> bool {
        let _completion = self
            .inner
            .completion
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let was_cancelled = self.inner.cancelled.swap(true, Ordering::AcqRel);
        if !was_cancelled {
            self.inner.changed.send_replace(true);
        }
        !was_cancelled
    }

    pub fn is_cancelled(&self) -> bool {
        self.inner.cancelled.load(Ordering::Acquire)
    }

    pub async fn cancelled(&self) {
        let mut changed = self.inner.changed.subscribe();
        while !*changed.borrow() {
            changed
                .changed()
                .await
                .expect("cancellation sender is retained by the token");
        }
    }

    /// Run one handoff atomically with respect to cancellation. If cancellation
    /// linearizes first the closure is not called; otherwise cancellation waits
    /// until the closure has handed off its work.
    pub fn run_if_active<T>(&self, operation: impl FnOnce() -> T) -> Option<T> {
        let _completion = self
            .inner
            .completion
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        (!self.is_cancelled()).then(operation)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn cancellation_is_idempotent_and_visible_to_existing_and_late_waiters() {
        let token = CancellationToken::new();
        let waiter = tokio::spawn({
            let token = token.clone();
            async move { token.cancelled().await }
        });

        assert!(token.cancel());
        assert!(!token.cancel());
        waiter.await.unwrap();
        token.cancelled().await;
        assert!(token.is_cancelled());
    }

    #[test]
    fn completion_and_cancellation_have_one_linearization_point() {
        let token = CancellationToken::new();
        assert_eq!(token.run_if_active(|| "promoted"), Some("promoted"));
        assert!(token.cancel());
        assert_eq!(token.run_if_active(|| "too late"), None);
    }
}
