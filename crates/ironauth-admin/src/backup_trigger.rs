// SPDX-License-Identifier: MIT OR Apache-2.0

//! The on-demand backup trigger (issue #153): the in-process wake-up the management
//! endpoint signals and the scheduled backup runner awaits.
//!
//! # Why a notify AND a durable record
//!
//! The trigger is NOT the command. The management endpoint writes the audited record
//! (who asked, when, with which idempotency key) through the store, and answers 202
//! whatever this process can do about it: a request issued while the scheduler is down
//! is honoured by the next boot's first pass. The trigger is the LATENCY half - waking
//! the runner the moment a request lands, instead of waiting out the interval - and it
//! is deliberately optional: `signal()` on a trigger nobody awaits is a no-op, so a
//! management plane mounted without a runner still records and still answers.

use std::sync::Arc;

use tokio::sync::Notify;

/// A handle to wake the scheduled backup runner.
///
/// [`signal`](Self::signal) may be called from any thread; the runner awaits
/// [`notified`](Self::notified). One trigger per process, shared between the management
/// router state and the runner loop.
#[derive(Debug, Default)]
pub struct BackupTrigger {
    notify: Arc<Notify>,
}

impl BackupTrigger {
    /// A fresh trigger.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Wake the runner.
    ///
    /// `notify_one`, deliberately not `notify_waiters`: the latter wakes only waiters that
    /// are waiting RIGHT NOW, so a signal that lands while a pass is running would be
    /// lost and the runner would sleep out the whole interval. `notify_one` stores a
    /// permit when nobody is waiting, so a signal during a pass wakes the NEXT wait -
    /// which is exactly the "an operator asked, and the next available pass performs it"
    /// contract.
    pub fn signal(&self) {
        self.notify.notify_one();
    }

    /// A future that resolves when the next [`signal`](Self::signal) fires.
    pub fn notified(&self) -> tokio::sync::futures::Notified<'_> {
        self.notify.notified()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_signalled_trigger_wakes_the_awaiting_runner() {
        let trigger = BackupTrigger::new();
        trigger.signal();
        // The signal is not missed: `notify_one` stores a permit when nobody is waiting,
        // so a runner that had not yet awaited is woken when it does - and a signal that
        // lands mid-pass wakes the next wait.
        let woken =
            tokio::time::timeout(std::time::Duration::from_secs(1), trigger.notified()).await;
        assert!(woken.is_ok(), "a signalled trigger must wake the runner");
    }

    #[tokio::test]
    async fn a_trigger_with_no_waiter_is_a_no_op() {
        let trigger = BackupTrigger::new();
        trigger.signal();
        // No panic, and the permit is consumed by a later await.
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), trigger.notified()).await;
    }
}
