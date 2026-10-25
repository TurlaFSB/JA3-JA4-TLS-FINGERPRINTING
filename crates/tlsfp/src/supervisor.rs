// © Pranav Verma | 2026
// supervisor.rs

//! Keeps a live capture alive.
//!
//! A laptop's Wi-Fi adapter disappears when it sleeps, roams or is switched
//! off; a USB network card is unplugged; a driver is restarted. The capture
//! then fails, and without supervision the dashboard stays "online" while it
//! silently reads nothing. The supervisor notices, says so (the capture state is
//! published for the dashboard), and tries to reopen the capture with a growing
//! pause between attempts, until it works or the server stops.
//!
//! It is generic over the packet source and over how time passes, so the
//! behaviour (the pauses, the counting, the state it reports, giving up on
//! shutdown) is covered by tests that need neither a network card nor a clock.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use serde::Serialize;
use tlsfp_core::{PacketSource, SourceError};

/// The first pause before reopening, doubling up to [`MAX_DELAY`].
const FIRST_DELAY: Duration = Duration::from_secs(1);
const MAX_DELAY: Duration = Duration::from_secs(30);

/// A capture that ran at least this long before failing counts as having
/// been healthy, so the next failure starts the pauses over.
const STABLE_AFTER: Duration = Duration::from_secs(30);

/// How the capture is doing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureState {
    Running,
    /// It failed and the supervisor is waiting to try again.
    Reconnecting,
    /// The server is shutting down, or the capture cannot continue.
    Stopped,
}

/// What the dashboard is told about the capture.
#[derive(Debug, Clone, Serialize)]
pub struct CaptureStatus {
    pub state: CaptureState,
    /// How many times the capture has had to be reopened.
    pub restarts: u64,
    /// Why the capture last failed.
    pub last_error: Option<String>,
    /// Seconds until the next attempt, while reconnecting.
    pub retry_in_secs: Option<u64>,
}

impl Default for CaptureStatus {
    fn default() -> Self {
        Self {
            state: CaptureState::Running,
            restarts: 0,
            last_error: None,
            retry_in_secs: None,
        }
    }
}

/// A shared, readable copy of the status.
#[derive(Clone, Default)]
pub struct StatusHandle(Arc<Mutex<CaptureStatus>>);

impl StatusHandle {
    #[must_use]
    pub fn get(&self) -> CaptureStatus {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn update(&self, change: impl FnOnce(&mut CaptureStatus)) {
        change(&mut self.0.lock().unwrap_or_else(PoisonError::into_inner));
    }
}

/// The pause before attempt number `attempt` (counted from 1): one second,
/// doubling, never more than thirty.
#[must_use]
pub fn backoff(attempt: u32) -> Duration {
    let doublings = attempt.saturating_sub(1).min(16);
    FIRST_DELAY.saturating_mul(1u32 << doublings).min(MAX_DELAY)
}

/// Sleeps for `total` but wakes early when `shutdown` is set, so stopping the
/// server never waits out a long pause.
pub fn sleep_unless(shutdown: &AtomicBool, total: Duration) {
    let step = Duration::from_millis(200);
    let mut left = total;
    while left > Duration::ZERO && !shutdown.load(Ordering::Relaxed) {
        let nap = left.min(step);
        std::thread::sleep(nap);
        left = left.saturating_sub(nap);
    }
}

/// Runs `run` on a source until the server stops, reopening the source with
/// `open` whenever it ends or fails.
///
/// `run` drains one source and returns how it ended. `wait` pauses between
/// attempts (and is where tests skip the waiting).
pub fn supervise<S, O, R, W>(
    first: S,
    mut open: O,
    mut run: R,
    shutdown: &AtomicBool,
    status: &StatusHandle,
    mut wait: W,
) where
    S: PacketSource,
    O: FnMut() -> Result<S, String>,
    R: FnMut(&mut S) -> Result<(), SourceError>,
    W: FnMut(Duration),
{
    let mut source = first;
    let mut attempt: u32 = 0;
    loop {
        status.update(|s| {
            s.state = CaptureState::Running;
            s.retry_in_secs = None;
        });
        let started = Instant::now();
        let ended = run(&mut source);
        if shutdown.load(Ordering::Relaxed) {
            status.update(|s| s.state = CaptureState::Stopped);
            return;
        }
        if started.elapsed() >= STABLE_AFTER {
            attempt = 0;
        }
        let mut reason = match ended {
            Err(error) => error.to_string(),
            Ok(()) => "the capture ended unexpectedly".to_owned(),
        };
        tracing::warn!(%reason, "live capture stopped; trying to reopen it");
        loop {
            attempt = attempt.saturating_add(1);
            let delay = backoff(attempt);
            status.update(|s| {
                s.state = CaptureState::Reconnecting;
                s.last_error = Some(reason.clone());
                s.retry_in_secs = Some(delay.as_secs());
            });
            wait(delay);
            if shutdown.load(Ordering::Relaxed) {
                status.update(|s| s.state = CaptureState::Stopped);
                return;
            }
            match open() {
                Ok(reopened) => {
                    source = reopened;
                    status.update(|s| s.restarts += 1);
                    tracing::info!(attempt, "live capture reopened");
                    break;
                }
                Err(error) => reason = error,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tlsfp_core::RawFrame;

    struct Fake;

    impl PacketSource for Fake {
        fn next_frame(&mut self) -> Result<Option<RawFrame<'_>>, SourceError> {
            Ok(None)
        }
    }

    #[test]
    fn the_pauses_double_and_stop_at_thirty_seconds() {
        let secs: Vec<u64> = (1..=8).map(|n| backoff(n).as_secs()).collect();
        assert_eq!(secs, [1, 2, 4, 8, 16, 30, 30, 30]);
        assert_eq!(backoff(0).as_secs(), 1);
        assert_eq!(backoff(u32::MAX).as_secs(), 30);
    }

    #[test]
    fn a_failed_capture_is_reopened_after_growing_pauses_and_counted() {
        let shutdown = AtomicBool::new(false);
        let status = StatusHandle::default();
        let mut pauses = Vec::new();
        let mut opens = 0;
        let mut runs = 0;
        supervise(
            Fake,
            || {
                opens += 1;
                // The first two reopen attempts fail, the third works.
                if opens < 3 {
                    Err(format!("adapter not ready ({opens})"))
                } else {
                    Ok(Fake)
                }
            },
            |_| {
                runs += 1;
                if runs == 1 {
                    Err(SourceError::Capture("the adapter went away".into()))
                } else {
                    shutdown.store(true, Ordering::Relaxed);
                    Ok(())
                }
            },
            &shutdown,
            &status,
            |d| pauses.push(d.as_secs()),
        );
        assert_eq!(pauses, [1, 2, 4]);
        let end = status.get();
        assert_eq!(end.restarts, 1);
        assert_eq!(end.state, CaptureState::Stopped);
        assert!(end.last_error.unwrap().contains("adapter not ready"));
    }

    #[test]
    fn it_reports_that_it_is_reconnecting_while_it_waits() {
        let shutdown = AtomicBool::new(false);
        let status = StatusHandle::default();
        let seen = std::cell::RefCell::new(Vec::new());
        supervise(
            Fake,
            || Ok(Fake),
            |_| {
                if seen.borrow().is_empty() {
                    Err(SourceError::Capture("unplugged".into()))
                } else {
                    shutdown.store(true, Ordering::Relaxed);
                    Ok(())
                }
            },
            &shutdown,
            &status,
            |d| {
                seen.borrow_mut().push((
                    status.get().state,
                    status.get().retry_in_secs,
                    d.as_secs(),
                ));
            },
        );
        let during = seen.borrow()[0];
        assert_eq!(during, (CaptureState::Reconnecting, Some(1), 1));
        assert_eq!(
            status.get().last_error.as_deref(),
            Some("capture source failed: unplugged")
        );
    }

    #[test]
    fn stopping_the_server_ends_supervision_without_reopening() {
        let shutdown = AtomicBool::new(false);
        let status = StatusHandle::default();
        let mut opened = false;
        supervise(
            Fake,
            || {
                opened = true;
                Ok(Fake)
            },
            |_| {
                shutdown.store(true, Ordering::Relaxed);
                Err(SourceError::Capture("closing".into()))
            },
            &shutdown,
            &status,
            |_| {},
        );
        assert!(!opened);
        assert_eq!(status.get().state, CaptureState::Stopped);
        assert_eq!(status.get().restarts, 0);
    }

    #[test]
    fn a_pause_is_cut_short_by_shutdown() {
        let shutdown = AtomicBool::new(true);
        let started = Instant::now();
        sleep_unless(&shutdown, Duration::from_secs(30));
        assert!(started.elapsed() < Duration::from_secs(1));
    }
}
