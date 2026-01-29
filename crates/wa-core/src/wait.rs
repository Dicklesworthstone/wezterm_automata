//! Shared wait-for utilities (no fixed sleeps).
//!
//! Provides retry-with-backoff helpers for tests and control loops.

use std::fmt;
use std::future::Future;
use std::pin::Pin;

use tokio::time::{Duration, Instant, sleep};

/// Backoff configuration for wait loops.
#[derive(Debug, Clone)]
pub struct Backoff {
    /// Initial delay before the second poll.
    pub initial: Duration,
    /// Maximum delay between polls.
    pub max: Duration,
    /// Multiplicative factor for backoff growth.
    pub factor: u32,
    /// Optional max retry count (inclusive of the first attempt).
    pub max_retries: Option<usize>,
}

impl Backoff {
    /// Compute the next delay given the current delay.
    #[must_use]
    pub fn next_delay(&self, current: Duration) -> Duration {
        let next = current.saturating_mul(self.factor);
        if next > self.max { self.max } else { next }
    }
}

impl Default for Backoff {
    fn default() -> Self {
        Self {
            initial: Duration::from_millis(25),
            max: Duration::from_secs(1),
            factor: 2,
            max_retries: None,
        }
    }
}

/// Result of a predicate check in a wait loop.
#[derive(Debug, Clone)]
pub enum WaitFor<T> {
    /// Predicate satisfied.
    Ready(T),
    /// Predicate not yet satisfied.
    NotReady { last_observed: Option<String> },
}

impl<T> WaitFor<T> {
    /// Convenience constructor for Ready.
    #[must_use]
    pub fn ready(value: T) -> Self {
        Self::Ready(value)
    }

    /// Convenience constructor for NotReady.
    #[must_use]
    pub fn not_ready(last_observed: impl Into<Option<String>>) -> Self {
        Self::NotReady {
            last_observed: last_observed.into(),
        }
    }
}

/// A predicate used by `wait_for`.
pub trait WaitPredicate {
    /// Output type when the predicate is satisfied.
    type Output: Send;

    /// Human-readable description for timeout errors.
    fn describe(&self) -> String;

    /// Execute a single poll.
    fn check(&mut self) -> Pin<Box<dyn Future<Output = WaitFor<Self::Output>> + Send + 'static>>;
}

/// Helper to build a `WaitPredicate` from a description and closure.
pub struct WaitCondition<F> {
    description: String,
    check: F,
}

impl<F> WaitCondition<F> {
    /// Create a new condition with description.
    #[must_use]
    pub fn new(description: impl Into<String>, check: F) -> Self {
        Self {
            description: description.into(),
            check,
        }
    }
}

impl<F, Fut, T> WaitPredicate for WaitCondition<F>
where
    F: FnMut() -> Fut + Send,
    Fut: Future<Output = WaitFor<T>> + Send + 'static,
    T: Send + 'static,
{
    type Output = T;

    fn describe(&self) -> String {
        self.description.clone()
    }

    fn check(&mut self) -> Pin<Box<dyn Future<Output = WaitFor<Self::Output>> + Send + 'static>> {
        Box::pin((self.check)())
    }
}

/// Timeout error returned by wait helpers.
#[derive(Debug, Clone)]
pub struct WaitError {
    /// Condition that was expected to become true.
    pub expected: String,
    /// Most recent observed state.
    pub last_observed: Option<String>,
    /// Number of retries attempted (including first poll).
    pub retries: usize,
    /// Elapsed time while waiting.
    pub elapsed: Duration,
}

impl fmt::Display for WaitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let last = self.last_observed.as_deref().unwrap_or("<none>");
        write!(
            f,
            "timeout waiting for {} after {}ms (retries={}, last_observed={})",
            self.expected,
            self.elapsed.as_millis(),
            self.retries,
            last
        )
    }
}

impl std::error::Error for WaitError {}

/// Wait for a predicate to become true within a timeout using backoff.
pub async fn wait_for<P>(
    mut predicate: P,
    timeout: Duration,
    backoff: Backoff,
) -> Result<P::Output, WaitError>
where
    P: WaitPredicate + Send,
{
    let expected = predicate.describe();
    let start = Instant::now();
    let deadline = start + timeout;
    let mut retries = 0usize;
    let mut delay = backoff.initial;
    let mut last_observed = None;

    loop {
        retries = retries.saturating_add(1);
        match predicate.check().await {
            WaitFor::Ready(value) => return Ok(value),
            WaitFor::NotReady { last_observed: obs } => {
                if obs.is_some() {
                    last_observed = obs;
                }
            }
        }

        let now = Instant::now();
        let timeout_reached = now >= deadline;
        let retries_exhausted = backoff.max_retries.is_some_and(|max| retries >= max);
        if timeout_reached || retries_exhausted {
            return Err(WaitError {
                expected,
                last_observed,
                retries,
                elapsed: now.saturating_duration_since(start),
            });
        }

        let remaining = deadline.saturating_duration_since(now);
        let sleep_for = if delay > remaining { remaining } else { delay };
        if !sleep_for.is_zero() {
            sleep(sleep_for).await;
        }
        delay = backoff.next_delay(delay);
    }
}

/// Wait for a query to return the expected value within a timeout.
pub async fn wait_for_value<F, Fut, T>(
    mut query: F,
    expected: T,
    timeout: Duration,
) -> Result<T, WaitError>
where
    F: FnMut() -> Fut + Send,
    Fut: Future<Output = T> + Send + 'static,
    T: PartialEq + fmt::Debug + Clone + Send + 'static,
{
    let expected_desc = format!("value == {expected:?}");
    let condition = WaitCondition::new(expected_desc, move || {
        let fut = query();
        let expected = expected.clone();
        async move {
            let observed = fut.await;
            if observed == expected {
                WaitFor::Ready(observed)
            } else {
                WaitFor::NotReady {
                    last_observed: Some(format!("{observed:?}")),
                }
            }
        }
    });
    wait_for(condition, timeout, Backoff::default()).await
}

/// Signals used to determine quiescence.
pub trait QuiescenceSignals {
    /// Returns true if the system is currently quiet.
    fn is_quiet(&self, now: Instant) -> bool;
    /// Human-readable description of the current state.
    fn describe(&self, now: Instant) -> String;
}

/// Snapshot of quiescence state for simple implementations.
#[derive(Debug, Clone)]
pub struct QuiescenceState {
    /// Pending work items.
    pub pending: usize,
    /// Last activity timestamp, if any.
    pub last_activity: Option<Instant>,
    /// Required quiet window duration.
    pub quiet_window: Duration,
}

impl QuiescenceState {
    #[must_use]
    fn is_quiet_at(&self, now: Instant) -> bool {
        if self.pending > 0 {
            return false;
        }
        self.last_activity
            .is_none_or(|last| now.saturating_duration_since(last) >= self.quiet_window)
    }

    #[must_use]
    fn describe_at(&self, now: Instant) -> String {
        let since_ms = self
            .last_activity
            .map_or(0, |last| now.saturating_duration_since(last).as_millis());
        format!(
            "pending={}, quiet_window_ms={}, since_last_ms={}",
            self.pending,
            self.quiet_window.as_millis(),
            since_ms
        )
    }
}

impl QuiescenceSignals for QuiescenceState {
    fn is_quiet(&self, now: Instant) -> bool {
        self.is_quiet_at(now)
    }

    fn describe(&self, now: Instant) -> String {
        self.describe_at(now)
    }
}

/// Wait for quiescence using default backoff.
pub async fn wait_for_quiescence<S>(signals: S, timeout: Duration) -> Result<(), WaitError>
where
    S: QuiescenceSignals + Clone + Send + 'static,
{
    wait_for_quiescence_with_backoff(signals, timeout, Backoff::default()).await
}

/// Wait for quiescence using a custom backoff.
pub async fn wait_for_quiescence_with_backoff<S>(
    signals: S,
    timeout: Duration,
    backoff: Backoff,
) -> Result<(), WaitError>
where
    S: QuiescenceSignals + Clone + Send + 'static,
{
    let condition = WaitCondition::new("quiescence", move || {
        let now = Instant::now();
        let signals = signals.clone();
        async move {
            if signals.is_quiet(now) {
                WaitFor::Ready(())
            } else {
                WaitFor::NotReady {
                    last_observed: Some(signals.describe(now)),
                }
            }
        }
    });
    wait_for(condition, timeout, backoff).await
}

/// Wait for a boolean condition to become true.
///
/// Simpler alternative to [`wait_for`] for cases where you just need
/// a bool predicate without structured `WaitFor` returns.
pub async fn wait_for_condition<F, Fut>(
    description: impl Into<String>,
    mut check: F,
    timeout: Duration,
) -> Result<(), WaitError>
where
    F: FnMut() -> Fut + Send,
    Fut: Future<Output = bool> + Send + 'static,
{
    let desc = description.into();
    let condition = WaitCondition::new(desc, move || {
        let fut = check();
        async move {
            if fut.await {
                WaitFor::Ready(())
            } else {
                WaitFor::not_ready(None::<String>)
            }
        }
    });
    wait_for(condition, timeout, Backoff::default()).await
}

/// Wait for a boolean condition with custom backoff.
pub async fn wait_for_condition_with_backoff<F, Fut>(
    description: impl Into<String>,
    mut check: F,
    timeout: Duration,
    backoff: Backoff,
) -> Result<(), WaitError>
where
    F: FnMut() -> Fut + Send,
    Fut: Future<Output = bool> + Send + 'static,
{
    let desc = description.into();
    let condition = WaitCondition::new(desc, move || {
        let fut = check();
        async move {
            if fut.await {
                WaitFor::Ready(())
            } else {
                WaitFor::not_ready(None::<String>)
            }
        }
    });
    wait_for(condition, timeout, backoff).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn backoff_schedule_increases_and_caps() {
        let backoff = Backoff {
            initial: Duration::from_millis(10),
            max: Duration::from_millis(70),
            factor: 2,
            max_retries: None,
        };

        let mut delay = backoff.initial;
        assert_eq!(delay, Duration::from_millis(10));
        delay = backoff.next_delay(delay);
        assert_eq!(delay, Duration::from_millis(20));
        delay = backoff.next_delay(delay);
        assert_eq!(delay, Duration::from_millis(40));
        delay = backoff.next_delay(delay);
        assert_eq!(delay, Duration::from_millis(70));
        delay = backoff.next_delay(delay);
        assert_eq!(delay, Duration::from_millis(70));
    }

    #[test]
    fn backoff_schedule_factor_three() {
        let backoff = Backoff {
            initial: Duration::from_millis(5),
            max: Duration::from_millis(100),
            factor: 3,
            max_retries: None,
        };

        let mut delay = backoff.initial;
        assert_eq!(delay, Duration::from_millis(5));
        delay = backoff.next_delay(delay);
        assert_eq!(delay, Duration::from_millis(15));
        delay = backoff.next_delay(delay);
        assert_eq!(delay, Duration::from_millis(45));
        delay = backoff.next_delay(delay);
        // 45 * 3 = 135, capped at 100
        assert_eq!(delay, Duration::from_millis(100));
    }

    #[test]
    fn backoff_default_is_sane() {
        let b = Backoff::default();
        assert_eq!(b.initial, Duration::from_millis(25));
        assert_eq!(b.max, Duration::from_secs(1));
        assert_eq!(b.factor, 2);
        assert!(b.max_retries.is_none());
    }

    #[test]
    fn wait_error_display_includes_all_fields() {
        let err = WaitError {
            expected: "database ready".to_string(),
            last_observed: Some("connecting".to_string()),
            retries: 5,
            elapsed: Duration::from_millis(3200),
        };
        let msg = err.to_string();
        assert!(msg.contains("database ready"), "should mention expected condition");
        assert!(msg.contains("3200"), "should mention elapsed ms");
        assert!(msg.contains("retries=5"), "should mention retry count");
        assert!(msg.contains("connecting"), "should mention last observed state");
    }

    #[test]
    fn wait_error_display_handles_none_observed() {
        let err = WaitError {
            expected: "ready".to_string(),
            last_observed: None,
            retries: 1,
            elapsed: Duration::from_millis(100),
        };
        let msg = err.to_string();
        assert!(msg.contains("<none>"), "should show <none> for missing observation");
    }

    #[tokio::test]
    async fn wait_for_value_timeout_includes_debug_info() {
        let result = wait_for_value(|| async { 1u32 }, 2u32, Duration::from_millis(0)).await;
        let err = result.expect_err("should timeout");
        assert!(err.expected.contains("value == 2"));
        assert_eq!(err.last_observed.as_deref(), Some("1"));
        assert_eq!(err.retries, 1);
    }

    #[tokio::test]
    async fn wait_for_value_succeeds_immediately() {
        let result = wait_for_value(|| async { 42u32 }, 42u32, Duration::from_secs(1)).await;
        assert_eq!(result.unwrap(), 42);
    }

    #[tokio::test]
    async fn wait_for_predicate_succeeds_after_n_attempts() {
        let counter = Arc::new(AtomicUsize::new(0));
        let counter2 = counter.clone();

        let condition = WaitCondition::new("counter reaches 3", move || {
            let n = counter2.fetch_add(1, Ordering::SeqCst);
            async move {
                if n >= 2 {
                    WaitFor::Ready(n)
                } else {
                    WaitFor::not_ready(Some(format!("count={n}")))
                }
            }
        });

        let backoff = Backoff {
            initial: Duration::from_millis(1),
            max: Duration::from_millis(5),
            factor: 2,
            max_retries: None,
        };

        let result = wait_for(condition, Duration::from_secs(1), backoff).await;
        let value = result.unwrap();
        assert!(value >= 2, "should have succeeded after attempts");
    }

    #[tokio::test]
    async fn wait_for_max_retries_exhausted() {
        let counter = Arc::new(AtomicUsize::new(0));
        let counter2 = counter.clone();

        let condition = WaitCondition::new("never ready", move || {
            let n = counter2.fetch_add(1, Ordering::SeqCst);
            async move {
                WaitFor::<()>::not_ready(Some(format!("attempt={n}")))
            }
        });

        let backoff = Backoff {
            initial: Duration::from_millis(1),
            max: Duration::from_millis(5),
            factor: 2,
            max_retries: Some(3),
        };

        let result = wait_for(condition, Duration::from_secs(10), backoff).await;
        let err = result.expect_err("should exhaust retries");
        assert!(err.retries <= 3, "retries={} should be <= 3", err.retries);
        assert!(err.expected.contains("never ready"));
        assert!(err.last_observed.is_some());
    }

    #[tokio::test]
    async fn wait_for_condition_succeeds() {
        let counter = Arc::new(AtomicUsize::new(0));
        let counter2 = counter.clone();

        let result = wait_for_condition(
            "counter reaches 2",
            move || {
                let n = counter2.fetch_add(1, Ordering::SeqCst);
                async move { n >= 1 }
            },
            Duration::from_secs(1),
        )
        .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn wait_for_condition_times_out() {
        let result = wait_for_condition(
            "impossible",
            || async { false },
            Duration::from_millis(10),
        )
        .await;
        let err = result.expect_err("should timeout");
        assert!(err.expected.contains("impossible"));
        assert!(err.retries >= 1);
    }

    #[tokio::test]
    async fn wait_for_quiescence_succeeds_when_quiet() {
        let signals = QuiescenceState {
            pending: 0,
            last_activity: None,
            quiet_window: Duration::from_millis(0),
        };

        let result = wait_for_quiescence(signals, Duration::from_millis(0)).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn wait_for_quiescence_timeout_with_pending_work() {
        let signals = QuiescenceState {
            pending: 5,
            last_activity: Some(Instant::now()),
            quiet_window: Duration::from_millis(100),
        };

        let result = wait_for_quiescence(signals, Duration::from_millis(10)).await;
        let err = result.expect_err("should timeout with pending work");
        assert!(err.expected.contains("quiescence"));
        assert!(err.last_observed.is_some());
        let obs = err.last_observed.unwrap();
        assert!(obs.contains("pending=5"), "should report pending count: {obs}");
    }

    #[test]
    fn quiescence_state_quiet_with_no_activity() {
        let state = QuiescenceState {
            pending: 0,
            last_activity: None,
            quiet_window: Duration::from_secs(10),
        };
        assert!(state.is_quiet_at(Instant::now()));
    }

    #[test]
    fn quiescence_state_not_quiet_with_pending() {
        let state = QuiescenceState {
            pending: 1,
            last_activity: None,
            quiet_window: Duration::from_millis(0),
        };
        assert!(!state.is_quiet_at(Instant::now()));
    }

    #[test]
    fn quiescence_state_not_quiet_within_window() {
        let state = QuiescenceState {
            pending: 0,
            last_activity: Some(Instant::now()),
            quiet_window: Duration::from_secs(60),
        };
        // Recent activity + 60s window = not quiet yet
        assert!(!state.is_quiet_at(Instant::now()));
    }

    #[test]
    fn quiescence_describe_includes_fields() {
        let state = QuiescenceState {
            pending: 3,
            last_activity: Some(Instant::now()),
            quiet_window: Duration::from_millis(500),
        };
        let desc = state.describe_at(Instant::now());
        assert!(desc.contains("pending=3"));
        assert!(desc.contains("quiet_window_ms=500"));
    }

    #[test]
    fn wait_for_enum_constructors() {
        let ready: WaitFor<i32> = WaitFor::ready(42);
        assert!(matches!(ready, WaitFor::Ready(42)));

        let not_ready: WaitFor<i32> = WaitFor::not_ready(Some("waiting".to_string()));
        assert!(matches!(
            not_ready,
            WaitFor::NotReady {
                last_observed: Some(_)
            }
        ));

        let not_ready_none: WaitFor<i32> = WaitFor::not_ready(None::<String>);
        assert!(matches!(
            not_ready_none,
            WaitFor::NotReady {
                last_observed: None
            }
        ));
    }
}
