//! Pane content tailing with adaptive polling.
//!
//! This module provides the TailerSupervisor for managing per-pane content
//! capture with adaptive polling intervals.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use tokio::sync::{mpsc, RwLock};
use tracing::{debug, trace};

use crate::ingest::{CapturedSegment, PaneCursor};
use crate::wezterm::PaneInfo;

/// Configuration for the tailer supervisor.
#[derive(Debug, Clone)]
pub struct TailerConfig {
    /// Minimum polling interval (fast polling for active panes)
    pub min_interval: Duration,
    /// Maximum polling interval (slow polling for idle panes)
    pub max_interval: Duration,
    /// Multiplier for backoff when pane is idle
    pub backoff_multiplier: f64,
    /// Maximum number of concurrent captures
    pub max_concurrent: usize,
    /// Overlap size for delta extraction
    pub overlap_size: usize,
    /// Timeout for sending to channel
    pub send_timeout: Duration,
}

impl Default for TailerConfig {
    fn default() -> Self {
        Self {
            min_interval: Duration::from_millis(50),
            max_interval: Duration::from_secs(1),
            backoff_multiplier: 1.5,
            max_concurrent: 10,
            overlap_size: 256,
            send_timeout: Duration::from_millis(100),
        }
    }
}

/// Metrics for tailer supervisor.
#[derive(Debug, Default)]
pub struct TailerMetrics {
    /// Total capture events sent
    pub events_sent: u64,
    /// Number of send timeouts
    pub send_timeouts: u64,
    /// Number of captures that found no changes
    pub no_change_captures: u64,
}

/// Metrics for supervisor operations.
#[derive(Debug, Default)]
pub struct SupervisorMetrics {
    /// Number of tailers started
    pub tailers_started: u64,
    /// Number of tailers stopped
    pub tailers_stopped: u64,
    /// Total sync operations
    pub sync_count: u64,
}

/// A captured segment event for persistence.
#[derive(Debug, Clone)]
pub struct CaptureEvent {
    /// The captured segment (includes pane_id, seq, content, kind, captured_at)
    pub segment: CapturedSegment,
}

/// Per-pane tailer state.
struct PaneTailer {
    /// Pane ID (retained for debugging/logging)
    #[allow(dead_code)]
    pane_id: u64,
    /// Current polling interval
    current_interval: Duration,
    /// Last poll time
    last_poll: Instant,
    /// Whether changes were detected in last poll
    had_changes: bool,
}

impl PaneTailer {
    fn new(pane_id: u64, initial_interval: Duration) -> Self {
        Self {
            pane_id,
            current_interval: initial_interval,
            last_poll: Instant::now(),
            had_changes: false,
        }
    }

    fn should_poll(&self) -> bool {
        self.last_poll.elapsed() >= self.current_interval
    }

    fn record_poll(&mut self, had_changes: bool, config: &TailerConfig) {
        self.last_poll = Instant::now();
        self.had_changes = had_changes;

        // Adaptive interval: speed up if changes, slow down if idle
        if had_changes {
            self.current_interval = config.min_interval;
        } else {
            let new_interval = Duration::from_secs_f64(
                self.current_interval.as_secs_f64() * config.backoff_multiplier,
            );
            self.current_interval = new_interval.min(config.max_interval);
        }
    }
}

/// Supervisor for managing multiple pane tailers.
pub struct TailerSupervisor {
    /// Configuration
    config: TailerConfig,
    /// Channel for sending capture events (will be used when actual polling is implemented)
    #[allow(dead_code)]
    tx: mpsc::Sender<CaptureEvent>,
    /// Per-pane cursors (shared with runtime)
    cursors: Arc<RwLock<HashMap<u64, PaneCursor>>>,
    /// Shutdown flag
    shutdown_flag: Arc<AtomicBool>,
    /// Per-pane tailer state
    tailers: HashMap<u64, PaneTailer>,
    /// Metrics
    metrics: TailerMetrics,
    /// Supervisor metrics
    supervisor_metrics: SupervisorMetrics,
}

impl TailerSupervisor {
    /// Create a new tailer supervisor.
    pub fn new(
        config: TailerConfig,
        tx: mpsc::Sender<CaptureEvent>,
        cursors: Arc<RwLock<HashMap<u64, PaneCursor>>>,
        shutdown_flag: Arc<AtomicBool>,
    ) -> Self {
        Self {
            config,
            tx,
            cursors,
            shutdown_flag,
            tailers: HashMap::new(),
            metrics: TailerMetrics::default(),
            supervisor_metrics: SupervisorMetrics::default(),
        }
    }

    /// Number of active tailers.
    pub fn active_count(&self) -> usize {
        self.tailers.len()
    }

    /// Sync tailers with the current set of observed panes.
    ///
    /// Adds tailers for new panes, removes tailers for departed panes.
    pub fn sync_tailers(&mut self, observed_panes: &HashMap<u64, PaneInfo>) {
        self.supervisor_metrics.sync_count += 1;

        // Remove tailers for panes no longer observed
        let to_remove: Vec<u64> = self
            .tailers
            .keys()
            .filter(|id| !observed_panes.contains_key(*id))
            .copied()
            .collect();

        for pane_id in to_remove {
            self.tailers.remove(&pane_id);
            self.supervisor_metrics.tailers_stopped += 1;
            debug!(pane_id, "Removed tailer for departed pane");
        }

        // Add tailers for new panes
        for &pane_id in observed_panes.keys() {
            if !self.tailers.contains_key(&pane_id) {
                self.tailers.insert(
                    pane_id,
                    PaneTailer::new(pane_id, self.config.min_interval),
                );
                self.supervisor_metrics.tailers_started += 1;
                debug!(pane_id, "Added tailer for new pane");
            }
        }
    }

    /// Perform one poll cycle, capturing from panes that are ready.
    pub async fn poll_once(&mut self) {
        if self.shutdown_flag.load(Ordering::SeqCst) {
            return;
        }

        // Find panes ready for polling
        let ready_panes: Vec<u64> = self
            .tailers
            .iter()
            .filter(|(_, t)| t.should_poll())
            .map(|(id, _)| *id)
            .take(self.config.max_concurrent)
            .collect();

        if ready_panes.is_empty() {
            return;
        }

        // Capture from each ready pane
        let mut cursors = self.cursors.write().await;
        
        for pane_id in ready_panes {
            let Some(_cursor) = cursors.get_mut(&pane_id) else {
                continue;
            };

            // In a real implementation, we would fetch current pane content here
            // and call _cursor.capture_snapshot() with the content.
            // For now, this is a placeholder - actual implementation would call wezterm CLI

            if let Some(tailer) = self.tailers.get_mut(&pane_id) {
                // Placeholder: mark as no change since we're not actually polling
                tailer.record_poll(false, &self.config);
                self.metrics.no_change_captures += 1;
                trace!(pane_id, "Tailer poll (placeholder - no actual capture)");
            }
        }
    }

    /// Graceful shutdown of all tailers.
    pub async fn shutdown(&mut self) {
        debug!(
            active_count = self.tailers.len(),
            "Shutting down tailer supervisor"
        );
        self.tailers.clear();
    }

    /// Get current metrics.
    pub fn metrics(&self) -> &TailerMetrics {
        &self.metrics
    }

    /// Get supervisor metrics.
    pub fn supervisor_metrics(&self) -> &SupervisorMetrics {
        &self.supervisor_metrics
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tailer_config_default() {
        let config = TailerConfig::default();
        assert_eq!(config.min_interval, Duration::from_millis(50));
        assert_eq!(config.max_interval, Duration::from_secs(1));
        assert!(config.backoff_multiplier > 1.0);
    }

    #[test]
    fn pane_tailer_adaptive_interval() {
        let config = TailerConfig {
            min_interval: Duration::from_millis(100),
            max_interval: Duration::from_secs(1),
            backoff_multiplier: 2.0,
            ..Default::default()
        };

        let mut tailer = PaneTailer::new(1, config.min_interval);
        
        // No changes - interval should increase
        tailer.record_poll(false, &config);
        assert_eq!(tailer.current_interval, Duration::from_millis(200));

        // Still no changes - continue increasing
        tailer.record_poll(false, &config);
        assert_eq!(tailer.current_interval, Duration::from_millis(400));

        // Changes detected - snap back to min
        tailer.record_poll(true, &config);
        assert_eq!(tailer.current_interval, config.min_interval);
    }

    #[test]
    fn pane_tailer_interval_capped_at_max() {
        let config = TailerConfig {
            min_interval: Duration::from_millis(100),
            max_interval: Duration::from_millis(500),
            backoff_multiplier: 10.0,
            ..Default::default()
        };

        let mut tailer = PaneTailer::new(1, config.min_interval);
        
        // Should cap at max_interval
        tailer.record_poll(false, &config);
        assert_eq!(tailer.current_interval, config.max_interval);
    }

    #[tokio::test]
    async fn supervisor_sync_tailers() {
        let config = TailerConfig::default();
        let (tx, _rx) = mpsc::channel(10);
        let cursors = Arc::new(RwLock::new(HashMap::new()));
        let shutdown = Arc::new(AtomicBool::new(false));

        let mut supervisor = TailerSupervisor::new(config, tx, cursors, shutdown);

        assert_eq!(supervisor.active_count(), 0);

        // Add some panes
        let mut panes = HashMap::new();
        panes.insert(1, PaneInfo {
            pane_id: 1,
            tab_id: 0,
            window_id: 0,
            domain_id: None,
            domain_name: None,
            workspace: None,
            size: None,
            rows: Some(24),
            cols: Some(80),
            cwd: None,
            title: None,
            tty_name: None,
            cursor_x: Some(0),
            cursor_y: Some(0),
            cursor_visibility: None,
            left_col: None,
            top_row: None,
            is_active: true,
            is_zoomed: false,
            extra: std::collections::HashMap::new(),
        });
        panes.insert(2, PaneInfo {
            pane_id: 2,
            tab_id: 0,
            window_id: 0,
            domain_id: None,
            domain_name: None,
            workspace: None,
            size: None,
            rows: Some(24),
            cols: Some(80),
            cwd: None,
            title: None,
            tty_name: None,
            cursor_x: Some(0),
            cursor_y: Some(0),
            cursor_visibility: None,
            left_col: None,
            top_row: None,
            is_active: false,
            is_zoomed: false,
            extra: std::collections::HashMap::new(),
        });

        supervisor.sync_tailers(&panes);
        assert_eq!(supervisor.active_count(), 2);

        // Remove a pane
        panes.remove(&1);
        supervisor.sync_tailers(&panes);
        assert_eq!(supervisor.active_count(), 1);
    }

    #[test]
    fn capture_event_wraps_captured_segment() {
        use std::time::{SystemTime, UNIX_EPOCH};

        #[allow(clippy::cast_possible_truncation)] // Epoch millis won't overflow i64 until year 292 million
        let captured_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0);

        let seg = CapturedSegment {
            pane_id: 42,
            seq: 10,
            content: "test content".to_string(),
            kind: crate::ingest::CapturedSegmentKind::Delta,
            captured_at,
        };

        let event = CaptureEvent { segment: seg };

        assert_eq!(event.segment.pane_id, 42);
        assert_eq!(event.segment.seq, 10);
        assert_eq!(event.segment.content, "test content");
        assert!(event.segment.captured_at > 0);
    }
}
