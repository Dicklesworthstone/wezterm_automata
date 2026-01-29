//! Crash recovery and health monitoring.
//!
//! This module provides structures for runtime health monitoring and
//! crash recovery.  The [`install_panic_hook`] function registers a custom
//! panic hook that writes a bounded, redacted crash bundle to disk when
//! the process panics.
//!
//! # Crash Bundle Layout
//!
//! ```text
//! .wa/crash/wa_crash_YYYYMMDD_HHMMSS/
//! ├── manifest.json        # Bundle metadata (version, timestamp, schema)
//! ├── crash_report.json    # Panic details (message, location, backtrace)
//! └── health_snapshot.json # Last known HealthSnapshot (if available)
//! ```

use std::backtrace::Backtrace;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::sync::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::policy::Redactor;

/// Global health snapshot for crash reporting
static GLOBAL_HEALTH: OnceLock<RwLock<Option<HealthSnapshot>>> = OnceLock::new();

/// Maximum backtrace string length included in crash bundles (64 KiB).
const MAX_BACKTRACE_LEN: usize = 64 * 1024;

/// Maximum crash bundle size in bytes (1 MiB) — a privacy/size budget.
const MAX_BUNDLE_SIZE: usize = 1024 * 1024;

/// Runtime health snapshot for crash reporting.
///
/// This is periodically updated by the observation runtime and included
/// in crash reports to aid debugging.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthSnapshot {
    /// Timestamp when snapshot was taken (epoch ms)
    pub timestamp: u64,
    /// Number of panes being observed
    pub observed_panes: usize,
    /// Current capture queue depth
    pub capture_queue_depth: usize,
    /// Current write queue depth
    pub write_queue_depth: usize,
    /// Last sequence number per pane
    pub last_seq_by_pane: Vec<(u64, i64)>,
    /// Any warnings detected
    pub warnings: Vec<String>,
    /// Average ingest lag in milliseconds
    pub ingest_lag_avg_ms: f64,
    /// Maximum ingest lag in milliseconds
    pub ingest_lag_max_ms: u64,
    /// Whether the database is writable
    pub db_writable: bool,
    /// Last database write timestamp (epoch ms)
    pub db_last_write_at: Option<u64>,
}

impl HealthSnapshot {
    /// Update the global health snapshot.
    pub fn update_global(snapshot: Self) {
        let lock = GLOBAL_HEALTH.get_or_init(|| RwLock::new(None));
        if let Ok(mut guard) = lock.write() {
            *guard = Some(snapshot);
        }
    }

    /// Get the current global health snapshot.
    pub fn get_global() -> Option<Self> {
        let lock = GLOBAL_HEALTH.get_or_init(|| RwLock::new(None));
        lock.read().ok().and_then(|guard| guard.clone())
    }
}

/// Summary of a graceful shutdown.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShutdownSummary {
    /// Total runtime in seconds
    pub elapsed_secs: u64,
    /// Final capture queue depth
    pub final_capture_queue: usize,
    /// Final write queue depth
    pub final_write_queue: usize,
    /// Total segments persisted
    pub segments_persisted: u64,
    /// Total events recorded
    pub events_recorded: u64,
    /// Last sequence number per pane
    pub last_seq_by_pane: Vec<(u64, i64)>,
    /// Whether shutdown was clean (no errors)
    pub clean: bool,
    /// Any warnings during shutdown
    pub warnings: Vec<String>,
}

/// Configuration for crash handling.
#[derive(Debug, Clone)]
pub struct CrashConfig {
    /// Path to write crash reports
    pub crash_dir: Option<PathBuf>,
    /// Whether to include stack traces
    pub include_backtrace: bool,
}

/// Crash report data written to crash_report.json.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrashReport {
    /// Panic message (redacted)
    pub message: String,
    /// Source location if available (file:line:col)
    pub location: Option<String>,
    /// Backtrace (truncated to MAX_BACKTRACE_LEN)
    pub backtrace: Option<String>,
    /// Epoch seconds when the crash occurred
    pub timestamp: u64,
    /// Process ID
    pub pid: u32,
    /// Thread name if available
    pub thread_name: Option<String>,
}

/// Manifest written to manifest.json in each crash bundle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrashManifest {
    /// wa version at crash time
    pub wa_version: String,
    /// ISO-8601 timestamp
    pub created_at: String,
    /// Files included in the bundle
    pub files: Vec<String>,
    /// Whether health snapshot was available
    pub has_health_snapshot: bool,
    /// Total bundle size in bytes
    pub bundle_size_bytes: u64,
}

// ---------------------------------------------------------------------------
// Panic hook
// ---------------------------------------------------------------------------

/// Install the panic hook for crash reporting.
///
/// Replaces the default panic hook with one that writes a crash bundle
/// containing the panic message, backtrace, and last known health snapshot.
/// The bundle is written atomically (temp dir + rename) and all text
/// content is passed through the [`Redactor`] before being persisted.
///
/// If `crash_dir` is `None` the hook still prints the panic to stderr but
/// does not write any files.
pub fn install_panic_hook(config: CrashConfig) {
    let include_backtrace = config.include_backtrace;
    let crash_dir = config.crash_dir.clone();

    std::panic::set_hook(Box::new(move |info| {
        // Capture backtrace early (before allocations that might fail)
        let bt = if include_backtrace {
            Some(Backtrace::force_capture())
        } else {
            None
        };

        // Extract panic message
        let message = if let Some(s) = info.payload().downcast_ref::<&str>() {
            (*s).to_string()
        } else if let Some(s) = info.payload().downcast_ref::<String>() {
            s.clone()
        } else {
            "unknown panic payload".to_string()
        };

        // Extract location
        let location = info.location().map(|loc| {
            format!("{}:{}:{}", loc.file(), loc.line(), loc.column())
        });

        // Always print to stderr (the original hook behavior)
        if let Some(ref loc) = location {
            eprintln!("wa: panic at {loc}: {message}");
        } else {
            eprintln!("wa: panic: {message}");
        }

        // Write crash bundle if crash_dir is configured
        if let Some(ref dir) = crash_dir {
            let report = CrashReport {
                message,
                location,
                backtrace: bt.map(|b| {
                    let s = b.to_string();
                    if s.len() > MAX_BACKTRACE_LEN {
                        let mut truncated = s[..MAX_BACKTRACE_LEN].to_string();
                        truncated.push_str("\n... [truncated]");
                        truncated
                    } else {
                        s
                    }
                }),
                timestamp: epoch_secs(),
                pid: std::process::id(),
                thread_name: std::thread::current().name().map(String::from),
            };

            let health = HealthSnapshot::get_global();

            match write_crash_bundle(dir, &report, health.as_ref()) {
                Ok(path) => eprintln!("wa: crash bundle written to {}", path.display()),
                Err(e) => eprintln!("wa: failed to write crash bundle: {e}"),
            }
        }
    }));
}

// ---------------------------------------------------------------------------
// Bundle writer
// ---------------------------------------------------------------------------

/// Write a crash bundle to `crash_dir`, returning the bundle directory path.
///
/// The bundle is written atomically: files go into a temporary directory
/// first, then the directory is renamed into place.  All text content is
/// redacted before writing.
pub fn write_crash_bundle(
    crash_dir: &Path,
    report: &CrashReport,
    health: Option<&HealthSnapshot>,
) -> std::io::Result<PathBuf> {
    let redactor = Redactor::new();

    // Build timestamped bundle directory name
    let ts_str = format_timestamp(report.timestamp);
    let bundle_name = format!("wa_crash_{ts_str}");
    let bundle_dir = crash_dir.join(&bundle_name);

    // Use a temp directory alongside the final location for atomic rename
    let tmp_name = format!(".{bundle_name}.tmp");
    let tmp_dir = crash_dir.join(&tmp_name);

    // Clean up any leftover temp directory
    if tmp_dir.exists() {
        fs::remove_dir_all(&tmp_dir)?;
    }

    fs::create_dir_all(&tmp_dir)?;

    let mut files = Vec::new();
    let mut total_size: u64 = 0;

    // 1. Write crash_report.json (redacted)
    {
        let redacted_report = CrashReport {
            message: redactor.redact(&report.message),
            location: report.location.clone(),
            backtrace: report.backtrace.as_ref().map(|bt| redactor.redact(bt)),
            timestamp: report.timestamp,
            pid: report.pid,
            thread_name: report.thread_name.clone(),
        };
        let json = serde_json::to_string_pretty(&redacted_report)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        let bytes = json.as_bytes();
        total_size += bytes.len() as u64;
        if total_size <= MAX_BUNDLE_SIZE as u64 {
            write_file_sync(&tmp_dir.join("crash_report.json"), bytes)?;
            files.push("crash_report.json".to_string());
        }
    }

    // 2. Write health_snapshot.json (if available)
    let has_health = if let Some(snap) = health {
        let json = serde_json::to_string_pretty(snap)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        let bytes = json.as_bytes();
        total_size += bytes.len() as u64;
        if total_size <= MAX_BUNDLE_SIZE as u64 {
            write_file_sync(&tmp_dir.join("health_snapshot.json"), bytes)?;
            files.push("health_snapshot.json".to_string());
            true
        } else {
            false
        }
    } else {
        false
    };

    // 3. Write manifest.json
    {
        let manifest = CrashManifest {
            wa_version: crate::VERSION.to_string(),
            created_at: format_iso8601(report.timestamp),
            files: files.clone(),
            has_health_snapshot: has_health,
            bundle_size_bytes: total_size,
        };
        let json = serde_json::to_string_pretty(&manifest)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        write_file_sync(&tmp_dir.join("manifest.json"), json.as_bytes())?;
        // manifest doesn't count toward the privacy budget
    }

    // Atomic rename: tmp → final
    // If bundle_dir already exists (rapid double-panic), append a counter
    let final_dir = if bundle_dir.exists() {
        let mut counter = 1u32;
        loop {
            let candidate = crash_dir.join(format!("{bundle_name}_{counter}"));
            if !candidate.exists() {
                break candidate;
            }
            counter += 1;
            if counter > 100 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    "too many crash bundles with same timestamp",
                ));
            }
        }
    } else {
        bundle_dir
    };

    fs::rename(&tmp_dir, &final_dir)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&final_dir, fs::Permissions::from_mode(0o700));
    }

    Ok(final_dir)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn write_file_sync(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let mut f = fs::File::create(path)?;
    f.write_all(data)?;
    f.sync_all()?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = f.set_permissions(fs::Permissions::from_mode(0o600));
    }

    Ok(())
}

fn epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Format epoch seconds as `YYYYMMDD_HHMMSS`.
fn format_timestamp(epoch_secs: u64) -> String {
    let secs = epoch_secs;
    let days = secs / 86400;
    let time_secs = secs % 86400;
    let hours = time_secs / 3600;
    let minutes = (time_secs % 3600) / 60;
    let seconds = time_secs % 60;

    let (year, month, day) = days_to_ymd(days);
    format!("{year:04}{month:02}{day:02}_{hours:02}{minutes:02}{seconds:02}")
}

/// Format epoch seconds as ISO-8601.
fn format_iso8601(epoch_secs: u64) -> String {
    let secs = epoch_secs;
    let days = secs / 86400;
    let time_secs = secs % 86400;
    let hours = time_secs / 3600;
    let minutes = (time_secs % 3600) / 60;
    let seconds = time_secs % 60;

    let (year, month, day) = days_to_ymd(days);
    format!("{year:04}-{month:02}-{day:02}T{hours:02}:{minutes:02}:{seconds:02}Z")
}

/// Convert days since epoch to (year, month, day).
fn days_to_ymd(days: u64) -> (u64, u64, u64) {
    // Civil calendar conversion (Euclidean affine)
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    (year, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_snapshot() -> HealthSnapshot {
        HealthSnapshot {
            timestamp: 1_234_567_890,
            observed_panes: 5,
            capture_queue_depth: 10,
            write_queue_depth: 5,
            last_seq_by_pane: vec![(1, 100), (2, 200)],
            warnings: vec!["test warning".to_string()],
            ingest_lag_avg_ms: 15.5,
            ingest_lag_max_ms: 50,
            db_writable: true,
            db_last_write_at: Some(1_234_567_800),
        }
    }

    #[test]
    fn health_snapshot_serialization() {
        let snapshot = test_snapshot();

        let json = serde_json::to_string(&snapshot).unwrap();
        let parsed: HealthSnapshot = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.timestamp, snapshot.timestamp);
        assert_eq!(parsed.observed_panes, snapshot.observed_panes);
        assert!((parsed.ingest_lag_avg_ms - snapshot.ingest_lag_avg_ms).abs() < f64::EPSILON);
    }

    #[test]
    fn shutdown_summary_serialization() {
        let summary = ShutdownSummary {
            elapsed_secs: 3600,
            final_capture_queue: 0,
            final_write_queue: 0,
            segments_persisted: 1000,
            events_recorded: 50,
            last_seq_by_pane: vec![(1, 500)],
            clean: true,
            warnings: vec![],
        };

        let json = serde_json::to_string(&summary).unwrap();
        let parsed: ShutdownSummary = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.elapsed_secs, summary.elapsed_secs);
        assert_eq!(parsed.segments_persisted, summary.segments_persisted);
        assert!(parsed.clean);
    }

    #[test]
    fn global_health_snapshot_update_and_get() {
        let snapshot = HealthSnapshot {
            timestamp: 1000,
            observed_panes: 3,
            capture_queue_depth: 0,
            write_queue_depth: 0,
            last_seq_by_pane: vec![],
            warnings: vec![],
            ingest_lag_avg_ms: 0.0,
            ingest_lag_max_ms: 0,
            db_writable: true,
            db_last_write_at: None,
        };

        HealthSnapshot::update_global(snapshot);

        let retrieved = HealthSnapshot::get_global();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().timestamp, 1000);
    }

    // -- CrashReport tests --

    #[test]
    fn crash_report_serialization() {
        let report = CrashReport {
            message: "assertion failed".to_string(),
            location: Some("src/main.rs:42:5".to_string()),
            backtrace: Some("   0: std::backtrace\n   1: my_func".to_string()),
            timestamp: 1_700_000_000,
            pid: 12345,
            thread_name: Some("main".to_string()),
        };

        let json = serde_json::to_string_pretty(&report).unwrap();
        let parsed: CrashReport = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.message, "assertion failed");
        assert_eq!(parsed.location.as_deref(), Some("src/main.rs:42:5"));
        assert_eq!(parsed.pid, 12345);
        assert_eq!(parsed.thread_name.as_deref(), Some("main"));
    }

    #[test]
    fn crash_report_without_optional_fields() {
        let report = CrashReport {
            message: "panic".to_string(),
            location: None,
            backtrace: None,
            timestamp: 0,
            pid: 1,
            thread_name: None,
        };

        let json = serde_json::to_string(&report).unwrap();
        let parsed: CrashReport = serde_json::from_str(&json).unwrap();
        assert!(parsed.location.is_none());
        assert!(parsed.backtrace.is_none());
        assert!(parsed.thread_name.is_none());
    }

    // -- CrashManifest tests --

    #[test]
    fn crash_manifest_serialization() {
        let manifest = CrashManifest {
            wa_version: "0.1.0".to_string(),
            created_at: "2026-01-28T12:00:00Z".to_string(),
            files: vec!["crash_report.json".to_string()],
            has_health_snapshot: false,
            bundle_size_bytes: 1024,
        };

        let json = serde_json::to_string_pretty(&manifest).unwrap();
        let parsed: CrashManifest = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.wa_version, "0.1.0");
        assert_eq!(parsed.files.len(), 1);
        assert!(!parsed.has_health_snapshot);
    }

    // -- write_crash_bundle tests --

    #[test]
    fn write_crash_bundle_creates_directory_and_files() {
        let tmp = tempfile::tempdir().unwrap();
        let crash_dir = tmp.path().join("crash");

        let report = CrashReport {
            message: "test panic".to_string(),
            location: Some("test.rs:1:1".to_string()),
            backtrace: Some("frame 0\nframe 1".to_string()),
            timestamp: 1_700_000_000,
            pid: 999,
            thread_name: Some("test".to_string()),
        };

        let health = test_snapshot();
        let bundle_path =
            write_crash_bundle(&crash_dir, &report, Some(&health)).unwrap();

        assert!(bundle_path.exists());
        assert!(bundle_path.join("manifest.json").exists());
        assert!(bundle_path.join("crash_report.json").exists());
        assert!(bundle_path.join("health_snapshot.json").exists());
    }

    #[test]
    fn write_crash_bundle_without_health_snapshot() {
        let tmp = tempfile::tempdir().unwrap();
        let crash_dir = tmp.path().join("crash");

        let report = CrashReport {
            message: "no health".to_string(),
            location: None,
            backtrace: None,
            timestamp: 1_700_000_000,
            pid: 1,
            thread_name: None,
        };

        let bundle_path = write_crash_bundle(&crash_dir, &report, None).unwrap();

        assert!(bundle_path.join("manifest.json").exists());
        assert!(bundle_path.join("crash_report.json").exists());
        assert!(!bundle_path.join("health_snapshot.json").exists());

        // Verify manifest records no health snapshot
        let manifest_json = fs::read_to_string(bundle_path.join("manifest.json")).unwrap();
        let manifest: CrashManifest = serde_json::from_str(&manifest_json).unwrap();
        assert!(!manifest.has_health_snapshot);
        assert_eq!(manifest.files.len(), 1);
    }

    #[test]
    fn write_crash_bundle_manifest_contains_version() {
        let tmp = tempfile::tempdir().unwrap();
        let crash_dir = tmp.path().join("crash");

        let report = CrashReport {
            message: "version check".to_string(),
            location: None,
            backtrace: None,
            timestamp: 1_700_000_000,
            pid: 1,
            thread_name: None,
        };

        let bundle_path = write_crash_bundle(&crash_dir, &report, None).unwrap();

        let manifest_json = fs::read_to_string(bundle_path.join("manifest.json")).unwrap();
        let manifest: CrashManifest = serde_json::from_str(&manifest_json).unwrap();

        assert_eq!(manifest.wa_version, crate::VERSION);
        assert!(!manifest.created_at.is_empty());
    }

    #[test]
    fn write_crash_bundle_redacts_secrets() {
        let tmp = tempfile::tempdir().unwrap();
        let crash_dir = tmp.path().join("crash");

        let report = CrashReport {
            message: "failed with key sk-ant-api03-secret123456789012345678901234567890ABCDEF".to_string(),
            location: None,
            backtrace: Some("token=my_secret_token_1234567890 in frame".to_string()),
            timestamp: 1_700_000_000,
            pid: 1,
            thread_name: None,
        };

        let bundle_path = write_crash_bundle(&crash_dir, &report, None).unwrap();

        let report_json = fs::read_to_string(bundle_path.join("crash_report.json")).unwrap();
        let parsed: CrashReport = serde_json::from_str(&report_json).unwrap();

        // Secrets should be redacted
        assert!(
            !parsed.message.contains("sk-ant-api03"),
            "API key should be redacted: {}",
            parsed.message
        );
        assert!(
            parsed.message.contains("[REDACTED]"),
            "Should contain REDACTED marker: {}",
            parsed.message
        );
    }

    #[test]
    fn write_crash_bundle_handles_duplicate_timestamp() {
        let tmp = tempfile::tempdir().unwrap();
        let crash_dir = tmp.path().join("crash");

        let report = CrashReport {
            message: "first".to_string(),
            location: None,
            backtrace: None,
            timestamp: 1_700_000_000,
            pid: 1,
            thread_name: None,
        };

        let path1 = write_crash_bundle(&crash_dir, &report, None).unwrap();

        let report2 = CrashReport {
            message: "second".to_string(),
            ..report.clone()
        };

        let path2 = write_crash_bundle(&crash_dir, &report2, None).unwrap();

        assert_ne!(path1, path2);
        assert!(path1.exists());
        assert!(path2.exists());
    }

    #[test]
    fn write_crash_bundle_directory_name_format() {
        let tmp = tempfile::tempdir().unwrap();
        let crash_dir = tmp.path().join("crash");

        let report = CrashReport {
            message: "test".to_string(),
            location: None,
            backtrace: None,
            // 2023-11-14 22:13:20 UTC
            timestamp: 1_700_000_000,
            pid: 1,
            thread_name: None,
        };

        let bundle_path = write_crash_bundle(&crash_dir, &report, None).unwrap();
        let dir_name = bundle_path.file_name().unwrap().to_str().unwrap();

        assert!(
            dir_name.starts_with("wa_crash_"),
            "should start with wa_crash_: {dir_name}"
        );
        // Should contain a timestamp-like string
        assert!(dir_name.len() > "wa_crash_".len());
    }

    #[test]
    fn crash_report_files_have_restricted_permissions() {
        let tmp = tempfile::tempdir().unwrap();
        let crash_dir = tmp.path().join("crash");

        let report = CrashReport {
            message: "perm check".to_string(),
            location: None,
            backtrace: None,
            timestamp: 1_700_000_000,
            pid: 1,
            thread_name: None,
        };

        let bundle_path = write_crash_bundle(&crash_dir, &report, None).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let crash_file = bundle_path.join("crash_report.json");
            let perms = fs::metadata(&crash_file).unwrap().permissions();
            let mode = perms.mode() & 0o777;
            assert_eq!(mode, 0o600, "crash report should be owner-only: {mode:o}");
        }
    }

    // -- Helper tests --

    #[test]
    fn format_timestamp_produces_valid_string() {
        // 2023-11-14 22:13:20 UTC
        let ts = format_timestamp(1_700_000_000);
        assert_eq!(ts, "20231114_221320");
    }

    #[test]
    fn format_iso8601_produces_valid_string() {
        let s = format_iso8601(0);
        assert_eq!(s, "1970-01-01T00:00:00Z");
    }

    #[test]
    fn format_iso8601_known_date() {
        let s = format_iso8601(1_700_000_000);
        assert_eq!(s, "2023-11-14T22:13:20Z");
    }

    #[test]
    fn days_to_ymd_epoch() {
        let (y, m, d) = days_to_ymd(0);
        assert_eq!((y, m, d), (1970, 1, 1));
    }

    #[test]
    fn days_to_ymd_known_date() {
        // 2024-02-29 (leap day)
        let (y, m, d) = days_to_ymd(19_782);
        assert_eq!(y, 2024);
        assert_eq!(m, 2);
        assert_eq!(d, 29);
    }

    #[test]
    fn max_backtrace_len_is_bounded() {
        assert!(MAX_BACKTRACE_LEN <= MAX_BUNDLE_SIZE);
    }

    #[test]
    fn max_bundle_size_is_reasonable() {
        assert!(MAX_BUNDLE_SIZE >= 1024, "bundle size too small");
        assert!(MAX_BUNDLE_SIZE <= 10 * 1024 * 1024, "bundle size too large");
    }

    #[test]
    fn crash_config_accepts_none_dir() {
        let config = CrashConfig {
            crash_dir: None,
            include_backtrace: true,
        };
        // install_panic_hook should accept this without crash_dir
        // (it just won't write files)
        assert!(config.crash_dir.is_none());
        assert!(config.include_backtrace);
    }

    #[test]
    fn write_crash_bundle_health_snapshot_is_valid_json() {
        let tmp = tempfile::tempdir().unwrap();
        let crash_dir = tmp.path().join("crash");
        let health = test_snapshot();

        let report = CrashReport {
            message: "health json check".to_string(),
            location: None,
            backtrace: None,
            timestamp: 1_700_000_000,
            pid: 1,
            thread_name: None,
        };

        let bundle_path =
            write_crash_bundle(&crash_dir, &report, Some(&health)).unwrap();

        let health_json =
            fs::read_to_string(bundle_path.join("health_snapshot.json")).unwrap();
        let parsed: HealthSnapshot = serde_json::from_str(&health_json).unwrap();

        assert_eq!(parsed.timestamp, health.timestamp);
        assert_eq!(parsed.observed_panes, health.observed_panes);
        assert_eq!(parsed.capture_queue_depth, health.capture_queue_depth);
    }
}
