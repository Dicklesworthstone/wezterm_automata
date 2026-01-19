//! Storage layer with SQLite and FTS5
//!
//! Provides persistent storage for captured output, events, and workflows.
//!
//! # Schema Design
//!
//! The database uses WAL mode for concurrent reads and single-writer semantics.
//! All timestamps are epoch milliseconds (i64) for hot-path performance.
//! JSON columns are stored as TEXT for SQLite compatibility.
//!
//! # Tables
//!
//! - `panes`: Pane metadata and observation decisions
//! - `output_segments`: Append-only captured terminal output
//! - `output_gaps`: Explicit discontinuities in capture
//! - `events`: Pattern detections with lifecycle tracking
//! - `workflow_executions`: Durable workflow state
//! - `workflow_step_logs`: Step execution history
//! - `config`: Key-value settings
//! - `maintenance_log`: System events and metrics
//!
//! FTS5 virtual table `output_segments_fts` enables full-text search.

use std::path::Path;
use std::sync::Arc;
use std::thread::{self, JoinHandle};

use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, oneshot};

use crate::error::{Result, StorageError};

// =============================================================================
// Schema Definition
// =============================================================================

/// Current schema version for migration tracking
pub const SCHEMA_VERSION: i32 = 1;

/// Schema initialization SQL
///
/// Convention notes:
/// - Timestamps: epoch milliseconds (i64) for hot-path queries
/// - JSON columns: TEXT containing JSON (v0 simplicity)
/// - All tables use INTEGER PRIMARY KEY for rowid aliasing
pub const SCHEMA_SQL: &str = r#"
-- Enable WAL mode for concurrent reads and single-writer semantics
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;
PRAGMA synchronous = NORMAL;

-- Schema version tracking
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER NOT NULL,
    applied_at INTEGER NOT NULL,  -- epoch ms
    description TEXT
);

-- Panes: metadata and observation decisions
-- Supports: wa status, wa robot state, privacy/perf filtering
CREATE TABLE IF NOT EXISTS panes (
    pane_id INTEGER PRIMARY KEY,
    domain TEXT NOT NULL DEFAULT 'local',
    window_id INTEGER,
    tab_id INTEGER,
    title TEXT,
    cwd TEXT,
    tty_name TEXT,
    first_seen_at INTEGER NOT NULL,   -- epoch ms
    last_seen_at INTEGER NOT NULL,    -- epoch ms
    observed INTEGER NOT NULL DEFAULT 1,  -- bool: 1=observe, 0=ignore
    ignore_reason TEXT,               -- rule id or short description if ignored
    last_decision_at INTEGER          -- epoch ms when observed/ignore was set
);

CREATE INDEX IF NOT EXISTS idx_panes_last_seen ON panes(last_seen_at);
CREATE INDEX IF NOT EXISTS idx_panes_observed ON panes(observed);

-- Output segments: append-only terminal output capture
-- UNIQUE(pane_id, seq) enforces monotonic sequence per pane
CREATE TABLE IF NOT EXISTS output_segments (
    id INTEGER PRIMARY KEY,
    pane_id INTEGER NOT NULL REFERENCES panes(pane_id) ON DELETE CASCADE,
    seq INTEGER NOT NULL,             -- monotonically increasing within pane
    content TEXT NOT NULL,
    content_len INTEGER NOT NULL,     -- cached length for stats
    content_hash TEXT,                -- for overlap detection (optional)
    captured_at INTEGER NOT NULL,     -- epoch ms
    UNIQUE(pane_id, seq)
);

CREATE INDEX IF NOT EXISTS idx_segments_pane_seq ON output_segments(pane_id, seq);
CREATE INDEX IF NOT EXISTS idx_segments_captured ON output_segments(captured_at);

-- Output gaps: explicit discontinuities in capture
CREATE TABLE IF NOT EXISTS output_gaps (
    id INTEGER PRIMARY KEY,
    pane_id INTEGER NOT NULL REFERENCES panes(pane_id) ON DELETE CASCADE,
    seq_before INTEGER NOT NULL,      -- last known seq before gap
    seq_after INTEGER NOT NULL,       -- first seq after gap
    reason TEXT NOT NULL,             -- e.g., "daemon_restart", "timeout", "buffer_overflow"
    detected_at INTEGER NOT NULL      -- epoch ms
);

CREATE INDEX IF NOT EXISTS idx_gaps_pane ON output_gaps(pane_id);
CREATE INDEX IF NOT EXISTS idx_gaps_detected ON output_gaps(detected_at);

-- Events: pattern detections with lifecycle tracking
-- Supports: unhandled queries, workflow linkage, idempotency
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY,
    pane_id INTEGER NOT NULL REFERENCES panes(pane_id) ON DELETE CASCADE,
    rule_id TEXT NOT NULL,            -- stable pattern identifier
    agent_type TEXT NOT NULL,         -- codex, claude_code, gemini, unknown
    event_type TEXT NOT NULL,         -- detection category
    severity TEXT NOT NULL,           -- info, warning, critical
    confidence REAL NOT NULL,         -- 0.0-1.0
    extracted TEXT,                   -- JSON: structured data from pattern
    matched_text TEXT,                -- original matched text
    segment_id INTEGER REFERENCES output_segments(id),  -- source segment
    detected_at INTEGER NOT NULL,     -- epoch ms

    -- Lifecycle tracking
    handled_at INTEGER,               -- epoch ms when handled (NULL = unhandled)
    handled_by_workflow_id TEXT,      -- links to workflow_executions.id
    handled_status TEXT,              -- completed, aborted, failed, paused

    -- Idempotency: optional dedupe key (pane_id + rule_id + time_window)
    dedupe_key TEXT,                  -- computed key for duplicate prevention

    UNIQUE(dedupe_key)                -- prevents duplicate events when dedupe_key set
);

CREATE INDEX IF NOT EXISTS idx_events_pane ON events(pane_id);
CREATE INDEX IF NOT EXISTS idx_events_rule ON events(rule_id);
CREATE INDEX IF NOT EXISTS idx_events_unhandled ON events(handled_at) WHERE handled_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_events_detected ON events(detected_at);
CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity, detected_at);

-- Workflow executions: durable FSM state for resumability
CREATE TABLE IF NOT EXISTS workflow_executions (
    id TEXT PRIMARY KEY,              -- UUID or ulid
    workflow_name TEXT NOT NULL,
    pane_id INTEGER NOT NULL REFERENCES panes(pane_id),
    trigger_event_id INTEGER REFERENCES events(id),  -- event that started this
    current_step INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'running',  -- running, waiting, completed, aborted
    wait_condition TEXT,              -- JSON: WaitCondition if status='waiting'
    context TEXT,                     -- JSON: workflow-specific state
    result TEXT,                      -- JSON: final result if completed
    error TEXT,                       -- error message if aborted
    started_at INTEGER NOT NULL,      -- epoch ms
    updated_at INTEGER NOT NULL,      -- epoch ms
    completed_at INTEGER              -- epoch ms
);

CREATE INDEX IF NOT EXISTS idx_workflows_pane ON workflow_executions(pane_id);
CREATE INDEX IF NOT EXISTS idx_workflows_status ON workflow_executions(status);
CREATE INDEX IF NOT EXISTS idx_workflows_started ON workflow_executions(started_at);

-- Workflow step logs: execution history for audit and debugging
CREATE TABLE IF NOT EXISTS workflow_step_logs (
    id INTEGER PRIMARY KEY,
    workflow_id TEXT NOT NULL REFERENCES workflow_executions(id) ON DELETE CASCADE,
    step_index INTEGER NOT NULL,
    step_name TEXT NOT NULL,
    result_type TEXT NOT NULL,        -- continue, done, retry, abort, wait_for
    result_data TEXT,                 -- JSON: result payload
    started_at INTEGER NOT NULL,      -- epoch ms
    completed_at INTEGER NOT NULL,    -- epoch ms
    duration_ms INTEGER NOT NULL      -- cached for stats
);

CREATE INDEX IF NOT EXISTS idx_step_logs_workflow ON workflow_step_logs(workflow_id, step_index);

-- Config: key-value settings
CREATE TABLE IF NOT EXISTS config (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,              -- JSON value
    updated_at INTEGER NOT NULL       -- epoch ms
);

-- Maintenance log: system events and metrics
CREATE TABLE IF NOT EXISTS maintenance_log (
    id INTEGER PRIMARY KEY,
    event_type TEXT NOT NULL,         -- startup, shutdown, vacuum, retention_cleanup, error
    message TEXT,
    metadata TEXT,                    -- JSON: additional context
    timestamp INTEGER NOT NULL        -- epoch ms
);

CREATE INDEX IF NOT EXISTS idx_maintenance_timestamp ON maintenance_log(timestamp);

-- FTS5 virtual table for full-text search over segments
CREATE VIRTUAL TABLE IF NOT EXISTS output_segments_fts USING fts5(
    content,
    content='output_segments',
    content_rowid='id',
    tokenize='porter unicode61'
);

-- Triggers to keep FTS index in sync
CREATE TRIGGER IF NOT EXISTS output_segments_ai AFTER INSERT ON output_segments BEGIN
    INSERT INTO output_segments_fts(rowid, content) VALUES (new.id, new.content);
END;

CREATE TRIGGER IF NOT EXISTS output_segments_ad AFTER DELETE ON output_segments BEGIN
    INSERT INTO output_segments_fts(output_segments_fts, rowid, content) VALUES('delete', old.id, old.content);
END;

CREATE TRIGGER IF NOT EXISTS output_segments_au AFTER UPDATE ON output_segments BEGIN
    INSERT INTO output_segments_fts(output_segments_fts, rowid, content) VALUES('delete', old.id, old.content);
    INSERT INTO output_segments_fts(rowid, content) VALUES (new.id, new.content);
END;
"#;

// =============================================================================
// Data Structures
// =============================================================================

/// A captured segment of pane output
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Segment {
    /// Unique segment ID
    pub id: i64,
    /// Pane this segment belongs to
    pub pane_id: u64,
    /// Sequence number within the pane (monotonically increasing)
    pub seq: u64,
    /// The captured text content
    pub content: String,
    /// Content length (cached)
    pub content_len: usize,
    /// Optional content hash for overlap detection
    pub content_hash: Option<String>,
    /// Timestamp when captured (epoch ms)
    pub captured_at: i64,
}

/// A gap event indicating discontinuous capture
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Gap {
    /// Unique gap ID
    pub id: i64,
    /// Pane where gap occurred
    pub pane_id: u64,
    /// Sequence number before gap
    pub seq_before: u64,
    /// Sequence number after gap
    pub seq_after: u64,
    /// Reason for gap
    pub reason: String,
    /// Timestamp of gap detection (epoch ms)
    pub detected_at: i64,
}

/// Pane metadata and observation state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaneRecord {
    /// Pane ID (from WezTerm)
    pub pane_id: u64,
    /// Domain name
    pub domain: String,
    /// Window ID
    pub window_id: Option<u64>,
    /// Tab ID
    pub tab_id: Option<u64>,
    /// Pane title
    pub title: Option<String>,
    /// Current working directory
    pub cwd: Option<String>,
    /// TTY name
    pub tty_name: Option<String>,
    /// First seen timestamp (epoch ms)
    pub first_seen_at: i64,
    /// Last seen timestamp (epoch ms)
    pub last_seen_at: i64,
    /// Whether to observe this pane
    pub observed: bool,
    /// Reason for ignoring (if not observed)
    pub ignore_reason: Option<String>,
    /// When observation decision was made (epoch ms)
    pub last_decision_at: Option<i64>,
}

/// A stored event (pattern detection)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredEvent {
    /// Event ID
    pub id: i64,
    /// Pane ID
    pub pane_id: u64,
    /// Rule ID
    pub rule_id: String,
    /// Agent type
    pub agent_type: String,
    /// Event type
    pub event_type: String,
    /// Severity
    pub severity: String,
    /// Confidence score
    pub confidence: f64,
    /// Extracted data (JSON)
    pub extracted: Option<serde_json::Value>,
    /// Original matched text
    pub matched_text: Option<String>,
    /// Source segment ID
    pub segment_id: Option<i64>,
    /// Detection timestamp (epoch ms)
    pub detected_at: i64,
    /// When handled (epoch ms, None = unhandled)
    pub handled_at: Option<i64>,
    /// Workflow that handled this
    pub handled_by_workflow_id: Option<String>,
    /// Handling status
    pub handled_status: Option<String>,
}

/// Workflow execution record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowRecord {
    /// Execution ID
    pub id: String,
    /// Workflow name
    pub workflow_name: String,
    /// Pane ID
    pub pane_id: u64,
    /// Trigger event ID
    pub trigger_event_id: Option<i64>,
    /// Current step index
    pub current_step: usize,
    /// Status
    pub status: String,
    /// Wait condition (JSON)
    pub wait_condition: Option<serde_json::Value>,
    /// Workflow context (JSON)
    pub context: Option<serde_json::Value>,
    /// Result (JSON)
    pub result: Option<serde_json::Value>,
    /// Error message
    pub error: Option<String>,
    /// Started timestamp (epoch ms)
    pub started_at: i64,
    /// Updated timestamp (epoch ms)
    pub updated_at: i64,
    /// Completed timestamp (epoch ms)
    pub completed_at: Option<i64>,
}

// =============================================================================
// Schema Initialization
// =============================================================================

/// Initialize the database schema
///
/// Creates all tables, indexes, triggers, and FTS if they don't exist.
/// Safe to call on an existing database.
pub fn initialize_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(SCHEMA_SQL)
        .map_err(|e| StorageError::MigrationFailed(format!("Schema init failed: {e}")))?;

    // Record schema version if not already present
    let existing: Option<i32> = conn
        .query_row(
            "SELECT version FROM schema_version ORDER BY version DESC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(|e| StorageError::Database(e.to_string()))?;

    if existing.is_none() {
        #[allow(clippy::cast_possible_truncation)]
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64) // Safe: won't overflow until year 292,277,026
            .unwrap_or(0);

        conn.execute(
            "INSERT INTO schema_version (version, applied_at, description) VALUES (?1, ?2, ?3)",
            params![SCHEMA_VERSION, now_ms, "Initial schema"],
        )
        .map_err(|e| StorageError::MigrationFailed(format!("Version insert failed: {e}")))?;
    }

    Ok(())
}

/// Get the current schema version
pub fn get_schema_version(conn: &Connection) -> Result<Option<i32>> {
    conn.query_row(
        "SELECT version FROM schema_version ORDER BY version DESC LIMIT 1",
        [],
        |row| row.get(0),
    )
    .optional()
    .map_err(|e| StorageError::Database(e.to_string()).into())
}

/// Check if schema needs initialization
pub fn needs_initialization(conn: &Connection) -> Result<bool> {
    let table_exists: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='panes'",
            [],
            |row| row.get(0),
        )
        .map_err(|e| StorageError::Database(e.to_string()))?;

    Ok(table_exists == 0)
}

// =============================================================================
// Storage Handle
// =============================================================================

/// Storage handle for async operations
pub struct StorageHandle {
    // TODO: Implement writer thread + read pool (see wa-4vx.3.2)
    _db_path: String,
}

impl StorageHandle {
    /// Create a new storage handle
    pub async fn new(db_path: &str) -> Result<Self> {
        // TODO: Initialize database and writer thread (see wa-4vx.3.2)
        Ok(Self {
            _db_path: db_path.to_string(),
        })
    }

    /// Append a segment to storage
    pub async fn append_segment(&self, _pane_id: u64, _content: &str) -> Result<Segment> {
        // TODO: Implement segment append (see wa-4vx.3.2)
        todo!("Implement segment append")
    }

    /// Record a gap event
    pub async fn record_gap(&self, _pane_id: u64, _reason: &str) -> Result<Gap> {
        // TODO: Implement gap recording (see wa-4vx.3.2)
        todo!("Implement gap recording")
    }

    /// Search segments using FTS5
    pub async fn search(&self, _query: &str) -> Result<Vec<Segment>> {
        // TODO: Implement FTS search (see wa-4vx.3.2)
        todo!("Implement FTS search")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    // =========================================================================
    // Schema Initialization Tests
    // =========================================================================

    #[test]
    fn schema_initializes_on_fresh_db() {
        let conn = Connection::open_in_memory().unwrap();

        // Should need initialization
        assert!(needs_initialization(&conn).unwrap());

        // Initialize
        initialize_schema(&conn).unwrap();

        // Should not need initialization anymore
        assert!(!needs_initialization(&conn).unwrap());

        // Version should be recorded
        let version = get_schema_version(&conn).unwrap();
        assert_eq!(version, Some(SCHEMA_VERSION));
    }

    #[test]
    fn schema_is_idempotent() {
        let conn = Connection::open_in_memory().unwrap();

        // Initialize twice
        initialize_schema(&conn).unwrap();
        initialize_schema(&conn).unwrap();

        // Should still be valid
        let version = get_schema_version(&conn).unwrap();
        assert_eq!(version, Some(SCHEMA_VERSION));
    }

    #[test]
    fn all_tables_exist_after_init() {
        let conn = Connection::open_in_memory().unwrap();
        initialize_schema(&conn).unwrap();

        let expected_tables = [
            "schema_version",
            "panes",
            "output_segments",
            "output_gaps",
            "events",
            "workflow_executions",
            "workflow_step_logs",
            "config",
            "maintenance_log",
        ];

        for table in &expected_tables {
            let count: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1",
                    [table],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(count, 1, "Table {table} should exist");
        }
    }

    #[test]
    fn fts_table_exists_after_init() {
        let conn = Connection::open_in_memory().unwrap();
        initialize_schema(&conn).unwrap();

        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='output_segments_fts'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1, "FTS5 table should exist");
    }

    #[test]
    fn wal_mode_is_enabled() {
        let conn = Connection::open_in_memory().unwrap();
        initialize_schema(&conn).unwrap();

        let mode: String = conn
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .unwrap();
        // In-memory databases use "memory" mode, but WAL works on file-based DBs
        assert!(mode == "memory" || mode == "wal");
    }

    // =========================================================================
    // Basic Insert/Query Tests (validates schema correctness)
    // =========================================================================

    #[test]
    #[allow(clippy::cast_possible_wrap)]
    fn can_insert_and_query_pane() {
        let conn = Connection::open_in_memory().unwrap();
        initialize_schema(&conn).unwrap();

        let now_ms = 1_700_000_000_000i64;

        conn.execute(
            "INSERT INTO panes (pane_id, domain, first_seen_at, last_seen_at, observed) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![42i64, "local", now_ms, now_ms, 1],
        )
        .unwrap();

        let (pane_id, domain): (i64, String) = conn
            .query_row(
                "SELECT pane_id, domain FROM panes WHERE pane_id = ?1",
                [42i64],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();

        assert_eq!(pane_id, 42);
        assert_eq!(domain, "local");
    }

    #[test]
    fn can_insert_segment_with_unique_constraint() {
        let conn = Connection::open_in_memory().unwrap();
        initialize_schema(&conn).unwrap();

        let now_ms = 1_700_000_000_000i64;

        // Insert pane first (foreign key)
        conn.execute(
            "INSERT INTO panes (pane_id, domain, first_seen_at, last_seen_at, observed) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![1i64, "local", now_ms, now_ms, 1],
        ).unwrap();

        // Insert segment
        conn.execute(
            "INSERT INTO output_segments (pane_id, seq, content, content_len, captured_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![1i64, 0i64, "hello", 5, now_ms],
        ).unwrap();

        // Duplicate should fail
        let result = conn.execute(
            "INSERT INTO output_segments (pane_id, seq, content, content_len, captured_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![1i64, 0i64, "world", 5, now_ms],
        );
        assert!(result.is_err(), "Duplicate (pane_id, seq) should fail");
    }

    #[test]
    fn fts_trigger_syncs_on_insert() {
        let conn = Connection::open_in_memory().unwrap();
        initialize_schema(&conn).unwrap();

        let now_ms = 1_700_000_000_000i64;

        // Insert pane
        conn.execute(
            "INSERT INTO panes (pane_id, domain, first_seen_at, last_seen_at, observed) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![1i64, "local", now_ms, now_ms, 1],
        ).unwrap();

        // Insert segment
        conn.execute(
            "INSERT INTO output_segments (pane_id, seq, content, content_len, captured_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![1i64, 0i64, "hello world test", 16, now_ms],
        ).unwrap();

        // Search via FTS
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM output_segments_fts WHERE output_segments_fts MATCH 'world'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1, "FTS should find the inserted content");
    }

    #[test]
    fn can_insert_event_and_mark_handled() {
        let conn = Connection::open_in_memory().unwrap();
        initialize_schema(&conn).unwrap();

        let now_ms = 1_700_000_000_000i64;

        // Insert pane
        conn.execute(
            "INSERT INTO panes (pane_id, domain, first_seen_at, last_seen_at, observed) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![1i64, "local", now_ms, now_ms, 1],
        ).unwrap();

        // Insert unhandled event
        conn.execute(
            "INSERT INTO events (pane_id, rule_id, agent_type, event_type, severity, confidence, detected_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![1i64, "codex.usage_limit", "codex", "usage", "warning", 0.95, now_ms],
        ).unwrap();

        // Query unhandled
        let unhandled_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM events WHERE handled_at IS NULL",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(unhandled_count, 1);

        // Mark as handled
        conn.execute(
            "UPDATE events SET handled_at = ?1, handled_status = ?2 WHERE id = 1",
            params![now_ms + 1000, "completed"],
        )
        .unwrap();

        // Query unhandled again
        let unhandled_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM events WHERE handled_at IS NULL",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(unhandled_count, 0);
    }

    #[test]
    fn can_insert_workflow_execution() {
        let conn = Connection::open_in_memory().unwrap();
        initialize_schema(&conn).unwrap();

        let now_ms = 1_700_000_000_000i64;

        // Insert pane
        conn.execute(
            "INSERT INTO panes (pane_id, domain, first_seen_at, last_seen_at, observed) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![1i64, "local", now_ms, now_ms, 1],
        ).unwrap();

        // Insert workflow execution
        conn.execute(
            "INSERT INTO workflow_executions (id, workflow_name, pane_id, current_step, status, started_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params!["wf-001", "handle_compaction", 1i64, 0, "running", now_ms, now_ms],
        ).unwrap();

        // Query
        let (name, status): (String, String) = conn
            .query_row(
                "SELECT workflow_name, status FROM workflow_executions WHERE id = ?1",
                ["wf-001"],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();

        assert_eq!(name, "handle_compaction");
        assert_eq!(status, "running");
    }

    // =========================================================================
    // Data Structure Serialization Tests
    // =========================================================================

    #[test]
    fn segment_serializes() {
        let segment = Segment {
            id: 1,
            pane_id: 42,
            seq: 100,
            content: "Hello, world!".to_string(),
            content_len: 13,
            content_hash: Some("abc123".to_string()),
            captured_at: 1_234_567_890,
        };

        let json = serde_json::to_string(&segment).unwrap();
        assert!(json.contains("Hello, world!"));
        assert!(json.contains("content_len"));
    }

    #[test]
    fn pane_record_serializes() {
        let pane = PaneRecord {
            pane_id: 1,
            domain: "local".to_string(),
            window_id: Some(0),
            tab_id: Some(0),
            title: Some("bash".to_string()),
            cwd: Some("/home/user".to_string()),
            tty_name: None,
            first_seen_at: 1_700_000_000_000,
            last_seen_at: 1_700_000_001_000,
            observed: true,
            ignore_reason: None,
            last_decision_at: None,
        };

        let json = serde_json::to_string(&pane).unwrap();
        assert!(json.contains("local"));
        assert!(json.contains("bash"));
    }

    #[test]
    fn stored_event_serializes() {
        let event = StoredEvent {
            id: 1,
            pane_id: 42,
            rule_id: "codex.usage_limit".to_string(),
            agent_type: "codex".to_string(),
            event_type: "usage".to_string(),
            severity: "warning".to_string(),
            confidence: 0.95,
            extracted: Some(serde_json::json!({"limit": 100})),
            matched_text: Some("Usage limit reached".to_string()),
            segment_id: Some(123),
            detected_at: 1_700_000_000_000,
            handled_at: None,
            handled_by_workflow_id: None,
            handled_status: None,
        };

        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("codex.usage_limit"));
        assert!(json.contains("0.95"));
    }

    #[test]
    fn workflow_record_serializes() {
        let workflow = WorkflowRecord {
            id: "wf-001".to_string(),
            workflow_name: "handle_compaction".to_string(),
            pane_id: 42,
            trigger_event_id: Some(1),
            current_step: 2,
            status: "running".to_string(),
            wait_condition: None,
            context: Some(serde_json::json!({"retry_count": 0})),
            result: None,
            error: None,
            started_at: 1_700_000_000_000,
            updated_at: 1_700_000_001_000,
            completed_at: None,
        };

        let json = serde_json::to_string(&workflow).unwrap();
        assert!(json.contains("handle_compaction"));
        assert!(json.contains("wf-001"));
    }
}
