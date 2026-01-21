//! Benchmarks for FTS (Full-Text Search) query performance.
//!
//! Performance budgets (from PLAN §13.4 + Appendix G.7):
//! - FTS query common patterns (DB ~100k captures):
//!   - **p50 < 10ms**, **p99 < 50ms** (hard cap: < 50ms for common queries)

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use std::time::SystemTime;
use tempfile::TempDir;
use wa_core::storage::{PaneRecord, SearchOptions, StorageHandle};

/// Create a temp database path.
fn temp_db() -> (TempDir, String) {
    let dir = TempDir::new().expect("create temp dir");
    let path = dir.path().join("bench.db").to_string_lossy().to_string();
    (dir, path)
}

/// Get current timestamp in milliseconds.
fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Create a test pane record.
fn test_pane(pane_id: u64) -> PaneRecord {
    let now = now_ms();
    PaneRecord {
        pane_id,
        domain: "local".to_string(),
        window_id: Some(1),
        tab_id: Some(1),
        title: Some("test".to_string()),
        cwd: Some("/tmp".to_string()),
        tty_name: None,
        first_seen_at: now,
        last_seen_at: now,
        observed: true,
        ignore_reason: None,
        last_decision_at: None,
    }
}

/// Generate terminal content for indexing.
fn generate_segment_content(i: usize) -> String {
    // Mix of different content types to simulate real usage
    match i % 10 {
        0 => format!(
            "$ cargo build\n   Compiling crate-{} v0.1.0\n    Finished dev target(s) in 2.34s\n",
            i
        ),
        1 => format!(
            "$ git status\nOn branch feature-{}\nChanges staged for commit:\n  modified: src/lib.rs\n",
            i
        ),
        2 => format!(
            "$ ls -la\ndrwxr-xr-x  5 user  staff   160 Jan {} 10:00 src\n-rw-r--r--  1 user  staff  1234 file{}.txt\n",
            i % 28 + 1,
            i
        ),
        3 => format!(
            "error[E0308]: mismatched types\n --> src/main.rs:{}:5\n  |\n{} |     return value;\n  |            ^^^^^ expected `i32`, found `String`\n",
            i, i
        ),
        4 => format!(
            "test test_{} ... ok\ntest test_{} ... ok\ntest result: ok. 2 passed; 0 failed\n",
            i,
            i + 1
        ),
        5 => format!(
            "Warning: less than 25% of your 20h limit remaining. {}% remaining.\n",
            25 - (i % 20)
        ),
        6 => format!(
            "Auto-compact: Conversation compacted {} tokens to {} tokens.\n",
            100000 + i * 1000,
            50000 + i * 100
        ),
        7 => format!("$ npm install\nadded {} packages in {}s\n", i * 10, i % 60),
        8 => format!(
            "Python 3.11.{}\n>>> print('Hello from segment {}')\nHello from segment {}\n",
            i % 10,
            i,
            i
        ),
        _ => format!(
            "Processing batch {}...\nItems processed: {}\nStatus: complete\nElapsed: {}ms\n",
            i,
            i * 100,
            i * 7 % 1000
        ),
    }
}

/// Runtime to allow async in benchmarks.
fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build runtime")
}

/// Create search options with a limit.
fn opts(limit: usize) -> SearchOptions {
    SearchOptions {
        limit: Some(limit),
        ..Default::default()
    }
}

/// Populate a database with N segments.
async fn populate_db(storage: &StorageHandle, num_segments: usize) {
    storage
        .upsert_pane(test_pane(1))
        .await
        .expect("upsert pane");

    for i in 0..num_segments {
        let content = generate_segment_content(i);
        storage
            .append_segment(1, &content, None)
            .await
            .expect("append segment");
    }
}

fn bench_fts_small_db(c: &mut Criterion) {
    let rt = runtime();

    let mut group = c.benchmark_group("fts_small_db");
    group.sample_size(50);

    // Setup: create DB with 1000 segments
    let (_dir, db_path) = temp_db();
    let storage = rt.block_on(async {
        let s = StorageHandle::new(&db_path).await.expect("create storage");
        populate_db(&s, 1000).await;
        s
    });

    // Budget: p50 < 10ms, p99 < 50ms
    group.bench_function("simple_term", |b| {
        b.to_async(&rt)
            .iter(|| async { storage.search_with_options("cargo", opts(10)).await })
    });

    group.bench_function("phrase_search", |b| {
        b.to_async(&rt).iter(|| async {
            storage
                .search_with_options("\"mismatched types\"", opts(10))
                .await
        })
    });

    group.bench_function("prefix_search", |b| {
        b.to_async(&rt)
            .iter(|| async { storage.search_with_options("compil*", opts(10)).await })
    });

    group.bench_function("boolean_search", |b| {
        b.to_async(&rt).iter(|| async {
            storage
                .search_with_options("error AND types", opts(10))
                .await
        })
    });

    group.bench_function("no_match", |b| {
        b.to_async(&rt).iter(|| async {
            storage
                .search_with_options("nonexistent_term_xyz", opts(10))
                .await
        })
    });

    rt.block_on(storage.shutdown()).expect("shutdown");
    group.finish();
}

fn bench_fts_medium_db(c: &mut Criterion) {
    let rt = runtime();

    let mut group = c.benchmark_group("fts_medium_db");
    group.sample_size(30);

    // Setup: create DB with 10000 segments
    let (_dir, db_path) = temp_db();
    let storage = rt.block_on(async {
        let s = StorageHandle::new(&db_path).await.expect("create storage");
        populate_db(&s, 10_000).await;
        s
    });

    group.bench_function("simple_term", |b| {
        b.to_async(&rt)
            .iter(|| async { storage.search_with_options("cargo", opts(10)).await })
    });

    group.bench_function("phrase_search", |b| {
        b.to_async(&rt).iter(|| async {
            storage
                .search_with_options("\"test result\"", opts(10))
                .await
        })
    });

    group.bench_function("common_term_high_results", |b| {
        b.to_async(&rt)
            .iter(|| async { storage.search_with_options("Processing", opts(100)).await })
    });

    rt.block_on(storage.shutdown()).expect("shutdown");
    group.finish();
}

fn bench_fts_large_db(c: &mut Criterion) {
    let rt = runtime();

    let mut group = c.benchmark_group("fts_large_db");
    group.sample_size(20);

    // Setup: create DB with 100000 segments (target size)
    let (_dir, db_path) = temp_db();
    let storage = rt.block_on(async {
        let s = StorageHandle::new(&db_path).await.expect("create storage");
        populate_db(&s, 100_000).await;
        s
    });

    // These should still meet budget: p50 < 10ms, p99 < 50ms
    group.bench_function("simple_term", |b| {
        b.to_async(&rt)
            .iter(|| async { storage.search_with_options("cargo", opts(10)).await })
    });

    group.bench_function("phrase_search", |b| {
        b.to_async(&rt).iter(|| async {
            storage
                .search_with_options("\"expected i32\"", opts(10))
                .await
        })
    });

    group.bench_function("common_term_limited", |b| {
        b.to_async(&rt)
            .iter(|| async { storage.search_with_options("test", opts(10)).await })
    });

    group.bench_function("rare_term", |b| {
        b.to_async(&rt).iter(|| async {
            storage
                .search_with_options("\"Auto-compact\"", opts(10))
                .await
        })
    });

    rt.block_on(storage.shutdown()).expect("shutdown");
    group.finish();
}

fn bench_fts_result_limits(c: &mut Criterion) {
    let rt = runtime();

    let mut group = c.benchmark_group("fts_result_limits");
    group.sample_size(30);

    let (_dir, db_path) = temp_db();
    let storage = rt.block_on(async {
        let s = StorageHandle::new(&db_path).await.expect("create storage");
        populate_db(&s, 10_000).await;
        s
    });

    // Test how result limit affects performance
    for limit in [1, 10, 50, 100, 500] {
        group.bench_with_input(BenchmarkId::new("limit", limit), &limit, |b, &limit| {
            b.to_async(&rt)
                .iter(|| async { storage.search_with_options("status", opts(limit)).await })
        });
    }

    rt.block_on(storage.shutdown()).expect("shutdown");
    group.finish();
}

criterion_group!(
    benches,
    bench_fts_small_db,
    bench_fts_medium_db,
    bench_fts_large_db,
    bench_fts_result_limits,
);
criterion_main!(benches);
