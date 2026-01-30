# Agent TODO (VioletStream)

## 0) Session Bootstrap & Safety
- [x] Read `AGENTS.md` fully
- [x] Read `README.md` fully
- [x] Start Agent Mail session (register identity)
- [x] Verify Agent Mail inbox is empty / respond + ack if needed
- [x] Record active agents list + note missing names (QuietDeer/SilverPine)
- [x] Introduce self to other agents (targeted list)
- [ ] Create/update this TODO file after each major step

## 1) Codebase Archaeology (Architecture Understanding)
- [x] Orientation: list repo structure + manifests (Cargo.toml, crate manifests)
- [x] Identify entry points (`crates/wa/src/main.rs`)
- [x] Summarize CLI command tree + key handlers
- [x] Trace data flow: wezterm CLI → ingest/tailer → storage → patterns → event bus → workflows
- [x] Identify 3–5 key types (StorageHandle, ObservationRuntime, PatternEngine, PolicyEngine, WorkflowRunner, etc.)
- [x] Note integration points (wezterm CLI, sqlite, IPC, config)
- [x] Review configuration system (config.rs + CLI overrides)
- [x] Review tests layout (crates/wa-core/tests, benches, fuzz)
- [x] Write concise architecture summary for user

## 2) Agent Mail Coordination
- [x] Register as `VioletStream`
- [x] Fetch inbox
- [x] Send intro to key agents (CopperDesert, CoralCanyon, GreenHarbor, QuietCave, QuietGlen)
- [x] Note that QuietDeer/SilverPine not registered; ask user or wait
- [ ] Post progress updates on wa-y6g thread (after changes)
- [ ] Acknowledge any new messages promptly

## 3) Beads / BV Triage
- [x] Run `bv --robot-next`
- [ ] Run `bv --robot-triage` if more context needed
- [x] Run `br ready --json` and locate wa-y6g/wa-iqf
- [x] Confirm wa-y6g ownership / in-progress status
- [ ] If switching tasks, update bead status + notify agents

## 4) Dependency Updates (library-updater)
### 4.0 Discovery & Setup
- [x] Confirm manifests: root + crates/wa + crates/wa-core + fuzz
- [x] Verify `cargo outdated` availability
- [x] Verify `cargo audit` availability
- [x] Ensure `UPGRADE_LOG.md` exists
- [x] Ensure `UPGRADE_TODO.md` exists
- [x] Update `claude-upgrade-progress.json` with actual completed/pending
- [ ] Capture current dependency list + versions (workspace + crate-specific)

### 4.1 Per-dependency Loop (one at a time)
**Already updated (tests blocked by cargo locks; rerun later):**
- [x] clap 4.5 → 4.5.54
- [x] serde 1.0 → 1.0.228
- [x] serde_json 1.0 → 1.0.149
- [x] tokio 1.43 → 1.49.0
- [x] anyhow 1.0 → 1.0.100
- [x] tracing 0.1 → 0.1.44
- [x] tracing-subscriber 0.3 → 0.3.22
- [x] toml 0.8 → 0.8.23
- [x] toml_edit 0.22 → 0.24.0
- [x] toon_rust git → latest master
- [x] dirs 5.0 → 6.0.0
- [x] assert_cmd 2.0 → 2.1.2
- [x] predicates 3.1 → 3.1.3
- [x] fancy-regex already latest (skip)

**Pending research + update + test:**
- [x] thiserror
- [x] aho-corasick
- [x] memchr
- [x] regex
- [x] rand
- [x] sha2
- [x] rusqlite
- [x] fs2
- [x] base64
- [x] ratatui
- [x] crossterm
- [x] proptest
- [x] tempfile
- [x] criterion
- [x] libfuzzer-sys

For each dependency (completed; tests need rerun once locks clear):
- [x] Research breaking changes (software-research + web sources)
- [x] Update manifest/lock
- [ ] Run `cargo test` (blocked by lock; rerun pending)
- [x] Log results in `UPGRADE_LOG.md`
- [x] Update `claude-upgrade-progress.json`

### 4.2 Finalization
- [ ] Clear cargo lock contention (coordinate if needed)
- [ ] Run full test suite `cargo test`
- [x] Run `cargo fmt --check`
- [ ] Run `cargo check --all-targets`
- [ ] Run `cargo clippy --all-targets -- -D warnings`
- [x] Run `cargo audit`
- [x] Update `UPGRADE_LOG.md` summary counts + commands section

## 5) wa-y6g (Schema Migration Framework)
- [x] Extend migration model (up/down, plan, status) in `crates/wa-core/src/storage.rs`
- [x] Wire CLI: `wa db migrate` with `--status`, `--run`, `--to <version>`
- [x] Add output formatting for migration status/plan
- [x] Add tests: upgrade path + rollback path
- [ ] Run required checks after code changes (fmt/check/clippy/test)
- [ ] Update bead status + notify Agent Mail thread

## 6) Communication & Reporting
- [x] Summarize architecture for user
- [x] Report dependency update progress + remaining items
- [x] Report bead status + next actions
- [x] Keep TODO updated as tasks complete

---

# Agent TODO (BoldRiver)

## 0) Session Bootstrap & Safety
- [x] Read `AGENTS.md` fully
- [x] Read `README.md` fully
- [x] Start Agent Mail session (`macro_start_session`)
- [x] Check inbox (`resource://inbox/BoldRiver`)
- [x] List active agents (`resource://agents/data-projects-wezterm-automata`)
- [x] Send intro to active agents (WildBrook, MagentaCove, RedFalcon, TurquoiseCave, RubyFox)

## 1) Beads / BV Triage
- [x] Run `bv --robot-triage`
- [x] Run `br ready --json` to find actionable tasks
- [x] Select bead `wa-4vx.10.13` (E2E unhandled→handled lifecycle)
- [x] Mark `wa-4vx.10.13` as `in_progress`
- [x] Announce start in Agent Mail thread `wa-4vx.10.13`

## 2) File Reservations (Agent Mail)
- [x] Reserve `scripts/e2e_test.sh`
- [x] Reserve `fixtures/e2e/dummy_agent.sh`
- [x] Reserve `docs/e2e-integration-checklist.md`

## 3) Implement wa-4vx.10.13 (E2E unhandled→handled lifecycle)
### 3.1 Scenario Definition (scripts/e2e_test.sh)
- [x] Add new scenario function `run_scenario_unhandled_event_lifecycle`
- [x] Add scenario to `SCENARIO_REGISTRY` with description
- [x] Add scenario dispatch case in `run_scenario`
- [x] Ensure scenario uses baseline config (`fixtures/e2e/config_baseline.toml`)
- [x] Emit two compaction markers (dedupe/cooldown assertion)
- [x] Use `wa events -f json --unhandled` to assert exactly 1 relevant event
- [x] Use `wa robot events --unhandled --would-handle --dry-run` to fetch recommended workflow
- [x] Confirm auto-handle workflow clears unhandled event
- [x] Capture artifacts: events pre/post JSON, audit slice, workflow logs, pane text

### 3.2 Dummy Agent Fixture (fixtures/e2e/dummy_agent.sh)
- [x] Add optional args for repeat compaction markers (count + interval)
- [x] Preserve default behavior for existing scenarios

### 3.3 Checklist Update (docs/e2e-integration-checklist.md)
- [x] Add new scenario reference for unhandled→handled lifecycle
- [x] Update dedupe/cooldown row to reference new scenario (remove “partial” note if appropriate)

## 4) Local Verification (required after substantive changes)
- [ ] Run `cargo fmt --check` (failed; formatting diffs in wa-core files not touched)
- [x] Run `cargo check --all-targets`
- [ ] Run `cargo clippy --all-targets -- -D warnings` (failed: clippy::needless_raw_string_hashes in wa-core/desktop_notify.rs)
- [ ] Run targeted E2E (optional if too heavy): `./scripts/e2e_test.sh --case unhandled_event_lifecycle`

## 5) Wrap-up & Coordination
- [ ] Post progress update to Agent Mail thread `wa-4vx.10.13` with files touched
- [ ] Release file reservations
- [ ] Mark bead `wa-4vx.10.13` closed with reason + tests run
