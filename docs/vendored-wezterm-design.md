# Vendored WezTerm Native Event Integration (Design)

> **Goal:** Define the native interface between a vendored WezTerm and `wa` so
> `wa` can receive high-fidelity pane output/state events **without** Lua.
>
> **Scope:** Interface and IPC protocol only. No implementation in this bead.

## Why

Lua hooks in WezTerm can become a performance bottleneck (e.g., `update-status`)
by executing on every render tick. A native integration avoids that overhead by
emitting events directly from WezTerm internals to `wa` using a lightweight,
non-blocking IPC protocol.

## Design Principles

- **Non-blocking:** WezTerm must never stall on `wa` I/O. Drop events if needed.
- **Best-effort:** If `wa` is not running, WezTerm continues normally.
- **Typed events:** Stable, versioned event shapes with bounded payloads.
- **Separation of concerns:** WezTerm produces events; `wa` decides what to store.
- **Compatibility:** Initial protocol is JSON Lines for ease of debug/inspection.

## Event Sink Trait (WezTerm-side)

`wa` exposes a trait that WezTerm can call into (vendored build only). This
trait is defined in `crates/wa-core/src/wezterm_native.rs` and is intended to be
implemented by a lightweight IPC sender in WezTerm.

```rust
/// Trait for receiving events from WezTerm.
///
/// Implementations must be non-blocking and thread-safe.
pub trait WaEventSink: Send + Sync + 'static {
    /// Called when new output is received for a pane.
    fn on_pane_output(&self, pane_id: u64, data: &[u8]);

    /// Called when pane state changes (title, dimensions, alt-screen, cursor).
    fn on_pane_state_change(&self, pane_id: u64, state: &WaPaneState);

    /// Called when a user-var (OSC 1337) is set.
    fn on_user_var_changed(&self, pane_id: u64, name: &str, value: &str);

    /// Called when a new pane is created.
    fn on_pane_created(&self, pane_id: u64, domain: &str, cwd: Option<&str>);

    /// Called when a pane is destroyed.
    fn on_pane_destroyed(&self, pane_id: u64);
}

/// Pane state snapshot for state change events.
pub struct WaPaneState {
    pub title: String,
    pub rows: u16,
    pub cols: u16,
    pub is_alt_screen: bool,
    pub cursor_row: u32,
    pub cursor_col: u32,
}
```

## IPC Protocol (WezTerm -> wa)

### Transport

- **Unix socket** (primary):
  - `$XDG_RUNTIME_DIR/wa/events.sock` (preferred)
  - `/tmp/wa-$USER/events.sock` (fallback)
- **Connection model:**
  - WezTerm attempts to connect at startup if socket exists.
  - On failure, it retries with exponential backoff (cap at 5s).
  - If `wa` is not running, events are dropped.

### Message Format

**JSON Lines** (newline-delimited JSON), one event per line.

```json
{"type":"pane_output","pane_id":0,"data_b64":"...","ts":1706123456789}
{"type":"state_change","pane_id":0,"state":{"title":"zsh","rows":24,"cols":80,"is_alt_screen":false,"cursor_row":10,"cursor_col":5},"ts":1706123456799}
{"type":"user_var","pane_id":0,"name":"wa-ready","value":"1","ts":1706123456801}
{"type":"pane_created","pane_id":1,"domain":"local","cwd":"/home/user","ts":1706123456810}
{"type":"pane_destroyed","pane_id":1,"ts":1706123456815}
```

### Event Types

- `pane_output`:
  - `data_b64`: base64-encoded bytes (raw terminal output)
  - **Note:** payload should be bounded (e.g., <= 64KB per event)
- `state_change`:
  - `state`: `title`, `rows`, `cols`, `is_alt_screen`, `cursor_row`, `cursor_col`
- `user_var`:
  - `name`, `value` (raw strings)
- `pane_created`:
  - `domain`, `cwd` (optional)
- `pane_destroyed`

### Versioning

- Optional first line on connect:
  ```json
  {"type":"hello","proto":1,"wezterm_version":"2026.01.30"}
  ```
- `wa` should accept missing `hello` (backwards-compatible).

### Reliability and Backpressure

- **WezTerm side:**
  - Use a bounded, lock-free queue for outgoing events.
  - If the queue is full, drop newest `pane_output` events first.
  - Never block on IPC writes from UI/PTY threads.

- **wa side:**
  - Accept best-effort ordering (no strict global ordering guarantees).
  - Timestamp each received event at ingest for consistent storage.

## Configuration

### WezTerm config (vendored only)

```lua
-- Optional: enable wa integration
config.wa_event_socket = "/tmp/wa-user/events.sock"
config.wa_event_filter = {
  pane_output = true,
  state_change = true,
  user_var = true,
  pane_lifecycle = true,
}
```

### Environment override

```bash
export WEZTERM_WA_SOCKET="/tmp/wa/events.sock"
```

## Thread Safety and Performance

WezTerm is multi-threaded (PTY reader, UI, mux). The event sink must be:

- `Send + Sync + 'static`
- Internally buffered (channel or ring buffer)
- Non-blocking on all call sites

## Security / Privacy

- `wa` must still redact secrets when persisting events.
- IPC transport should be local-only; socket permissions `0700`.
- No remote network transport in v0.1.

## Open Questions

1. Should `pane_output` include pane generation UUID to disambiguate reused IDs?
2. Do we need a `pane_title_changed` event separate from `state_change`?
3. Should `wa` provide a best-effort ACK channel for adaptive throttling?

## Acceptance Criteria (for this design)

- Trait definition is clear and thread-safe.
- IPC protocol is specified and versionable.
- Socket location and reconnect behavior are defined.
- WezTerm configuration knobs are documented.

