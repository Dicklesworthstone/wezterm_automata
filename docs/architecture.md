# Architecture

This document captures the wa core architecture for operators and contributors.

## High-level pipeline

```
WezTerm panes
  -> discovery (wezterm cli list)
  -> capture (wezterm cli get-text)
  -> delta extraction (overlap matching + gap detection)
  -> storage (SQLite + FTS5)
  -> pattern engine (rule packs)
  -> event bus
  -> workflow engine
  -> policy engine (capability + rate limit + approvals)
  -> Robot Mode API + MCP (stdio)
```

## Deterministic state (OSC 133)

- wa relies on OSC 133 prompt markers to infer prompt-active vs command-running.
- These markers are parsed during ingest and recorded into pane state.
- Policy gating and workflows use this state to decide if a send is safe.

## Explicit GAP semantics

- Delta extraction uses overlap matching to avoid full scrollback captures.
- If overlap fails (or alt-screen content blocks stable capture), wa records an
  explicit gap segment and emits a gap event.
- Gap events are treated as uncertainty: policy checks can require approval
  when recent gaps are present.

## Interfaces

- Human CLI is optimized for operator use and safety.
- Robot Mode provides stable, machine-parseable JSON (or TOON) envelopes.
- MCP mirrors Robot Mode for tool and schema parity (feature-gated).

## Library integration map (Appendix F)

| Library | Role in wa | Status |
|---------|------------|--------|
| cass (/dp/coding_agent_session_search) | Correlation + session archaeology; used in status/workflows | integrated |
| caut (/dp/coding_agent_usage_tracker) | Usage truth + selection; used in accounts/workflows | integrated |
| rich_rust | Human-first CLI output (tables/panels/highlight) | planned |
| charmed_rust | Optional TUI (pane picker, event feed, transcript viewer) | feature-gated (tui) |
| fastmcp_rust | MCP tool surface (mirrors robot mode) | feature-gated (mcp) |
| fastapi_rust | Optional HTTP server for dashboards/webhooks | planned |
| asupersync | Remote bootstrap/sync layer (configs, binaries, DB snapshots) | planned |
| playwright | Automate device auth flows with persistent profiles | feature-gated (browser) |
| ast-grep | Structure-aware scans for rule hygiene tooling | tooling |

