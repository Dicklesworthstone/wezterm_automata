#!/bin/bash
# Dummy agent script for E2E testing
# Simulates an AI agent that triggers compaction and echoes received input
#
# Usage: ./dummy_agent.sh [DELAY_BEFORE_COMPACTION] [REPEAT_COUNT] [REPEAT_INTERVAL]
#
# Arguments:
#   DELAY_BEFORE_COMPACTION - Seconds to wait before emitting compaction marker (default: 1)
#   REPEAT_COUNT - How many times to emit the compaction marker (default: 1)
#   REPEAT_INTERVAL - Seconds between repeated markers (default: 1)

set -euo pipefail

DELAY="${1:-1}"
REPEAT_COUNT="${2:-1}"
REPEAT_INTERVAL="${3:-1}"

echo "[CODEX] Session started"
echo "[CODEX] Agent ready for work"

sleep "$DELAY"

echo "[CODEX] Compaction required: context window 95% full"
echo "[CODEX] Waiting for refresh prompt..."

if [[ "$REPEAT_COUNT" -gt 1 ]]; then
    for ((i=2; i<=REPEAT_COUNT; i++)); do
        sleep "$REPEAT_INTERVAL"
        echo "[CODEX] Compaction required: context window 95% full"
        echo "[CODEX] Waiting for refresh prompt..."
    done
fi

# Wait for input and echo it back
# This simulates the agent receiving and processing user input
while IFS= read -r -t 30 line; do
    echo "Received: $line"
    if [[ "$line" == *"exit"* ]]; then
        echo "[CODEX] Exit requested, shutting down"
        break
    fi
    if [[ "$line" == *"refresh"* ]] || [[ "$line" == *"/compact"* ]]; then
        echo "[CODEX] Refresh acknowledged"
        echo "[CODEX] Context compacted successfully"
    fi
done

echo "[CODEX] Session ended"
