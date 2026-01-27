#!/usr/bin/env bash
set -euo pipefail

CHECKLIST_FILE="${1:-docs/e2e-integration-checklist.md}"
REGISTRY_FILE="${2:-scripts/e2e_test.sh}"

if [[ ! -f "$CHECKLIST_FILE" ]]; then
  echo "checklist missing: $CHECKLIST_FILE" >&2
  exit 1
fi
if [[ ! -f "$REGISTRY_FILE" ]]; then
  echo "registry script missing: $REGISTRY_FILE" >&2
  exit 1
fi

python3 - <<'PY' "$CHECKLIST_FILE" "$REGISTRY_FILE"
import re
import subprocess
import sys
from pathlib import Path

checklist_path = Path(sys.argv[1])
registry_path = Path(sys.argv[2])

checklist = checklist_path.read_text(encoding="utf-8")
registry = registry_path.read_text(encoding="utf-8")

# Extract scenario names referenced in checklist lines.
# Expected format: "Scenario(s): name[, name2] (notes...)"
scenario_refs = set()
for match in re.finditer(r"Scenario\(s\):([^\n]+)", checklist):
    tail = match.group(1)
    # Drop parenthetical notes.
    tail = re.sub(r"\([^)]*\)", "", tail)
    for part in tail.split(","):
        name = part.strip()
        if not name:
            continue
        # Only take the first token (scenario name).
        name = name.split()[0].strip().lower()
        if name == "none":
            continue
        scenario_refs.add(name)

# Extract scenario names from SCENARIO_REGISTRY array.
registry_names = set(re.findall(r'"([^"\s:]+):', registry))

missing = sorted(scenario_refs - registry_names)
if missing:
    print("Checklist references scenarios not in SCENARIO_REGISTRY:")
    for name in missing:
        print(f"  - {name}")
    sys.exit(2)

# Optional: check bead IDs referenced in checklist exist in br.
bead_ids = sorted(set(re.findall(r"wa-[a-z0-9][a-z0-9.-]*", checklist)))

if bead_ids:
    if subprocess.call(["bash", "-lc", "command -v br >/dev/null 2>&1"]) == 0:
        missing_beads = []
        for bead_id in bead_ids:
            result = subprocess.call(["br", "show", bead_id, "--json"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if result != 0:
                missing_beads.append(bead_id)
        if missing_beads:
            print("Checklist references bead IDs not found by br:")
            for bead_id in missing_beads:
                print(f"  - {bead_id}")
            sys.exit(3)
    else:
        print("br not available; skipping bead ID validation", file=sys.stderr)

print("OK: checklist scenarios align with registry")
PY
