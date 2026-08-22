#!/usr/bin/env bash
# Legacy extension entry point retained for callers; the verified core owns it.
set -euo pipefail
ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
ARGS=()
[[ -n "${WEB_VULN_MINING_ONLY_TOOLS:-}" ]] && ARGS+=(--only-tools "$WEB_VULN_MINING_ONLY_TOOLS")
python3 "$ROOT/scripts/install_toolchain.py" "${ARGS[@]}"
