#!/usr/bin/env bash
# Compatibility front end for the single locked Python installer core.
set -euo pipefail

PROFILE="default"
WITH_HEXSTRIKE=0
HEXSTRIKE_CONFIG=""
INSTALL_CODEX_SKILL=0
REPAIR=0
ONLY_TOOLS=""
DRY_RUN=0
ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --profile) PROFILE="$2"; shift 2 ;;
    --with-hexstrike) WITH_HEXSTRIKE=1; shift ;;
    --hexstrike-config) HEXSTRIKE_CONFIG="$2"; shift 2 ;;
    --install-codex-skill) INSTALL_CODEX_SKILL=1; shift ;;
    --repair) REPAIR=1; shift ;;
    --only-tools) ONLY_TOOLS="$2"; shift 2 ;;
    --dry-run) DRY_RUN=1; shift ;;
    -h|--help)
      echo "usage: install.sh [--profile default] [--repair] [--only-tools names] [--install-codex-skill] [--with-hexstrike --hexstrike-config FILE] [--dry-run]"
      exit 0 ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
done

INSTALL=(python3 "$ROOT/scripts/install_toolchain.py")
[[ -n "$ONLY_TOOLS" ]] && INSTALL+=(--only-tools "$ONLY_TOOLS")
if [[ "$DRY_RUN" == 1 ]]; then
  printf '[dry-run] '; printf '%q ' "${INSTALL[@]}"; echo
  exit 0
fi

# --repair remains an explicit user action. The core is idempotent and never
# falls back to dynamic checksums, source builds, or mutable Docker tags.
"${INSTALL[@]}"
WEB_VULN_MINING_DATA="${WEB_VULN_MINING_DATA:-$HOME/.local/share/web-vuln-mining}" \
  python3 "$ROOT/scripts/preflight.py" --json --required-profiles source web-baseline api

if [[ "$INSTALL_CODEX_SKILL" == 1 ]]; then
  mkdir -p "$HOME/.codex/skills/web-vuln-mining"
  cp "$ROOT/adapters/codex/SKILL.md" "$HOME/.codex/skills/web-vuln-mining/SKILL.md"
fi
if [[ "$WITH_HEXSTRIKE" == 1 ]]; then
  [[ -n "$HEXSTRIKE_CONFIG" ]] || { echo '--with-hexstrike requires --hexstrike-config' >&2; exit 2; }
  python3 -m pip install --require-hashes -r "$ROOT/requirements-hexstrike.lock"
  python3 "$ROOT/scripts/hexstrike_deploy.py" --config "$HEXSTRIKE_CONFIG"
fi

echo "Installed profile ${PROFILE} with immutable lock verification."
