#!/usr/bin/env bash
# ============================ Configuration zone ============================
# BUTIAN_PIPELINE_VENV: override the private Python environment when needed.
VENV_DIR="$BUTIAN_PIPELINE_VENV"
if [[ -z "$VENV_DIR" ]]; then
  VENV_DIR="$HOME/.local/share/butian-src-pipeline/venv"
fi
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "$BASH_SOURCE")" && pwd)"
PYTHON="$VENV_DIR/bin/python"

if [[ ! -x "$PYTHON" ]]; then
  printf 'Missing private environment: %s\n' "$VENV_DIR" >&2
  printf 'Create it with: python3 -m venv %s && %s/bin/pip install -r %s/requirements-butian.txt\n' "$VENV_DIR" "$VENV_DIR" "$SCRIPT_DIR" >&2
  exit 2
fi

exec "$PYTHON" "$SCRIPT_DIR/butian_src_pipeline.py" "$@"
