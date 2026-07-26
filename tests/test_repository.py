"""Repository-only validation; it never downloads tools or scans a target."""
from __future__ import annotations
import json
from pathlib import Path
# ============================ Configuration zone ============================
REQUIRED_TOOLS = {"semgrep", "codeql", "trivy", "gitleaks", "pd-httpx", "katana", "nuclei", "zap", "schemathesis"}
# ============================================================================
ROOT = Path(__file__).resolve().parents[1]
for lock_name in ("tool-lock.windows.json", "tool-lock.linux.json"):
    lock = json.loads((ROOT / "config" / lock_name).read_text(encoding="utf-8"))
    assert REQUIRED_TOOLS <= set(lock["tools"]), lock_name
for adapter in ("codex", "hermes", "openclaw"):
    assert (ROOT / "adapters" / adapter / "SKILL.md").is_file(), adapter
assert not any(part.lower() in {"bin", "runs", "cache"} for part in ["README.md"])
print("repository validation passed")
