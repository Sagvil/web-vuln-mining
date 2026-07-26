"""Repository-only validation; it never downloads tools or scans a target."""
from __future__ import annotations
import json
import subprocess
import sys
from pathlib import Path
# ============================ Configuration zone ============================
REQUIRED_TOOLS = {"semgrep", "codeql", "trivy", "gitleaks", "pd-httpx", "katana", "nuclei", "zap", "schemathesis", "dalfox", "sqlmap", "ffuf"}
# ============================================================================
ROOT = Path(__file__).resolve().parents[1]
for lock_name in ("tool-lock.windows.json", "tool-lock.linux.json"):
    lock = json.loads((ROOT / "config" / lock_name).read_text(encoding="utf-8"))
    assert REQUIRED_TOOLS <= set(lock["tools"]), lock_name
    for name in ("dalfox", "sqlmap", "ffuf"):
        record = lock["tools"][name]
        assert record.get("url") and len(record.get("sha256", "")) == 64 and record.get("executable"), (lock_name, name)
for adapter in ("codex", "hermes", "openclaw"):
    assert (ROOT / "adapters" / adapter / "SKILL.md").is_file(), adapter
for profile in ("verify-xss", "verify-sqli", "content-discovery"):
    assert (ROOT / "profiles" / f"{profile}.yaml").is_file(), profile
for scope, profile in (("web-vuln-sample.yaml", "source"), ("web-vuln-sample-runtime.yaml", "web-baseline"), ("web-vuln-sample-runtime.yaml", "api"), ("web-vuln-sample-runtime.yaml", "verify-xss"), ("web-vuln-sample-runtime.yaml", "verify-sqli"), ("web-vuln-sample-runtime.yaml", "content-discovery")):
    result = subprocess.run([sys.executable, str(ROOT / "scripts" / "run_profile.py"), str(ROOT / "scopes" / scope), "--profile", profile, "--validate-only"], capture_output=True, text=True, encoding="utf-8", errors="replace")
    assert result.returncode == 0, result.stderr
assert (ROOT / "README.md").is_file() and (ROOT / "README.zh-CN.md").is_file()
print("repository validation passed")
