"""Validate second-batch result normalization without running external scanners."""
from __future__ import annotations
import json
import subprocess
import sys
import tempfile
from pathlib import Path
# ============================ Configuration zone ============================
ROOT = Path(__file__).resolve().parents[1]  # Repository root containing normalization script.
# ============================================================================
with tempfile.TemporaryDirectory() as temporary:
    run = Path(temporary); (run / "raw").mkdir(); (run / "sarif").mkdir(); (run / "evidence").mkdir()
    (run / "run-manifest.json").write_text(json.dumps({"run_id": "fixture", "profile": "verify-xss", "local_tool_status": [], "hexstrike_status": "optional-not-requested"}), encoding="utf-8")
    (run / "raw" / "dalfox.jsonl").write_text(json.dumps({"url": "http://127.0.0.1/?q=x", "type": "reflected", "param": "q", "message": "fixture"}) + "\n", encoding="utf-8")
    (run / "raw" / "ffuf-0.json").write_text(json.dumps({"results": [{"url": "http://127.0.0.1/admin", "status": 200}]}), encoding="utf-8")
    result = subprocess.run([sys.executable, str(ROOT / "scripts" / "normalize_results.py"), str(run)], capture_output=True, text=True, encoding="utf-8", errors="replace")
    assert result.returncode == 0, result.stderr
    summary = json.loads((run / "summary.json").read_text(encoding="utf-8"))
    assert summary["counts"]["candidate"] == 2, summary
    assert len(json.loads((run / "evidence" / "findings.json").read_text(encoding="utf-8"))["findings"]) == 2
    assert len(json.loads((run / "sarif" / "normalized.sarif").read_text(encoding="utf-8"))["runs"][0]["results"]) == 2
    rerun = subprocess.run([sys.executable, str(ROOT / "scripts" / "normalize_results.py"), str(run)], capture_output=True, text=True, encoding="utf-8", errors="replace")
    assert rerun.returncode == 0, rerun.stderr
    assert json.loads((run / "summary.json").read_text(encoding="utf-8"))["counts"]["candidate"] == 2
print("normalization validation passed")
