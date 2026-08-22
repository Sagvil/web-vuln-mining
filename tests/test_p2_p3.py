"""Offline P2/P3 regression tests for integrity, passive rules, and reports."""
from __future__ import annotations

import base64
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import run_profile as runner  # noqa: E402
from openapi_lint import lint_openapi_file  # noqa: E402
from redaction import redact_text  # noqa: E402
from toolchain_integrity import verify_python_record, verify_provenance  # noqa: E402
from validate_nuclei_rules import validate as validate_nuclei  # noqa: E402


class P2P3Tests(unittest.TestCase):
    def test_python_record_tamper_is_detected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            target = root / "venv" / "lib" / "python3.12" / "site-packages" / "demo.py"
            target.parent.mkdir(parents=True)
            target.write_text("safe = False\n", encoding="utf-8")
            digest = base64.urlsafe_b64encode(hashlib.sha256(b"safe = True\n").digest()).decode().rstrip("=")
            record = target.parent / "demo-1.0.dist-info" / "RECORD"
            record.parent.mkdir()
            record.write_text(f"demo.py,sha256={digest},0\n", encoding="utf-8")
            self.assertTrue(verify_python_record(root / "venv"))

    def test_provenance_mismatch_blocks_profile_integrity(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            lock_path = ROOT / "config" / "tool-lock.linux.json"
            lock = json.loads(lock_path.read_text(encoding="utf-8"))
            executable = root / lock["tools"]["gitleaks"]["executable"]
            executable.parent.mkdir(parents=True)
            executable.write_bytes(b"tampered")
            (root / "provenance.json").write_text(json.dumps({"lock_sha256": "bad", "tools": {"gitleaks": {"executable_sha256": "bad"}}}), encoding="utf-8")
            errors = verify_provenance(root, lock_path, lock, ["gitleaks"])
            self.assertTrue(any("provenance" in item for item in errors), errors)

    def test_runner_does_not_start_profile_after_preflight_failure(self) -> None:
        scope = ROOT / "scopes" / "web-vuln-sample.yaml"
        with mock.patch.object(runner, "preflight_inspect", return_value={"ok": False, "errors": ["fixture mismatch"]}), mock.patch.object(runner, "_source") as source, mock.patch.object(sys, "argv", ["run_profile.py", str(scope), "--profile", "source"]):
            self.assertEqual(3, runner.main())
            source.assert_not_called()

    def test_validate_only_does_not_run_preflight(self) -> None:
        scope = ROOT / "scopes" / "web-vuln-sample.yaml"
        with mock.patch.object(runner, "preflight_inspect", side_effect=AssertionError("must not run")), mock.patch.object(sys, "argv", ["run_profile.py", str(scope), "--profile", "source", "--validate-only"]):
            self.assertEqual(0, runner.main())

    def test_zap_is_fixed_to_loopback_and_api_key_is_attached(self) -> None:
        self.assertEqual("key", runner._zap_params("key")["apikey"])
        with tempfile.TemporaryDirectory() as raw:
            run = Path(raw)
            for directory in ("raw", "logs", "sarif", "evidence"):
                (run / directory).mkdir()
            process = mock.Mock()
            process.poll.return_value = 0
            statuses: list[dict] = []
            with mock.patch.object(runner, "command_for", return_value=["zap"]), mock.patch.object(runner, "_wait_zap", return_value=False), mock.patch.object(runner.subprocess, "Popen", return_value=process) as popen:
                runner._zap_passive(["http://127.0.0.1/"], run, {"zap": {"host": "0.0.0.0", "port": 8099, "startup_timeout_seconds": 1}}, statuses, "zap-passive", 1)
            command = popen.call_args.args[0]
            self.assertEqual("127.0.0.1", command[command.index("-host") + 1])
            self.assertIn("api.disablekey=false", command)
            self.assertTrue(statuses and statuses[0]["status"] == "failed")

    def test_openapi_lint_is_offline_and_marks_candidates(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            schema = Path(raw) / "schema.yaml"
            schema.write_text("""openapi: 3.0.3
servers:
  - url: http://api.example.test
paths:
  /admin/users:
    post:
      responses: {}
      requestBody: {}
components:
  schemas:
    NeverFetched:
      $ref: https://outside.example/schema.yaml
""", encoding="utf-8")
            findings = lint_openapi_file(schema)
            self.assertTrue(findings)
            self.assertTrue(all(item["status"] == "candidate" for item in findings))
            self.assertTrue(any(item["rule"] == "openapi.insecure-transport" for item in findings))

    def test_nuclei_rules_are_get_or_head_only(self) -> None:
        self.assertEqual([], validate_nuclei(ROOT / "rules" / "nuclei"))
        for path in (ROOT / "rules" / "nuclei").glob("*.yaml"):
            document = yaml.safe_load(path.read_text(encoding="utf-8"))
            for request in document["http"]:
                self.assertIn(request["method"], {"GET", "HEAD"})

    def test_submission_requires_triage_review_scope_and_reproduction(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            run = Path(raw)
            for directory in ("raw", "sarif", "logs", "evidence"):
                (run / directory).mkdir()
            token = "Bearer " + "abcdefghijkl" + ".abcdefghijk.lmnopqrstuv"
            (run / "run-manifest.json").write_text(json.dumps({"schema_version": 2, "run_id": "fixture", "profile": "source", "local_tool_status": [], "hexstrike_status": "optional"}), encoding="utf-8")
            (run / "raw" / "dalfox.jsonl").write_text(json.dumps({"url": "http://127.0.0.1/?token=fixture-secret", "type": "xss", "param": "q", "message": token}) + "\n", encoding="utf-8")
            subprocess.run([sys.executable, str(ROOT / "scripts" / "normalize_results.py"), str(run)], check=True, capture_output=True, text=True)
            subprocess.run([sys.executable, str(ROOT / "scripts" / "create_report.py"), str(run)], check=True, capture_output=True, text=True)
            candidate_draft = (run / "submission" / "hackerone.md").read_text(encoding="utf-8")
            self.assertIn("No finding is eligible", candidate_draft)
            summary = json.loads((run / "summary.json").read_text(encoding="utf-8"))
            fingerprint = summary["findings"][0]["fingerprint"]
            (run / "triage.yaml").write_text("\n".join(["findings:", f"  - fingerprint: {fingerprint}", "    status: reproduced", "    human_reviewed: true", "    scope_confirmed: true", "    reviewer: tester", "    reviewed_at: 2026-08-23", "    impact: bounded test impact", "    cwe: CWE-79", "    reproduction_steps: [open local fixture]", "    recommendation: encode output"]), encoding="utf-8")
            subprocess.run([sys.executable, str(ROOT / "scripts" / "normalize_results.py"), str(run)], check=True, capture_output=True, text=True)
            subprocess.run([sys.executable, str(ROOT / "scripts" / "create_report.py"), str(run)], check=True, capture_output=True, text=True)
            draft = (run / "submission" / "hackerone.md").read_text(encoding="utf-8")
            self.assertIn("bounded test impact", draft)
            for output in (run / "report.md", run / "review.zh-CN.md", run / "sarif" / "normalized.sarif", run / "submission" / "hackerone.md"):
                self.assertNotIn("fixture-secret", output.read_text(encoding="utf-8"))
                self.assertNotIn(token, output.read_text(encoding="utf-8"))

    def test_redaction_covers_common_credentials(self) -> None:
        value = "Cookie: session=secret; Authorization: Bearer aaa.bbb.ccc&api_key=secret"
        self.assertNotIn("session=secret", redact_text(value))
        self.assertNotIn("api_key=secret", redact_text(value))


if __name__ == "__main__":
    unittest.main(verbosity=2)
