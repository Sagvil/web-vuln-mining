"""Integration checks: governance decisions are written before profile tools run."""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import governance  # noqa: E402
import run_profile  # noqa: E402


class GovernanceRunnerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.scope = self.root / "scope.yaml"
        self.scope.write_text(
            "name: fixture\ninclude_hosts: [lab.example.test]\nbase_urls: [https://lab.example.test/]\nopenapi: []\nrate_limit: 2\ncrawl_budget: {max_depth: 1, max_pages: 10}\nprofiles: [web-baseline]\n",
            encoding="utf-8",
        )
        self.contract = self.root / "contract.json"
        self.contract.write_text(json.dumps({
            "schema_version": 1, "contract_id": "fixture", "status": "active",
            "valid_until": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
            "scope_ref": {"path": str(self.scope), "sha256": governance.file_sha256(self.scope)},
            "allowed_profiles": ["web-baseline"],
            "allowed_actions": ["bounded-network-read"],
            "budgets": {"max_targets": 1, "max_rate_limit": 2},
        }), encoding="utf-8")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def invoke(self, *extra: str) -> int:
        with mock.patch.object(sys, "argv", ["run_profile.py", str(self.scope), "--profile", "web-baseline", *extra]):
            return run_profile.main()

    def test_enforce_without_contract_blocks_before_profile_tools(self) -> None:
        runs = self.root / "runs"
        with mock.patch.object(run_profile, "RUNS_DIR", runs), mock.patch.object(run_profile, "preflight_inspect", return_value={"ok": True}), mock.patch.object(run_profile, "_load_template", return_value=None), mock.patch.object(run_profile, "_web") as web:
            self.assertEqual(4, self.invoke("--governance-mode", "enforce"))
        web.assert_not_called()
        manifest = json.loads(next(runs.glob("*/run-manifest.json")).read_text(encoding="utf-8"))
        self.assertEqual("blocked-policy", manifest["status"])
        self.assertEqual("REQUIRE_APPROVAL", manifest["governance"]["outcome"])

    def test_enforce_with_matching_contract_runs_and_receipts_result(self) -> None:
        runs = self.root / "runs"
        with mock.patch.object(run_profile, "RUNS_DIR", runs), mock.patch.object(run_profile, "preflight_inspect", return_value={"ok": True}), mock.patch.object(run_profile, "_load_template", return_value=None), mock.patch.object(run_profile, "_web") as web:
            self.assertEqual(0, self.invoke("--governance-mode", "enforce", "--governance-contract", str(self.contract)))
        web.assert_called_once()
        ledger = next(runs.glob("*/governance/action-ledger.jsonl"))
        rows = [json.loads(line) for line in ledger.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(["policy_decision", "execution_receipt"], [row["event"] for row in rows])


if __name__ == "__main__":
    unittest.main(verbosity=2)
