"""Offline regression tests for Action Contract shadow/enforcement decisions."""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import governance  # noqa: E402


class GovernanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.scope_path = self.root / "scope.yaml"
        self.scope_path.write_text(
            "name: fixture\ninclude_hosts: [lab.example.test]\nbase_urls: [https://lab.example.test/]\nrate_limit: 2\ncrawl_budget: {max_depth: 1, max_pages: 10}\nprofiles: [web-baseline, verify-llm-injection]\n",
            encoding="utf-8",
        )
        self.scope = {
            "name": "fixture", "include_hosts": ["lab.example.test"],
            "base_urls": ["https://lab.example.test/"], "openapi": [],
            "rate_limit": 2, "crawl_budget": {"max_depth": 1, "max_pages": 10},
        }

    def tearDown(self) -> None:
        self.temp.cleanup()

    def contract(self, **updates: object) -> Path:
        payload: dict[str, object] = {
            "schema_version": 1, "contract_id": "fixture-contract", "status": "active",
            "valid_until": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
            "scope_ref": {"path": str(self.scope_path), "sha256": governance.file_sha256(self.scope_path)},
            "allowed_profiles": ["web-baseline"],
            "allowed_actions": ["bounded-network-read"],
            "budgets": {"max_targets": 1, "max_rate_limit": 2},
            "skipped_profiles": ["verify-llm-injection"],
        }
        payload.update(updates)
        path = self.root / "contract.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def test_shadow_without_contract_records_approval_need(self) -> None:
        decision, contract = governance.evaluate(self.scope_path, self.scope, "web-baseline", mode="shadow")
        self.assertIsNone(contract)
        self.assertEqual("REQUIRE_APPROVAL", decision["outcome"])

    def test_enforce_valid_contract_permits_and_binds_intent(self) -> None:
        decision, _ = governance.evaluate(self.scope_path, self.scope, "web-baseline", mode="enforce", contract_path=self.contract())
        self.assertEqual("PERMIT_AND_NOTIFY", decision["outcome"])
        self.assertTrue(decision["intent_fingerprint"].startswith("sha256:"))

    def test_changed_scope_or_expired_contract_requires_approval(self) -> None:
        contract = self.contract(valid_until=(datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat())
        decision, _ = governance.evaluate(self.scope_path, self.scope, "web-baseline", mode="enforce", contract_path=contract)
        self.assertEqual("REQUIRE_APPROVAL", decision["outcome"])
        contract = self.contract()
        self.scope_path.write_text(self.scope_path.read_text(encoding="utf-8") + "exclude_paths: [/logout]\n", encoding="utf-8")
        decision, _ = governance.evaluate(self.scope_path, self.scope, "web-baseline", mode="enforce", contract_path=contract)
        self.assertEqual("REQUIRE_APPROVAL", decision["outcome"])

    def test_contract_skip_denies_without_executing_profile(self) -> None:
        decision, _ = governance.evaluate(self.scope_path, self.scope, "verify-llm-injection", mode="enforce", contract_path=self.contract())
        self.assertEqual("DENY", decision["outcome"])

    def test_artifacts_separate_policy_from_execution_receipt(self) -> None:
        decision, contract = governance.evaluate(self.scope_path, self.scope, "web-baseline", mode="shadow", contract_path=self.contract())
        run = self.root / "run"
        governance.write_artifacts(run, decision, contract, execution={"status": "completed", "verification_status": "unverified"})
        rows = [json.loads(line) for line in (run / "governance" / "action-ledger.jsonl").read_text(encoding="utf-8").splitlines()]
        self.assertEqual(["policy_decision", "execution_receipt"], [row["event"] for row in rows])
        self.assertTrue((run / "governance" / "evidence-index.json").is_file())


if __name__ == "__main__":
    unittest.main(verbosity=2)
