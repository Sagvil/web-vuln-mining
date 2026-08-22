"""Repository-only integrity validation; it never downloads tools or scans a target."""
from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from toolchain_integrity import verify_lock_schema  # noqa: E402


class RepositoryTests(unittest.TestCase):
    def test_v2_locks_have_no_dynamic_fallback(self) -> None:
        for name in ("tool-lock.windows.json", "tool-lock.linux.json", "tool-lock.linux-arm64.json"):
            payload = json.loads((ROOT / "config" / name).read_text(encoding="utf-8"))
            self.assertEqual([], verify_lock_schema(payload), name)
            for record in payload["tools"].values():
                if record.get("kind") != "platform-disabled":
                    self.assertNotIn("checksum_url", record)
                    self.assertNotIn("go_module", record)
                    self.assertNotIn("docker_image", record)

    def test_hash_locks_and_adapters_exist(self) -> None:
        for name in ("requirements-runner.lock", "requirements-tools.lock", "requirements-dev.lock", "requirements-hexstrike.lock"):
            self.assertIn("--hash=sha256:", (ROOT / name).read_text(encoding="utf-8"))
        for adapter in ("codex", "hermes", "openclaw"):
            self.assertTrue((ROOT / "adapters" / adapter / "SKILL.md").is_file())

    def test_validate_only_never_requires_preflight(self) -> None:
        checks = (("web-vuln-sample.yaml", "source"), ("web-vuln-sample-runtime.yaml", "web-baseline"), ("web-vuln-sample-runtime.yaml", "api"))
        for scope, profile in checks:
            result = subprocess.run([sys.executable, str(ROOT / "scripts" / "run_profile.py"), str(ROOT / "scopes" / scope), "--profile", profile, "--validate-only"], capture_output=True, text=True, encoding="utf-8", errors="replace")
            self.assertEqual(0, result.returncode, result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
