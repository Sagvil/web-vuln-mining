"""Check the Web-only toolchain before a profile run."""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from common import WORKBENCH_ROOT, command_for, data_root, load_json, platform_lock_path, runtime_settings, write_json

# ============================ Configuration zone ============================
# CORE_TOOLS: first-batch Web/API tools required by the default profiles.
# HexStrike is optional; WEB_VULN_MINING_HEXSTRIKE_BRIDGE or local.runtime.yaml enables it.
CORE_TOOLS = ["semgrep", "codeql", "trivy", "gitleaks", "pd-httpx", "katana", "nuclei", "zap", "schemathesis"]
# ============================================================================


def policy_bridge() -> Path | None:
    configured = os.environ.get("WEB_VULN_MINING_HEXSTRIKE_BRIDGE", "").strip() or str(runtime_settings().get("hexstrike_bridge") or "").strip()
    return Path(configured).expanduser() if configured else None

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except AttributeError:
    pass


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--check-policy", action="store_true")
    args = parser.parse_args()
    lock = load_json(platform_lock_path())
    tools = []
    missing = []
    for name in CORE_TOOLS:
        command = command_for(name)
        present = command is not None and (name == "schemathesis" or Path(command[0]).exists())
        tools.append({"name": name, "version": lock["tools"][name]["version"], "present": present, "command": command})
        if not present:
            missing.append(name)
    bridge = policy_bridge()
    result = {"workbench": str(WORKBENCH_ROOT), "data_root": str(data_root()), "lock": str(platform_lock_path()), "tools": tools, "missing": missing, "hexstrike_policy_bridge": bridge.exists() if args.check_policy and bridge else False if args.check_policy else None}
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        for item in tools:
            print(f"{item['name']}: {'OK' if item['present'] else 'MISSING'} ({item['version']})")
        if args.check_policy:
            print(f"hexstrike-policy: {'OK' if OPTIONAL_POLICY_BRIDGE.exists() else 'MISSING'}")
    write_json(WORKBENCH_ROOT / "runs" / "preflight-latest.json", result)
    return 0 if not missing else 2


if __name__ == "__main__":
    sys.exit(main())
