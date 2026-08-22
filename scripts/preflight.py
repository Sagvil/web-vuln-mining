"""Read-only integrity preflight for a profile's locked local toolchain."""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from common import WORKBENCH_ROOT, data_root, load_json, platform_lock_path, runtime_settings, write_json
from toolchain_integrity import verify_lock_schema, verify_provenance


PROFILE_TOOLS = {
    "source": ["gitleaks", "trivy", "semgrep", "codeql"],
    "web-baseline": ["pd-httpx", "katana", "nuclei", "zap"],
    "api": ["schemathesis", "zap"],
    "verify-xss": ["dalfox"],
    "verify-sqli": ["sqlmap"],
    "content-discovery": ["ffuf"],
    "active-dns-discovery": [],
}
SYSTEM_PROFILE_BINARIES = {"active-dns-discovery": ["nmap"]}


def policy_bridge() -> Path | None:
    value = os.environ.get("WEB_VULN_MINING_HEXSTRIKE_BRIDGE", "").strip() or str(runtime_settings().get("hexstrike_bridge") or "").strip()
    return Path(value).expanduser() if value else None


def required_tools(profiles: list[str] | None) -> list[str]:
    selected = profiles or ["source", "web-baseline", "api"]
    return list(dict.fromkeys(tool for profile in selected for tool in PROFILE_TOOLS[profile]))


def inspect(profiles: list[str] | None, check_policy: bool = False) -> dict[str, Any]:
    lock_path = platform_lock_path()
    lock = load_json(lock_path)
    selected = profiles or ["source", "web-baseline", "api"]
    required = required_tools(selected)
    schema_errors = verify_lock_schema(lock)
    integrity_errors = verify_provenance(data_root(), lock_path, lock, required) if not schema_errors else []
    records = lock.get("tools", {}) if isinstance(lock.get("tools"), dict) else {}
    tools: list[dict[str, Any]] = []
    for name in required:
        record = records.get(name, {}) if isinstance(records.get(name), dict) else {}
        disabled = record.get("kind") == "platform-disabled"
        tools.append({
            "name": name,
            "locked_version": record.get("version"),
            "present": False if disabled else not any(name in error for error in integrity_errors),
            "platform_disabled": disabled,
            "reason": record.get("reason") if disabled else None,
        })
    system = []
    for profile in selected:
        for binary in SYSTEM_PROFILE_BINARIES.get(profile, []):
            present = shutil.which(binary) is not None
            system.append({"name": binary, "present": present})
            if not present:
                integrity_errors.append(f"missing system dependency: {binary}")
    dependencies = []
    for name in ("yaml", "requests"):
        present = importlib.util.find_spec(name) is not None
        dependencies.append({"name": name, "present": present})
        if not present:
            integrity_errors.append(f"missing runner dependency: {name}")
    bridge = policy_bridge() if check_policy else None
    if check_policy and bridge and not bridge.exists():
        integrity_errors.append("configured HexStrike policy bridge is missing")
    return {
        "schema_version": 2,
        "workbench": str(WORKBENCH_ROOT),
        "data_root": str(data_root()),
        "lock": str(lock_path),
        "required_profiles": selected,
        "tools": tools,
        "system_tools": system,
        "runtime_dependencies": dependencies,
        "hexstrike_policy_bridge": str(bridge) if bridge else None,
        "errors": schema_errors + integrity_errors,
        "ok": not schema_errors and not integrity_errors,
    }


def explicit_repair(profiles: list[str] | None) -> int:
    """Run the unified installer only after the operator explicitly requests it."""
    lock_name = platform_lock_path().name
    command = [sys.executable, str(WORKBENCH_ROOT / "scripts" / "install_toolchain.py"), "--lock", lock_name, "--only-tools", ",".join(required_tools(profiles))]
    return subprocess.run(command, cwd=WORKBENCH_ROOT).returncode


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--check-policy", action="store_true")
    parser.add_argument("--repair", action="store_true", help="explicitly run the unified locked installer, then re-check")
    parser.add_argument("--required-profiles", nargs="+", choices=sorted(PROFILE_TOOLS))
    args = parser.parse_args()
    if args.repair and explicit_repair(args.required_profiles) != 0:
        return 2
    result = inspect(args.required_profiles, args.check_policy)
    write_json(data_root() / "preflight-latest.json", result)
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        for tool in result["tools"] + result["system_tools"]:
            print(f"{tool['name']}: {'OK' if tool.get('present') or tool.get('platform_disabled') else 'FAILED'}")
        for error in result["errors"]:
            print(f"ERROR: {error}", file=sys.stderr)
    return 0 if result["ok"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
