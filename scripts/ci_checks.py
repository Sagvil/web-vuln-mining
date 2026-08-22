"""Repository-only policy checks used locally and by CI; no downloads or scans."""
from __future__ import annotations

import argparse
import importlib.util
import json
import re
import subprocess
from pathlib import Path

import yaml  # type: ignore[import-untyped]

from toolchain_integrity import verify_lock_schema
from validate_nuclei_rules import validate as validate_nuclei


ROOT = Path(__file__).resolve().parents[1]
LOCKS = ("tool-lock.linux.json", "tool-lock.linux-arm64.json", "tool-lock.windows.json")
ACTION_SHA = re.compile(r"^[0-9a-f]{40}$")
SECRET_VALUE = re.compile(r"(?i)(?:bearer\s+[a-z0-9._-]{16,}|-----begin(?: [a-z]+)? private key-----)")


def check_locks() -> list[str]:
    errors: list[str] = []
    for name in LOCKS:
        payload = json.loads((ROOT / "config" / name).read_text(encoding="utf-8"))
        errors.extend(f"{name}: {error}" for error in verify_lock_schema(payload))
    return errors


def check_hash_locks() -> list[str]:
    errors = []
    for name in ("requirements-runner.lock", "requirements-tools.lock", "requirements-dev.lock", "requirements-hexstrike.lock"):
        path = ROOT / name
        if not path.is_file():
            errors.append(f"missing {name}")
        elif "--hash=sha256:" not in path.read_text(encoding="utf-8"):
            errors.append(f"{name} lacks hash pins")
    return errors


def check_actions() -> list[str]:
    errors: list[str] = []
    lock = json.loads((ROOT / "config" / "ci-actions.lock.json").read_text(encoding="utf-8"))
    for name, value in lock.get("actions", {}).items():
        if not ACTION_SHA.fullmatch(str(value)):
            errors.append(f"CI action {name} is not pinned to a commit SHA")
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    for reference in re.findall(r"uses:\s*([^\s@]+)@([^\s]+)", workflow):
        if not ACTION_SHA.fullmatch(reference[1]):
            errors.append(f"workflow action is mutable: {reference[0]}@{reference[1]}")
    if "@sha256:" not in workflow:
        errors.append("workflow has no digest-pinned container")
    return errors


def check_rule_syntax() -> list[str]:
    errors: list[str] = []
    for path in (ROOT / "rules" / "semgrep").glob("*.yml"):
        try:
            document = yaml.safe_load(path.read_text(encoding="utf-8"))
            if not isinstance(document, dict) or not isinstance(document.get("rules"), list):
                errors.append(f"invalid Semgrep rule pack: {path.name}")
        except yaml.YAMLError as exc:
            errors.append(f"invalid Semgrep YAML {path.name}: {exc}")
    errors.extend(validate_nuclei(ROOT / "rules" / "nuclei"))
    return errors


def check_semgrep() -> list[str]:
    """Parse local rules with Semgrep Core, without version/network side effects."""
    specification = importlib.util.find_spec("semgrep")
    if specification is None or specification.origin is None:
        return ["Semgrep is not installed; CI must install requirements-dev.lock"]
    candidates = sorted(Path(specification.origin).resolve().parent.joinpath("bin").glob("semgrep-core*"))
    if not candidates:
        return ["Semgrep Core is unavailable in the installed Semgrep package"]
    result = subprocess.run(
        [str(candidates[0]), "-parse_rules", str(ROOT / "rules" / "semgrep")],
        capture_output=True,
        text=True,
        timeout=60,
    )
    return [] if result.returncode == 0 else [f"Semgrep rule validation failed: {result.stderr.strip() or result.stdout.strip()}"]


def check_secrets() -> list[str]:
    errors: list[str] = []
    for path in ROOT.rglob("*"):
        if not path.is_file() or any(part in {".git", "runs", "__pycache__"} for part in path.parts):
            continue
        try:
            if SECRET_VALUE.search(path.read_text(encoding="utf-8", errors="ignore")):
                errors.append(f"possible committed secret: {path.relative_to(ROOT)}")
        except OSError:
            continue
    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lock-only", action="store_true")
    parser.add_argument("--with-semgrep", action="store_true", help="require the locally installed Semgrep CLI to parse rules")
    args = parser.parse_args()
    errors = check_locks() + check_hash_locks()
    if not args.lock_only:
        errors += check_actions() + check_rule_syntax() + check_secrets()
    if args.with_semgrep:
        errors += check_semgrep()
    if errors:
        print("\n".join(errors))
        return 2
    print("CI policy checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
