"""Shared helpers for the local Web vulnerability mining workbench."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

# ============================ Configuration zone ============================
# WEB_VULN_MINING_DATA: user-owned tool/runtime root. Empty uses platform default.
# WEB_VULN_MINING_PYTHON: optional interpreter override for agent launchers.
# WEB_VULN_MINING_HEXSTRIKE_BRIDGE: optional local policy bridge path.
WORKBENCH_ROOT = Path(__file__).resolve().parents[1]
PLATFORM_DATA_ROOT = Path(os.environ.get(
    "WEB_VULN_MINING_DATA",
    str((Path(os.environ["LOCALAPPDATA"]) / "web-vuln-mining") if os.name == "nt" and os.environ.get("LOCALAPPDATA") else (Path.home() / ".local" / "share" / "web-vuln-mining"))
))
LOCAL_RUNTIME_CONFIG = WORKBENCH_ROOT / "config" / "local.runtime.yaml"
LEGACY_BIN_DIR = WORKBENCH_ROOT / "bin"
RUNS_DIR = WORKBENCH_ROOT / "runs"
DEFAULT_TIMEOUT_SECONDS = 900
# ============================================================================


def runtime_settings() -> dict[str, Any]:
    """Return optional private settings without requiring a local config file."""
    if not LOCAL_RUNTIME_CONFIG.is_file():
        return {}
    return load_yaml(LOCAL_RUNTIME_CONFIG)


def data_root() -> Path:
    # An explicit process environment always wins over a local file so agents
    # can run separate, isolated toolchains without modifying the repository.
    value = os.environ.get("WEB_VULN_MINING_DATA", "").strip() or str(runtime_settings().get("data_root") or "").strip()
    return Path(value).expanduser() if value else PLATFORM_DATA_ROOT


def utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def load_yaml(path: Path) -> dict[str, Any]:
    try:
        import yaml
    except ImportError as exc:
        raise RuntimeError("PyYAML is required. Run python -m pip install pyyaml") from exc
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a YAML mapping")
    return value


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def platform_lock_path() -> Path:
    """Select the required platform lock; unsupported or incomplete clones fail clearly."""
    name = "tool-lock.windows.json" if os.name == "nt" else "tool-lock.linux.json"
    candidate = WORKBENCH_ROOT / "config" / name
    if not candidate.is_file():
        raise RuntimeError(f"Missing platform lock: {candidate}")
    return candidate


def tool_path(name: str) -> Path | None:
    lock = load_json(platform_lock_path())
    record = lock.get("tools", {}).get(name, {})
    executable = record.get("executable")
    if not isinstance(executable, str) or executable.startswith("uvx "):
        return None
    portable = data_root() / executable
    if portable.exists():
        return portable
    # Linux ZAP archives carry a release directory; accept its launcher without
    # hard-coding a release-directory name in every caller.
    if name == "zap" and data_root().is_dir():
        discovered = next(data_root().glob("bin/zap/**/zap.sh"), None)
        if discovered:
            return discovered
    legacy = WORKBENCH_ROOT / executable
    return legacy if legacy.exists() else None


def command_for(name: str) -> list[str] | None:
    path = tool_path(name)
    if path:
        if name == "sqlmap":
            configured = os.environ.get("WEB_VULN_MINING_PYTHON", "").strip() or str(runtime_settings().get("python") or "").strip()
            return [configured or sys.executable, str(WORKBENCH_ROOT / "scripts" / "sqlmap_launcher.py"), "--sqlmap-root", str(path.parent)]
        return [str(path)]
    if name == "schemathesis":
        uvx = shutil.which("uvx")
        lock = load_json(platform_lock_path())
        version = lock["tools"]["schemathesis"]["version"]
        return [uvx, "--from", f"schemathesis=={version}", "schemathesis"] if uvx else None
    return None


def is_allowed_url(url: str, scope: dict[str, Any]) -> bool:
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    include_hosts = {str(item).lower() for item in scope.get("include_hosts", [])}
    if parsed.scheme not in {"http", "https"} or host not in include_hosts:
        return False
    path = parsed.path or "/"
    return not any(path.startswith(str(prefix)) for prefix in scope.get("exclude_paths", []))


def allowed_urls(scope: dict[str, Any], key: str = "base_urls") -> list[str]:
    return [str(url) for url in scope.get(key, []) if is_allowed_url(str(url), scope)]


def run_command(command: list[str], output: Path, timeout: int = DEFAULT_TIMEOUT_SECONDS, acceptable: set[int] | None = None) -> dict[str, Any]:
    acceptable = acceptable or {0}
    output.parent.mkdir(parents=True, exist_ok=True)
    started = datetime.now(timezone.utc).isoformat()
    try:
        environment = os.environ.copy()
        environment["PYTHONUTF8"] = "1"  # Keeps Python-based CLI output readable on Windows code pages.
        environment["PYTHONIOENCODING"] = "utf-8"
        completed = subprocess.run(command, cwd=WORKBENCH_ROOT, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout, env=environment)
        status = "completed" if completed.returncode in acceptable else "failed"
        record = {"command": command, "returncode": completed.returncode, "status": status, "started_at": started, "stdout": completed.stdout, "stderr": completed.stderr}
    except (OSError, subprocess.TimeoutExpired) as exc:
        record = {"command": command, "returncode": None, "status": "failed", "started_at": started, "stdout": "", "stderr": str(exc)}
    output.write_text(json.dumps(record, ensure_ascii=False, indent=2), encoding="utf-8")
    return record


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")
