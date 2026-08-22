"""Install immutable release assets and hash-locked Python requirements.

This is the sole installer core used by Bash, PowerShell, and ARM64 wrappers.
It intentionally has no source-build, dynamic-checksum, or mutable-image path.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import zipfile
from pathlib import Path
from typing import Any

from toolchain_integrity import sha256_file, verify_lock_schema, write_provenance


ROOT = Path(__file__).resolve().parents[1]


def data_root() -> Path:
    return Path(os.environ.get("WEB_VULN_MINING_DATA", str(Path.home() / ".local" / "share" / "web-vuln-mining"))).expanduser()


def lock_for_platform(name: str | None) -> Path:
    if name:
        return ROOT / "config" / name
    return ROOT / "config" / ("tool-lock.windows.json" if os.name == "nt" else "tool-lock.linux-arm64.json" if os.uname().machine.lower() in {"aarch64", "arm64"} else "tool-lock.linux.json")


def download(url: str, path: Path, expected: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_file() and sha256_file(path) == expected:
        return
    path.unlink(missing_ok=True)
    request = urllib.request.Request(url, headers={"User-Agent": "web-vuln-mining/2"})
    with urllib.request.urlopen(request, timeout=180) as response, path.open("wb") as handle:
        shutil.copyfileobj(response, handle)
    if sha256_file(path) != expected:
        path.unlink(missing_ok=True)
        raise RuntimeError(f"artifact digest mismatch: {path.name}")


def extract(archive: Path, destination: Path) -> None:
    with tempfile.TemporaryDirectory(prefix="web-vuln-mining-") as temporary:
        temporary_root = Path(temporary)
        if archive.suffix.lower() == ".zip":
            with zipfile.ZipFile(archive) as bundle:
                bundle.extractall(temporary_root)
        else:
            with tarfile.open(archive) as bundle:
                bundle.extractall(temporary_root, filter="data")
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(temporary_root, destination, dirs_exist_ok=True)


def install_archive(name: str, record: dict[str, Any], root: Path) -> dict[str, Any]:
    executable = root / str(record["executable"])
    artifact = root / "cache" / Path(str(record["url"])).name
    download(str(record["url"]), artifact, str(record["artifact_sha256"]))
    stage = root / "stage" / name
    shutil.rmtree(stage, ignore_errors=True)
    extract(artifact, stage)
    expected_name = str(record.get("asset_executable") or executable.name)
    source = next((item for item in stage.rglob(expected_name) if item.is_file()), None)
    if source is None:
        raise RuntimeError(f"{name}: executable {expected_name} not found in locked asset")
    executable.parent.mkdir(parents=True, exist_ok=True)
    if record.get("archive_layout") == "tree":
        shutil.copytree(source.parent, executable.parent, dirs_exist_ok=True)
    else:
        shutil.copy2(source, executable)
    if os.name != "nt":
        executable.chmod(0o755)
    actual = sha256_file(executable)
    expected = str(record.get("executable_sha256", "computed"))
    if expected != "computed" and actual != expected:
        executable.unlink(missing_ok=True)
        raise RuntimeError(f"{name}: executable digest mismatch")
    return {"artifact_sha256": str(record["artifact_sha256"]), "executable_sha256": actual, "method": record["install_method"], "url": record["url"]}


def install_python(root: Path, lock_file: Path) -> None:
    venv = root / "venv"
    subprocess.run([sys.executable, "-m", "venv", str(venv)], check=True)
    python = venv / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    subprocess.run([str(python), "-m", "pip", "install", "--require-hashes", "--no-deps", "-r", str(lock_file)], check=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lock", choices=["tool-lock.linux.json", "tool-lock.linux-arm64.json", "tool-lock.windows.json"])
    parser.add_argument("--only-tools", default="")
    parser.add_argument("--skip-python", action="store_true")
    args = parser.parse_args()
    lock_path = lock_for_platform(args.lock)
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    errors = verify_lock_schema(lock)
    if errors:
        raise SystemExit("\n".join(errors))
    selected = {name for name in args.only_tools.split(",") if name} or set(lock["tools"])
    root = data_root()
    installed: dict[str, dict[str, Any]] = {}
    for name in sorted(selected):
        record = lock["tools"].get(name)
        if not isinstance(record, dict):
            raise SystemExit(f"unknown tool: {name}")
        if record.get("kind") == "platform-disabled":
            continue
        if record.get("install_method") == "python":
            continue
        installed[name] = install_archive(name, record, root)
    if not args.skip_python:
        install_python(root, ROOT / "requirements-tools.lock")
        for name, record in lock["tools"].items():
            if isinstance(record, dict) and record.get("install_method") == "python":
                executable = root / str(record["executable"])
                if executable.is_file():
                    installed[name] = {"artifact_sha256": "python-lock", "executable_sha256": sha256_file(executable), "method": "python", "url": "requirements-tools.lock"}
    write_provenance(root, lock_path, installed, [root / "venv"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
