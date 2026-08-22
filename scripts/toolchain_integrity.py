"""Schema, artifact, Python RECORD, and provenance verification helpers."""
from __future__ import annotations

import base64
import csv
import hashlib
import json
import platform
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


LOCK_SCHEMA_VERSION = 2
PROVENANCE_NAME = "provenance.json"
HEX = set("0123456789abcdef")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def is_sha256(value: object) -> bool:
    return isinstance(value, str) and len(value) == 64 and set(value.lower()) <= HEX


def lock_digest(lock_path: Path) -> str:
    return sha256_file(lock_path)


def verify_lock_schema(lock: dict[str, Any]) -> list[str]:
    """Return deterministic human-readable schema errors, never download data."""
    errors: list[str] = []
    if lock.get("schema_version") != LOCK_SCHEMA_VERSION:
        errors.append("lock schema_version must be 2")
    tools = lock.get("tools")
    if not isinstance(tools, dict) or not tools:
        return errors + ["lock.tools must be a non-empty object"]
    for name, record in sorted(tools.items()):
        if not isinstance(record, dict):
            errors.append(f"{name}: record must be an object")
            continue
        if record.get("kind") == "platform-disabled":
            if not str(record.get("reason", "")).strip():
                errors.append(f"{name}: platform-disabled record needs reason")
            continue
        for field in ("version", "url", "artifact_sha256", "executable", "executable_sha256", "install_method", "platform_support"):
            if not record.get(field):
                errors.append(f"{name}: missing {field}")
        for field in ("artifact_sha256",):
            if field in record and not is_sha256(record[field]):
                errors.append(f"{name}: {field} must be a SHA-256")
        if record.get("executable_sha256") != "computed" and not is_sha256(record.get("executable_sha256")):
            errors.append(f"{name}: executable_sha256 must be a SHA-256 or computed")
        if "checksum_url" in record or "go_module" in record or "docker_image" in record:
            errors.append(f"{name}: dynamic checksum, Go build, and Docker tag fallbacks are forbidden")
        if "@sha256:" not in str(record.get("container_image", "")) and record.get("install_method") == "container":
            errors.append(f"{name}: container_image must use image@sha256 digest")
    return errors


def _record_digest(value: str) -> str:
    """Turn a RECORD urlsafe base64 digest into normal hexadecimal SHA-256."""
    algorithm, encoded = value.split("=", 1)
    if algorithm != "sha256":
        raise ValueError("unsupported RECORD digest")
    return base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)).hex()


def verify_python_record(venv: Path) -> list[str]:
    """Check installed wheel RECORD entries below a venv; return errors."""
    errors: list[str] = []
    for record in venv.rglob("*.dist-info/RECORD"):
        try:
            rows = list(csv.reader(record.read_text(encoding="utf-8", errors="replace").splitlines()))
        except OSError as exc:
            errors.append(f"cannot read {record}: {exc}")
            continue
        base = record.parent.parent
        for row in rows:
            if len(row) < 2 or not row[1]:
                continue
            candidate = base / row[0]
            if not candidate.is_file():
                errors.append(f"RECORD missing file: {candidate}")
                continue
            try:
                if sha256_file(candidate) != _record_digest(row[1]):
                    errors.append(f"RECORD digest mismatch: {candidate}")
            except ValueError:
                errors.append(f"RECORD digest malformed: {candidate}")
    return errors


def provenance_path(data_root: Path) -> Path:
    return data_root / PROVENANCE_NAME


def write_provenance(data_root: Path, lock_path: Path, tools: dict[str, dict[str, Any]], python_venvs: list[Path]) -> Path:
    payload = {
        "schema_version": 2,
        "installed_at": datetime.now(timezone.utc).isoformat(),
        "platform": f"{platform.system().lower()}-{platform.machine().lower()}",
        "lock_path": str(lock_path),
        "lock_sha256": lock_digest(lock_path),
        "tools": tools,
        "python_record_errors": {str(venv): verify_python_record(venv) for venv in python_venvs if venv.is_dir()},
    }
    path = provenance_path(data_root)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return path


def verify_provenance(data_root: Path, lock_path: Path, lock: dict[str, Any], required: list[str]) -> list[str]:
    """Verify a previous local installation without repairing or downloading."""
    path = provenance_path(data_root)
    if not path.is_file():
        return [f"missing provenance: {path}"]
    try:
        provenance = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return [f"invalid provenance JSON: {path}"]
    errors: list[str] = []
    if provenance.get("lock_sha256") != lock_digest(lock_path):
        errors.append("provenance lock digest mismatch")
    installed = provenance.get("tools") if isinstance(provenance.get("tools"), dict) else {}
    for name in required:
        record = lock.get("tools", {}).get(name, {})
        if not isinstance(record, dict) or record.get("kind") == "platform-disabled":
            continue
        binary = data_root / str(record.get("executable", ""))
        if not binary.is_file():
            errors.append(f"missing executable: {name}")
            continue
        actual = sha256_file(binary)
        provenance_tool: dict[str, Any] = {}
        candidate_provenance = installed.get(name)
        if isinstance(candidate_provenance, dict):
            provenance_tool = candidate_provenance
        if provenance_tool.get("executable_sha256") != actual:
            errors.append(f"provenance executable digest mismatch: {name}")
        expected = str(record.get("executable_sha256", ""))
        # A lock can use the special computed marker only for interpreters whose
        # platform-specific wrapper is generated locally.  Its provenance is
        # still mandatory and hashed above.
        if expected != "computed" and actual != expected:
            errors.append(f"lock executable digest mismatch: {name}")
    for candidate in (data_root / "venv", data_root / "bin" / "python-tools"):
        if candidate.is_dir():
            errors.extend(verify_python_record(candidate))
    return errors
