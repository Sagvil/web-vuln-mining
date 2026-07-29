#!/usr/bin/env python3
"""Install the locked Linux ARM64 Web/API toolchain without sudo."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import zipfile
from datetime import datetime, timezone
from pathlib import Path

# ============================ Configuration zone ============================
# DATA_ROOT: user-owned tool and cache directory; WEB_VULN_MINING_DATA overrides it.
# DOWNLOAD_TIMEOUT_SECONDS: upper bound for each release asset or checksum request.
# ARM64 installs never run an AMD64 compatibility layer; CodeQL is replaced by Semgrep taint rules.
DATA_ROOT = Path(os.environ.get("WEB_VULN_MINING_DATA", str(Path.home() / ".local" / "share" / "web-vuln-mining")))
DOWNLOAD_TIMEOUT_SECONDS = 180
# ============================================================================

ROOT = Path(__file__).resolve().parents[1]
LOCK_PATH = ROOT / "config" / "tool-lock.linux-arm64.json"


def run(command: list[str], *, env: dict[str, str] | None = None) -> None:
    subprocess.run(command, check=True, cwd=ROOT, env=env)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def download(url: str, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    request = urllib.request.Request(url, headers={"User-Agent": "web-vuln-mining/0.1"})
    with urllib.request.urlopen(request, timeout=DOWNLOAD_TIMEOUT_SECONDS) as response, destination.open("wb") as handle:
        shutil.copyfileobj(response, handle)


def expected_checksum(checksum_url: str, asset: str, cache: Path) -> str:
    if not cache.exists():
        download(checksum_url, cache)
    for line in cache.read_text(encoding="utf-8", errors="replace").splitlines():
        fields = line.replace("*", " ").split()
        if len(fields) >= 2 and fields[1].rsplit("/", 1)[-1] == asset and len(fields[0]) == 64:
            return fields[0].lower()
    raise RuntimeError(f"checksum for {asset} not found in {checksum_url}")


def verified_download(url: str, asset: str, checksum_url: str | None, static_sha256: str | None) -> tuple[Path, str]:
    target = DATA_ROOT / "cache" / asset
    expected = static_sha256 or (expected_checksum(checksum_url, asset, DATA_ROOT / "cache" / f"{asset}.checksums.txt") if checksum_url else None)
    if not expected:
        raise RuntimeError(f"no checksum source configured for {asset}")
    if not target.exists() or sha256(target) != expected:
        target.unlink(missing_ok=True)
        download(url, target)
    actual = sha256(target)
    if actual != expected:
        target.unlink(missing_ok=True)
        raise RuntimeError(f"checksum mismatch for {asset}: expected {expected}, got {actual}")
    return target, actual


def archive_binary(archive: Path, binary: str, destination: Path) -> None:
    with tempfile.TemporaryDirectory(prefix="web-vuln-mining-") as temporary:
        root = Path(temporary)
        if archive.suffix == ".zip":
            with zipfile.ZipFile(archive) as bundle:
                bundle.extractall(root)
        else:
            with tarfile.open(archive) as bundle:
                bundle.extractall(root, filter="data")
        source = next((path for path in root.rglob(binary) if path.is_file()), None)
        if source is None:
            raise RuntimeError(f"{archive.name} does not contain {binary}")
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
        destination.chmod(0o755)


def release_url(name: str, version: str, asset: str) -> str:
    repositories = {
        "trivy": "aquasecurity/trivy", "gitleaks": "gitleaks/gitleaks", "nuclei": "projectdiscovery/nuclei",
        "pd-httpx": "projectdiscovery/httpx", "katana": "projectdiscovery/katana", "dalfox": "hahwul/dalfox", "ffuf": "ffuf/ffuf",
    }
    return f"https://github.com/{repositories[name]}/releases/download/v{version}/{asset}"


def install_go_fallback(name: str, record: dict[str, object], destination: Path) -> dict[str, str]:
    module = str(record["go_module"])
    version = str(record["version"])
    environment = os.environ.copy()
    stage = DATA_ROOT / "go-bin"
    stage.mkdir(parents=True, exist_ok=True)
    environment["GOBIN"] = str(stage)
    run(["go", "install", f"{module}@v{version}"], env=environment)
    binary = "httpx" if name == "pd-httpx" else name
    source = stage / binary
    if not source.is_file():
        raise RuntimeError(f"Go build did not produce {source}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)
    destination.chmod(0o755)
    return {"method": "go-build", "source": f"{module}@v{version}", "sha256": sha256(destination)}


def install_docker_wrapper(record: dict[str, object], destination: Path) -> dict[str, str]:
    image = str(record["docker_image"])
    run(["docker", "pull", image])
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text("#!/usr/bin/env bash\nset -euo pipefail\nexec docker run --rm --network host --user \"$(id -u):$(id -g)\" --entrypoint /app/dalfox -v \"$HOME:$HOME\" -w \"$PWD\" %s \"$@\"\n" % image, encoding="utf-8")
    destination.chmod(0o755)
    run([str(destination), "--version"])
    return {"method": "docker-native-image", "source": image, "sha256": sha256(destination)}


def install_release_or_go(name: str, record: dict[str, object]) -> dict[str, str]:
    executable = str(record["executable"])
    destination = DATA_ROOT / executable
    asset = str(record["asset"])
    binary = "httpx" if name == "pd-httpx" else name
    try:
        archive, digest = verified_download(release_url(name, str(record["version"]), asset), asset, str(record["checksum_url"]), None)
        archive_binary(archive, binary, destination)
        return {"method": "release", "source": release_url(name, str(record["version"]), asset), "sha256": digest}
    except Exception as error:
        if record.get("docker_image"):
            print(f"{name}: native release unavailable ({error}); using the locked native Docker image", file=sys.stderr)
            return install_docker_wrapper(record, destination)
        print(f"{name}: native release unavailable ({error}); building the locked Go tag", file=sys.stderr)
        return install_go_fallback(name, record, destination)


def install_python_tools(records: dict[str, dict[str, object]]) -> dict[str, dict[str, str]]:
    venv = DATA_ROOT / "bin" / "python-tools"
    run([sys.executable, "-m", "venv", str(venv)])
    pip = venv / "bin" / "pip"
    run([str(pip), "install", "--upgrade", "pip"])
    run([str(pip), "install", f"semgrep=={records['semgrep']['version']}", f"schemathesis=={records['schemathesis']['version']}", "PyYAML==6.0.3", "requests==2.32.5"])
    return {
        name: {"method": "python-venv", "source": f"{name}=={record['version']}", "sha256": sha256(DATA_ROOT / str(record["executable"]))}
        for name, record in records.items() if name in {"semgrep", "schemathesis"}
    }


def install_zap(record: dict[str, object]) -> dict[str, str]:
    asset = Path(str(record["url"])).name
    archive, digest = verified_download(str(record["url"]), asset, None, str(record["sha256"]))
    destination = DATA_ROOT / "bin" / "zap"
    shutil.rmtree(destination, ignore_errors=True)
    destination.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(archive) as bundle:
        bundle.extractall(destination)
    launcher = next(destination.rglob("zap.sh"), None)
    if launcher is None:
        raise RuntimeError("ZAP archive does not contain zap.sh")
    launcher.chmod(0o755)
    return {"method": "cross-platform-release", "source": str(record["url"]), "sha256": digest}


def install_sqlmap(record: dict[str, object]) -> dict[str, str]:
    asset = "sqlmap-1.10.zip"
    archive, digest = verified_download(str(record["url"]), asset, None, str(record["sha256"]))
    destination = DATA_ROOT / "bin" / "sqlmap"
    shutil.rmtree(destination, ignore_errors=True)
    with tempfile.TemporaryDirectory(prefix="sqlmap-") as temporary:
        with zipfile.ZipFile(archive) as bundle:
            bundle.extractall(temporary)
        source = next((path.parent for path in Path(temporary).rglob("sqlmap.py")), None)
        if source is None:
            raise RuntimeError("sqlmap archive does not contain sqlmap.py")
        shutil.copytree(source, destination)
    run([sys.executable, str(ROOT / "scripts" / "prepare_sqlmap.py"), str(destination), str(destination)])
    return {"method": "source-archive", "source": str(record["url"]), "sha256": digest}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--only-tools", default="")
    parser.add_argument("--repair", action="store_true")
    args = parser.parse_args()
    records = json.loads(LOCK_PATH.read_text(encoding="utf-8"))["tools"]
    requested = {name for name in args.only_tools.split(",") if name} or set(records)
    disabled = {name for name in requested if records[name].get("kind") == "platform-disabled"}
    selected = requested - disabled
    for name in sorted(disabled):
        print(f"{name}: platform-disabled; using {records[name].get('replacement', 'local replacement')}")
    installed: dict[str, dict[str, str]] = {}
    for name in selected:
        record = records[name]
        if record["kind"] == "release-or-go":
            installed[name] = install_release_or_go(name, record)
    if selected & {"semgrep", "schemathesis"}:
        installed.update(install_python_tools(records))
    if "zap" in selected:
        installed["zap"] = install_zap(records["zap"])
    if "sqlmap" in selected:
        installed["sqlmap"] = install_sqlmap(records["sqlmap"])
    state_path = DATA_ROOT / "install-state.json"
    try:
        previous = json.loads(state_path.read_text(encoding="utf-8")) if state_path.is_file() else {}
    except json.JSONDecodeError:
        previous = {}
    previous_tools = previous.get("tools", {}) if isinstance(previous.get("tools"), dict) else {}
    previous_tools.update(installed)
    previous_disabled = {str(item.get("name")): item for item in previous.get("platform_disabled", []) if isinstance(item, dict) and item.get("name")}
    previous_disabled.update({name: {"name": name, "replacement": records[name].get("replacement"), "reason": records[name].get("reason")} for name in disabled})
    state = {"schema_version": 2, "installed_at": datetime.now(timezone.utc).isoformat(), "platform": "linux-arm64", "data_root": str(DATA_ROOT), "tools": previous_tools, "platform_disabled": list(previous_disabled.values())}
    state_path.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
