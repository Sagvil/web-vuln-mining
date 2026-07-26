"""Run a Web-only source, baseline, or API profile from a TARGET.yaml manifest."""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import time
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import requests

from common import DEFAULT_TIMEOUT_SECONDS, RUNS_DIR, WORKBENCH_ROOT, allowed_urls, command_for, is_allowed_url, load_yaml, run_command, utc_stamp, write_json

# Configuration zone: execution limits and output locations for all profiles.
DEFAULT_PROFILE_TIMEOUT_SECONDS = DEFAULT_TIMEOUT_SECONDS
ZAP_API_KEY = ""  # Empty by design: ZAP is bound only to loopback by this runner.
MAX_DISCOVERED_URLS = 5000

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except AttributeError:
    pass


def _append_status(statuses: list[dict[str, Any]], tool: str, record: dict[str, Any], output: Path | None = None) -> None:
    item = {"tool": tool, "status": record["status"], "returncode": record["returncode"], "output": str(output) if output else None, "log": record}
    if record.get("fallback"):
        item["fallback"] = record["fallback"]
    statuses.append(item)


def _missing(tool: str, statuses: list[dict[str, Any]]) -> bool:
    if command_for(tool):
        return False
    statuses.append({"tool": tool, "status": "skipped", "reason": "tool not installed"})
    return True


def _source(scope: dict[str, Any], run_dir: Path, statuses: list[dict[str, Any]]) -> None:
    root = Path(str(scope.get("source_root", ""))).expanduser()
    if not root.is_dir():
        statuses.append({"tool": "source", "status": "skipped", "reason": f"source_root not found: {root}"})
        return
    raw, sarif, logs = run_dir / "raw", run_dir / "sarif", run_dir / "logs"
    if not _missing("gitleaks", statuses):
        output = sarif / "gitleaks.sarif"
        _append_status(statuses, "gitleaks", run_command(command_for("gitleaks") + ["git", "--report-format", "sarif", "--report-path", str(output), str(root)], logs / "gitleaks.json", acceptable={0, 1}), output)
    if not _missing("trivy", statuses):
        output = sarif / "trivy.sarif"
        # A non-zero exit is meaningful for findings, but a database bootstrap error must trigger
        # the offline secret/misconfiguration fallback instead of being reported as a completed scan.
        record = run_command(command_for("trivy") + ["fs", "--scanners", "vuln,secret,misconfig", "--format", "sarif", "--output", str(output), str(root)], logs / "trivy.json", acceptable={0})
        if record["status"] == "failed" and "failed to download vulnerability DB" in record["stderr"]:
            fallback = run_command(command_for("trivy") + ["fs", "--skip-db-update", "--scanners", "secret,misconfig", "--format", "sarif", "--output", str(output), str(root)], logs / "trivy-fallback.json", acceptable={0, 1})
            fallback["fallback"] = "vulnerability DB unavailable; completed secret and misconfiguration scanners only"
            record = fallback
        _append_status(statuses, "trivy", record, output)
    if not _missing("semgrep", statuses):
        output = sarif / "semgrep.sarif"
        _append_status(statuses, "semgrep", run_command(command_for("semgrep") + ["scan", "--config", str(WORKBENCH_ROOT / "rules" / "semgrep"), "--sarif", "--output", str(output), str(root)], logs / "semgrep.json", acceptable={0, 1}), output)
    if _missing("codeql", statuses):
        return
    codeql = scope.get("codeql") if isinstance(scope.get("codeql"), dict) else {}
    languages = [str(item) for item in codeql.get("languages", [])]
    if not languages:
        statuses.append({"tool": "codeql", "status": "skipped", "reason": "codeql.languages is empty"})
        return
    db_root = raw / "codeql-db"
    command = command_for("codeql") + ["database", "create", str(db_root), "--db-cluster", "--source-root", str(root), "--language", ",".join(languages), "--overwrite"]
    build = str(codeql.get("build_command", "")).strip()
    if build:
        command.extend(["--command", build])
    record = run_command(command, logs / "codeql-create.json")
    _append_status(statuses, "codeql-create", record, db_root)
    if record["status"] != "completed":
        return
    for language in languages:
        db = db_root / language
        if not db.exists():
            continue
        output = sarif / f"codeql-{language}.sarif"
        record = run_command(command_for("codeql") + ["database", "analyze", str(db), f"codeql/{language}-queries", "--format=sarif-latest", f"--output={output}"], logs / f"codeql-{language}.json", acceptable={0, 1})
        _append_status(statuses, f"codeql-{language}", record, output)


def _read_jsonl_urls(path: Path, scope: dict[str, Any]) -> list[str]:
    urls: list[str] = []
    if not path.exists():
        return urls
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        request = item.get("request") if isinstance(item, dict) else None
        value = item.get("url") if isinstance(item, dict) else None
        if not value and isinstance(request, dict):
            value = request.get("endpoint")
        if isinstance(value, str) and is_allowed_url(value, scope) and value not in urls:
            urls.append(value)
        if len(urls) >= MAX_DISCOVERED_URLS:
            break
    return urls


def _header_values(scope: dict[str, Any]) -> list[str]:
    """Read one `Name: value` header per line from the optional scope file."""
    candidate = str((scope.get("auth") or {}).get("headers_file", "")).strip()
    path = Path(candidate).expanduser() if candidate else None
    if not path or not path.is_file():
        return []
    return [line.strip() for line in path.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip() and not line.lstrip().startswith("#")]


def _katana_scope_args(scope: dict[str, Any]) -> list[str]:
    hosts = [re.escape(str(host).lower()) for host in scope.get("include_hosts", [])]
    if not hosts:
        return []
    args = ["-crawl-scope", rf"^https?://(?:{'|'.join(hosts)})(?::\d+)?(?:/|$)"]
    for prefix in scope.get("exclude_paths", []):
        path = re.escape(str(prefix))
        args.extend(["-crawl-out-scope", rf"^https?://(?:{'|'.join(hosts)})(?::\d+)?{path}(?:/|$)"])
    return args


def _wait_zap(base: str, timeout: int) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if requests.get(f"{base}/JSON/core/view/version/", timeout=3).ok:
                return True
        except requests.RequestException:
            pass
        time.sleep(2)
    return False


def _zap_passive(urls: list[str], run_dir: Path, settings: dict[str, Any], statuses: list[dict[str, Any]], label: str, rate_limit: int, openapi_schemas: list[str] | None = None) -> None:
    if not urls:
        statuses.append({"tool": label, "status": "skipped", "reason": "no in-scope URLs"})
        return
    if _missing("zap", statuses):
        return
    zap = settings.get("zap") if isinstance(settings.get("zap"), dict) else {}
    host, port = str(zap.get("host", "127.0.0.1")), int(zap.get("port", 8090))
    base = f"http://{host}:{port}"
    zap_command = command_for("zap")
    # zap.bat resolves zap-<version>.jar relative to its own directory.
    process = subprocess.Popen(zap_command + ["-daemon", "-host", host, "-port", str(port), "-config", "api.disablekey=true"], cwd=Path(zap_command[0]).parent, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if not _wait_zap(base, int(zap.get("startup_timeout_seconds", 90))):
        process.terminate()
        statuses.append({"tool": label, "status": "failed", "reason": "ZAP daemon did not become ready"})
        return
    try:
        requests.get(f"{base}/JSON/core/action/newSession/", params={"overwrite": "true"}, timeout=10)
        # OpenAPI import lets ZAP parse operation metadata without enabling an active attack scan.
        for schema in openapi_schemas or []:
            requests.get(f"{base}/JSON/openapi/action/importUrl/", params={"url": schema}, timeout=30)
        delay = 1 / max(1, rate_limit)
        for index, url in enumerate(urls):
            requests.get(f"{base}/JSON/core/action/accessUrl/", params={"url": url}, timeout=30)
            if index + 1 < len(urls):
                time.sleep(delay)
        # The runner deliberately avoids ZAP's autonomous spider: supplied URLs are already
        # filtered by the TARGET manifest and Katana budget, so ZAP remains in the same scope.
        alerts = requests.get(f"{base}/JSON/core/view/alerts/", params={"start": 0, "count": 9999}, timeout=30).json()
        output = run_dir / "raw" / f"{label}.json"
        write_json(output, alerts)
        statuses.append({"tool": label, "status": "completed", "output": str(output), "alerts": len(alerts.get("alerts", []))})
    except (requests.RequestException, ValueError) as exc:
        statuses.append({"tool": label, "status": "failed", "reason": str(exc)})
    finally:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()


def _web(scope: dict[str, Any], run_dir: Path, statuses: list[dict[str, Any]], settings: dict[str, Any]) -> None:
    urls = allowed_urls(scope)
    if not urls:
        statuses.append({"tool": "web-baseline", "status": "skipped", "reason": "no in-scope base_urls"})
        return
    raw, logs = run_dir / "raw", run_dir / "logs"
    targets = raw / "base-urls.txt"
    targets.parent.mkdir(parents=True, exist_ok=True)
    targets.write_text("\n".join(urls) + "\n", encoding="utf-8")
    rate = str(int(scope.get("rate_limit", 5)))
    headers_file = str((scope.get("auth") or {}).get("headers_file", "")).strip()
    headers = _header_values(scope)
    header_args = [element for header in headers for element in ("-H", header)]
    if not _missing("pd-httpx", statuses):
        output = raw / "httpx.jsonl"
        command = command_for("pd-httpx") + ["-l", str(targets), "-json", "-sc", "-title", "-td", "-server", "-cl", "-fr", "-rl", rate, "-o", str(output)] + header_args
        _append_status(statuses, "pd-httpx", run_command(command, logs / "pd-httpx.json"), output)
    if not _missing("katana", statuses):
        output = raw / "katana.jsonl"
        budget = scope.get("crawl_budget") if isinstance(scope.get("crawl_budget"), dict) else {}
        command = command_for("katana") + ["-list", str(targets), "-jsonl", "-jc", "-d", str(int(budget.get("max_depth", 3))), "-mdp", str(int(budget.get("max_pages", 300))), "-rl", rate, "-o", str(output)] + _katana_scope_args(scope) + header_args
        _append_status(statuses, "katana", run_command(command, logs / "katana.json"), output)
        crawled = _read_jsonl_urls(output, scope)
        if crawled:
            (raw / "in-scope-urls.txt").write_text("\n".join(crawled) + "\n", encoding="utf-8")
            urls = crawled
    if not _missing("nuclei", statuses):
        input_file = raw / "in-scope-urls.txt"
        if not input_file.exists():
            input_file = targets
        output = raw / "nuclei.jsonl"
        command = command_for("nuclei") + ["-l", str(input_file), "-jsonl", "-rl", rate, "-t", str(WORKBENCH_ROOT / "rules" / "nuclei"), "-o", str(output)] + header_args
        _append_status(statuses, "nuclei", run_command(command, logs / "nuclei.json", acceptable={0, 1}), output)
    _zap_passive(urls[: int((scope.get("crawl_budget") or {}).get("max_pages", 300))], run_dir, settings, statuses, "zap-passive", int(scope.get("rate_limit", 5)))


def _api(scope: dict[str, Any], run_dir: Path, statuses: list[dict[str, Any]], settings: dict[str, Any]) -> None:
    schemas = allowed_urls(scope, "openapi")
    if not schemas:
        statuses.append({"tool": "api", "status": "skipped", "reason": "no in-scope OpenAPI URLs"})
        return
    raw, logs = run_dir / "raw", run_dir / "logs"
    if not _missing("schemathesis", statuses):
        for index, schema in enumerate(schemas):
            output = raw / f"schemathesis-{index}.txt"
            junit = raw / f"schemathesis-{index}.xml"
            ndjson = raw / f"schemathesis-{index}.ndjson"
            rate = f"{max(1, int(scope.get('rate_limit', 5)))}/s"
            headers = _header_values(scope)
            command = command_for("schemathesis") + ["run", schema, "--no-color", "--workers", "1", "--rate-limit", rate, "--report", "junit,ndjson", "--report-junit-path", str(junit), "--report-ndjson-path", str(ndjson)] + [element for header in headers for element in ("-H", header)]
            record = run_command(command, logs / f"schemathesis-{index}.json", acceptable={0, 1})
            output.write_text(record.get("stdout", "") + "\n" + record.get("stderr", ""), encoding="utf-8")
            _append_status(statuses, f"schemathesis-{index}", record, output)
    _zap_passive(schemas, run_dir, settings, statuses, "zap-api-passive", int(scope.get("rate_limit", 5)), openapi_schemas=schemas)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("scope", type=Path)
    parser.add_argument("--profile", choices=["source", "web-baseline", "api"], required=True)
    parser.add_argument("--hexstrike-status", default="optional-not-requested")
    args = parser.parse_args()
    scope = load_yaml(args.scope)
    settings = load_yaml(WORKBENCH_ROOT / "config" / "defaults.yaml")
    run_dir = RUNS_DIR / f"{utc_stamp()}-{str(scope.get('name', 'project')).lower()}-{args.profile}"
    for directory in (run_dir / "raw", run_dir / "sarif", run_dir / "logs", run_dir / "evidence"):
        directory.mkdir(parents=True, exist_ok=True)
    shutil.copy2(args.scope, run_dir / "scope.yaml")
    statuses: list[dict[str, Any]] = []
    if args.profile == "source":
        _source(scope, run_dir, statuses)
    elif args.profile == "web-baseline":
        _web(scope, run_dir, statuses, settings)
    else:
        _api(scope, run_dir, statuses, settings)
    manifest = {"schema_version": 1, "run_id": run_dir.name, "profile": args.profile, "scope": str(args.scope), "local_tool_status": statuses, "hexstrike_status": args.hexstrike_status}
    write_json(run_dir / "run-manifest.json", manifest)
    print(json.dumps(manifest, ensure_ascii=False, indent=2))
    return 0 if not any(item.get("status") == "failed" for item in statuses) else 1


if __name__ == "__main__":
    sys.exit(main())
