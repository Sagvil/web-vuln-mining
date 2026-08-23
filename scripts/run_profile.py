"""Run a Web-only source, baseline, or API profile from a TARGET.yaml manifest."""
from __future__ import annotations

import argparse
import json
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

import requests

from common import DEFAULT_TIMEOUT_SECONDS, RUNS_DIR, WORKBENCH_ROOT, allowed_urls, command_for, is_allowed_url, load_yaml, run_command, tool_disabled_reason, utc_stamp, write_json
from governance import evaluate as evaluate_governance
from governance import write_artifacts as write_governance_artifacts
from openapi_lint import lint_openapi_file
from preflight import inspect as preflight_inspect
from scope_validation import validate_scope

# Configuration zone: execution limits and output locations for all profiles.
DEFAULT_PROFILE_TIMEOUT_SECONDS = DEFAULT_TIMEOUT_SECONDS
MAX_DISCOVERED_URLS = 5000
MAX_VERIFY_TARGETS = 20  # Maximum explicit candidate URLs processed by one verification run.
DALFOX_WORKERS = 1  # Serial XSS verification to avoid request bursts.
DALFOX_MAX_CONCURRENT_TARGETS = 1  # Process one candidate target at a time.
DALFOX_SCAN_TIMEOUT_SECONDS = 300  # Maximum payload-injection time per target.
DALFOX_SKIP_MINING = True  # Use only explicitly supplied parameters; do not mine extra names.
SQLMAP_TECHNIQUES = "BE"  # Boolean- and error-based checks; excludes time delays and stacked queries.
SQLMAP_TIMEOUT_SECONDS = 15  # Per-request timeout for bounded SQL verification.
SQLMAP_RETRIES = 0  # Do not amplify transient failures with retries.
# ACTIVE_DNS_NMAP_TIMEOUT_SECONDS: upper bound for one DNS-only Nmap invocation.
ACTIVE_DNS_NMAP_TIMEOUT_SECONDS = 900
# ACTIVE_DNS_*: hard execution caps mirroring scope_validation.py. Scope files
# select values within these limits; candidates never become Web targets here.
ACTIVE_DNS_MAX_WORDS = 10_000
ACTIVE_DNS_MAX_THREADS = 20
ACTIVE_DNS_MAX_CANDIDATES = 5_000

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
    statuses.append({"tool": tool, "status": "skipped", "reason": tool_disabled_reason(tool) or "tool not installed"})
    return True


def _source(scope: dict[str, Any], run_dir: Path, statuses: list[dict[str, Any]]) -> None:
    root = Path(str(scope.get("source_root", ""))).expanduser()
    if not root.is_dir():
        statuses.append({"tool": "source", "status": "skipped", "reason": f"source_root not found: {root}"})
        return
    raw, sarif, logs = run_dir / "raw", run_dir / "sarif", run_dir / "logs"
    _cyclonedx_sbom(root, raw / "sbom.cdx.json", statuses)
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


def _cyclonedx_sbom(source_root: Path, output: Path, statuses: list[dict[str, Any]]) -> None:
    """Emit a small CycloneDX JSON inventory without adding a dependency scanner."""
    components: list[dict[str, Any]] = []
    for name in ("requirements.txt", "requirements-dev.txt"):
        candidate = source_root / name
        if not candidate.is_file():
            continue
        for line in candidate.read_text(encoding="utf-8", errors="replace").splitlines():
            value = line.split("#", 1)[0].strip()
            if not value or value.startswith(("-", ".")):
                continue
            package, separator, version = value.partition("==")
            components.append({"type": "library", "name": package.strip(), "version": version.strip() if separator else "unspecified"})
    write_json(output, {"bomFormat": "CycloneDX", "specVersion": "1.5", "serialNumber": f"urn:uuid:{run_dir_token(source_root)}", "version": 1, "components": components})
    statuses.append({"tool": "cyclonedx-sbom", "status": "completed", "output": str(output), "components": len(components)})


def run_dir_token(source_root: Path) -> str:
    """Produce a non-sensitive deterministic SBOM identifier from a local path."""
    import hashlib
    return hashlib.sha256(str(source_root).encode("utf-8")).hexdigest()[:32]


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


def _zap_params(api_key: str, **values: Any) -> dict[str, Any]:
    """Attach the transient local API key to every ZAP API request."""
    return {"apikey": api_key, **values}


def _wait_zap(base: str, timeout: int, api_key: str) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if requests.get(f"{base}/JSON/core/view/version/", params=_zap_params(api_key), timeout=3).ok:
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
    # YAML can select a local port, but never a network-accessible bind host.
    host = "127.0.0.1"
    try:
        port = int(zap.get("port", 8090))
    except (TypeError, ValueError):
        statuses.append({"tool": label, "status": "failed", "reason": "invalid local ZAP port"})
        return
    if not 1024 <= port <= 65535:
        statuses.append({"tool": label, "status": "failed", "reason": "ZAP port must be a local user port"})
        return
    base = f"http://{host}:{port}"
    zap_command = command_for("zap")
    api_key = secrets.token_urlsafe(32)
    # ZAP's temp directory is per run.  Neither key nor launch command reaches
    # a conventional run log; only the de-sensitized outcome below is stored.
    with tempfile.TemporaryDirectory(prefix="web-vuln-mining-zap-") as temporary:
        process: subprocess.Popen[str] | None = None
        try:
            process = subprocess.Popen(
                zap_command + ["-daemon", "-host", host, "-port", str(port), "-dir", temporary, "-config", "api.disablekey=false", "-config", f"api.key={api_key}"],
                cwd=Path(zap_command[0]).parent,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            if not _wait_zap(base, int(zap.get("startup_timeout_seconds", 90)), api_key):
                statuses.append({"tool": label, "status": "failed", "reason": "ZAP daemon did not become ready"})
                return
            requests.get(f"{base}/JSON/core/action/newSession/", params=_zap_params(api_key, overwrite="true"), timeout=10)
            # OpenAPI imports are deliberately restricted to already scope-validated URLs.
            for schema in openapi_schemas or []:
                requests.get(f"{base}/JSON/openapi/action/importUrl/", params=_zap_params(api_key, url=schema), timeout=30)
            delay = 1 / max(1, rate_limit)
            for index, url in enumerate(urls):
                requests.get(f"{base}/JSON/core/action/accessUrl/", params=_zap_params(api_key, url=url), timeout=30)
                if index + 1 < len(urls):
                    time.sleep(delay)
            alerts = requests.get(f"{base}/JSON/core/view/alerts/", params=_zap_params(api_key, start=0, count=9999), timeout=30).json()
            output = run_dir / "raw" / f"{label}.json"
            write_json(output, alerts)
            statuses.append({"tool": label, "status": "completed", "output": str(output), "alerts": len(alerts.get("alerts", [])), "message": "ZAP passive completed"})
        except (OSError, requests.RequestException, ValueError):
            statuses.append({"tool": label, "status": "failed", "reason": "ZAP passive failed"})
        finally:
            if process is not None and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=10)


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
    lint_findings: list[dict[str, Any]] = []
    # Fetch only the schema URLs the Scope manifest has already accepted.  The
    # offline linter receives saved bytes, and never resolves remote $ref values
    # or contacts ``servers`` entries in the document.
    for index, schema in enumerate(schemas):
        saved = raw / f"openapi-{index}.json"
        try:
            response = requests.get(schema, timeout=30, headers={"Accept": "application/json, application/yaml, text/yaml"})
            response.raise_for_status()
            saved.write_bytes(response.content)
            lint_findings.extend(lint_openapi_file(saved))
        except (OSError, ValueError, requests.RequestException):
            statuses.append({"tool": "openapi-lint", "status": "failed", "reason": "OpenAPI schema download or parse failed"})
    lint_output = raw / "openapi-lint.json"
    write_json(lint_output, {"schema_version": 1, "followed_external_refs": False, "findings": lint_findings})
    if not any(item.get("tool") == "openapi-lint" and item.get("status") == "failed" for item in statuses):
        statuses.append({"tool": "openapi-lint", "status": "completed", "output": str(lint_output), "findings": len(lint_findings)})
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


def _candidate_urls(candidate_file: Path, scope: dict[str, Any]) -> list[str]:
    """Read explicit candidate URLs and retain only the target manifest's scope."""
    urls: list[str] = []
    for line in candidate_file.read_text(encoding="utf-8", errors="replace").splitlines():
        url = line.strip().lstrip("\ufeff")
        if url and is_allowed_url(url, scope) and url not in urls:
            urls.append(url)
        if len(urls) >= MAX_VERIFY_TARGETS:
            break
    return urls


def _verify_xss(scope: dict[str, Any], run_dir: Path, statuses: list[dict[str, Any]], candidate_file: Path | None) -> None:
    if not candidate_file or not candidate_file.is_file():
        statuses.append({"tool": "dalfox", "status": "failed", "reason": "verify-xss requires --input candidate URL file"})
        return
    urls = _candidate_urls(candidate_file, scope)
    if not urls:
        statuses.append({"tool": "dalfox", "status": "failed", "reason": "candidate file contains no in-scope URLs"})
        return
    if _missing("dalfox", statuses):
        return
    raw, logs = run_dir / "raw", run_dir / "logs"
    targets = raw / "dalfox-targets.txt"
    targets.write_text("\n".join(urls) + "\n", encoding="utf-8")
    output = raw / "dalfox.jsonl"
    headers = _header_values(scope)
    rate = str(max(1, int(scope.get("rate_limit", 5))))
    command = command_for("dalfox") + [
        "scan", str(targets),
        "--format", "jsonl",
        "--output", str(output),
        "--silence",
        "--workers", str(DALFOX_WORKERS),
        "--max-concurrent-targets", str(DALFOX_MAX_CONCURRENT_TARGETS),
        "--rate-limit", rate,
        "--scan-timeout", str(DALFOX_SCAN_TIMEOUT_SECONDS),
    ]
    if DALFOX_SKIP_MINING:
        command.append("--skip-mining")
    command += [element for header in headers for element in ("-H", header)]
    _append_status(statuses, "dalfox", run_command(command, logs / "dalfox.json", acceptable={0, 1}), output)


def _verify_sqli(scope: dict[str, Any], run_dir: Path, statuses: list[dict[str, Any]], candidate_file: Path | None) -> None:
    if not candidate_file or not candidate_file.is_file():
        statuses.append({"tool": "sqlmap", "status": "failed", "reason": "verify-sqli requires --input candidate URL file"})
        return
    urls = _candidate_urls(candidate_file, scope)
    if not urls:
        statuses.append({"tool": "sqlmap", "status": "failed", "reason": "candidate file contains no in-scope URLs"})
        return
    if _missing("sqlmap", statuses):
        return
    raw, logs = run_dir / "raw", run_dir / "logs"
    index: list[dict[str, Any]] = []
    delay = f"{max(0.2, 1 / max(1, int(scope.get('rate_limit', 5)))):.2f}"
    for position, url in enumerate(urls):
        output_dir = raw / "sqlmap" / str(position)
        command = command_for("sqlmap") + [
            "-u", url,
            "--batch",
            "--level", "1",
            "--risk", "1",
            "--threads", "1",
            "--delay", delay,
            "--technique", SQLMAP_TECHNIQUES,
            "--timeout", str(SQLMAP_TIMEOUT_SECONDS),
            "--retries", str(SQLMAP_RETRIES),
            "--output-dir", str(output_dir),
        ]
        record = run_command(command, logs / f"sqlmap-{position}.json", acceptable={0, 1})
        _append_status(statuses, f"sqlmap-{position}", record, output_dir)
        index.append({"url": url, "output_dir": str(output_dir), "command": command, "status": record["status"]})
    write_json(raw / "sqlmap-index.json", {"candidates": index})


def _content_discovery(scope: dict[str, Any], run_dir: Path, statuses: list[dict[str, Any]], wordlist: Path | None, max_requests: int) -> None:
    if not wordlist or not wordlist.is_file():
        statuses.append({"tool": "ffuf", "status": "failed", "reason": "content-discovery requires --wordlist"})
        return
    if _missing("ffuf", statuses):
        return
    raw, logs = run_dir / "raw", run_dir / "logs"
    bounded = raw / "ffuf-wordlist.txt"
    values = [line for line in wordlist.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip()][:max_requests]
    if not values:
        statuses.append({"tool": "ffuf", "status": "failed", "reason": "wordlist is empty"})
        return
    bounded.write_text("\n".join(values) + "\n", encoding="utf-8")
    discovery = scope.get("content_discovery") if isinstance(scope.get("content_discovery"), dict) else {}
    statuses_filter = ",".join(str(item) for item in discovery.get("match_statuses", [200, 204, 301, 302, 307, 401, 403]))
    for position, base_url in enumerate(allowed_urls(scope)):
        target = base_url.rstrip("/") + "/FUZZ"
        output = raw / f"ffuf-{position}.json"
        command = command_for("ffuf") + ["-w", str(bounded), "-u", target, "-rate", str(int(scope.get("rate_limit", 5))), "-t", "1", "-maxtime", "300", "-mc", statuses_filter, "-of", "json", "-o", str(output), "-noninteractive"]
        _append_status(statuses, f"ffuf-{position}", run_command(command, logs / f"ffuf-{position}.json", acceptable={0, 1}), output)



def _dns_candidates_from_xml(path: Path, root_domain: str) -> list[dict[str, Any]]:
    """Extract DNS-brute hostnames from Nmap XML without treating them as Web targets."""
    if not path.is_file():
        return []
    try:
        document = ET.parse(path).getroot()
    except (ET.ParseError, OSError):
        return []
    candidates: list[dict[str, Any]] = []
    seen: set[str] = set()
    expected = root_domain.lower().rstrip('.')
    for host in document.findall('.//host'):
        addresses = sorted({str(item.get('addr', '')).strip() for item in host.findall('address') if item.get('addr')})
        for hostname in host.findall('.//hostname'):
            name = str(hostname.get('name', '')).strip().lower().rstrip('.')
            if not name or name in seen or not (name == expected or name.endswith('.' + expected)):
                continue
            seen.add(name)
            candidates.append({'hostname': name, 'addresses': addresses, 'root': expected, 'source': 'nmap-dns-brute', 'status': 'candidate', 'evidence': str(path)})
    return candidates


def _active_dns_discovery(scope: dict[str, Any], run_dir: Path, statuses: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Run bounded Nmap dns-brute and persist candidates without expanding Web scope."""
    config = scope.get('active_dns_discovery') if isinstance(scope.get('active_dns_discovery'), dict) else {}
    raw, logs = run_dir / 'raw', run_dir / 'logs'
    roots = [str(item).strip().lower().rstrip('.') for item in config.get('roots', []) if str(item).strip()]
    configured_wordlist = Path(str(config.get('wordlist', '')).strip()).expanduser()
    wordlist = configured_wordlist if configured_wordlist.is_absolute() else WORKBENCH_ROOT / configured_wordlist
    max_words = max(1, min(int(config.get('max_words', ACTIVE_DNS_MAX_WORDS)), ACTIVE_DNS_MAX_WORDS))
    threads = max(1, min(int(config.get('threads', ACTIVE_DNS_MAX_THREADS)), ACTIVE_DNS_MAX_THREADS))
    max_candidates = max(1, min(int(config.get('max_candidates', ACTIVE_DNS_MAX_CANDIDATES)), ACTIVE_DNS_MAX_CANDIDATES))
    output = raw / 'asset-candidates.json'
    nmap = shutil.which('nmap')
    if not nmap:
        reason = 'nmap system dependency is not installed'
        statuses.append({'tool': 'nmap-dns-brute', 'status': 'failed', 'reason': reason})
        write_json(logs / 'nmap-preflight.json', {'command': [], 'returncode': None, 'status': 'failed', 'reason': reason})
        write_json(output, {'schema_version': 1, 'profile': 'active-dns-discovery', 'candidates': []})
        return []
    if not wordlist.is_file():
        reason = f'DNS wordlist not found: {wordlist}'
        statuses.append({'tool': 'nmap-dns-brute', 'status': 'failed', 'reason': reason})
        write_json(logs / 'nmap-preflight.json', {'command': [], 'returncode': None, 'status': 'failed', 'reason': reason})
        write_json(output, {'schema_version': 1, 'profile': 'active-dns-discovery', 'candidates': []})
        return []
    labels: list[str] = []
    for line in wordlist.read_text(encoding='utf-8', errors='replace').splitlines():
        label = line.split('#', 1)[0].strip().lower()
        if not label or label in labels or not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,62}', label):
            continue
        labels.append(label)
        if len(labels) >= max_words:
            break
    if not labels:
        reason = 'DNS wordlist has no usable labels'
        statuses.append({'tool': 'nmap-dns-brute', 'status': 'failed', 'reason': reason})
        write_json(logs / 'nmap-preflight.json', {'command': [], 'returncode': None, 'status': 'failed', 'reason': reason})
        write_json(output, {'schema_version': 1, 'profile': 'active-dns-discovery', 'candidates': []})
        return []
    candidates: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, root_domain in enumerate(roots):
        safe_name = re.sub(r'[^a-z0-9.-]+', '-', root_domain).strip('-') or str(index)
        bounded = raw / f'dns-wordlist-{safe_name}.txt'
        bounded.write_text('\n'.join(labels) + '\n', encoding='utf-8')
        xml_output = raw / f'nmap-{safe_name}.xml'
        command = [nmap, '-sn', '-n', '-Pn', '--script', 'dns-brute', '--script-args', f'dns-brute.domain={root_domain},dns-brute.hostlist={bounded},dns-brute.threads={threads}', '-oX', str(xml_output), root_domain]
        record = run_command(command, logs / f'nmap-{safe_name}.json', timeout=ACTIVE_DNS_NMAP_TIMEOUT_SECONDS, acceptable={0})
        _append_status(statuses, f'nmap-dns-brute-{safe_name}', record, xml_output)
        for candidate in _dns_candidates_from_xml(xml_output, root_domain):
            hostname = str(candidate['hostname'])
            if hostname not in seen and len(candidates) < max_candidates:
                seen.add(hostname)
                candidates.append(candidate)
    payload = {'schema_version': 1, 'profile': 'active-dns-discovery', 'candidate_only': True, 'candidates': candidates}
    write_json(output, payload)
    return candidates

def _load_template(profile_name: str, run_dir: Path) -> dict[str, Any] | None:
    """Load the verification playbook referenced by a profile's `template` field.

    Returns template metadata or None when the profile has no template.
    The playbook is copied into the run directory as run_template.md so every
    run records which playbook governed its verification steps.
    """
    tdir = WORKBENCH_ROOT / "templates"
    prof = load_yaml(WORKBENCH_ROOT / "profiles" / f"{profile_name}.yaml")
    name = prof.get("template")
    if not name:
        return None
    src = tdir / f"{name}.md"
    if not src.exists():
        print(f"template {name!r} referenced by {profile_name} not found", file=sys.stderr)
        return None
    shutil.copy2(src, run_dir / "run_template.md")
    return {"template": name, "path": str(src)}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("scope", type=Path)
    parser.add_argument("--profile", choices=["source", "web-baseline", "api", "verify-xss", "verify-sqli", "verify-jwt", "verify-nosql", "verify-race", "verify-ssrf-ssti", "verify-llm-injection", "content-discovery", "active-dns-discovery"], required=True)
    parser.add_argument("--hexstrike-status", default="optional-not-requested")
    parser.add_argument("--validate-only", action="store_true", help="validate TARGET.yaml without starting a profile")
    parser.add_argument("--input", type=Path, help="explicit in-scope candidate URL file for verify-* profiles")
    parser.add_argument("--wordlist", type=Path, help="wordlist used only by content-discovery; DNS uses active_dns_discovery.wordlist")
    parser.add_argument("--max-requests", type=int, default=None, help="maximum wordlist entries consumed by content-discovery; overrides TARGET.yaml")
    parser.add_argument("--governance-mode", choices=["off", "shadow", "enforce"], default="shadow", help="record deterministic policy decisions; enforce blocks non-permit outcomes before profile tools run")
    parser.add_argument("--governance-contract", type=Path, help="JSON Action Contract required by --governance-mode enforce for networked profiles")
    args = parser.parse_args()
    scope = load_yaml(args.scope)
    # Relative local paths are always relative to the repository, not the terminal's current directory.
    for key in ("source_root",):
        value = str(scope.get(key, "")).strip()
        if value and not Path(value).expanduser().is_absolute():
            scope[key] = str(WORKBENCH_ROOT / value)
    auth = scope.get("auth") if isinstance(scope.get("auth"), dict) else {}
    headers_file = str(auth.get("headers_file", "")).strip()
    if headers_file and not Path(headers_file).expanduser().is_absolute():
        auth["headers_file"] = str(WORKBENCH_ROOT / headers_file)
        scope["auth"] = auth
    errors = validate_scope(scope, args.profile)
    if errors:
        for item in errors:
            print(f"{item.field}: {item.message}", file=sys.stderr)
        return 2
    if args.validate_only:
        print(json.dumps({"scope": str(args.scope), "profile": args.profile, "status": "valid"}, ensure_ascii=False))
        return 0
    # A normal profile must have a verifiable local toolchain.  This check is
    # deliberately after --validate-only and deliberately does not repair.
    preflight = preflight_inspect([args.profile])
    if not preflight.get("ok"):
        print(json.dumps({"status": "preflight-failed", "errors": preflight.get("errors", [])}, ensure_ascii=False), file=sys.stderr)
        return 3
    if args.profile in {"verify-xss", "verify-sqli"} and not args.input:
        print(f"{args.profile} requires --input", file=sys.stderr)
        return 2
    if args.profile == "content-discovery" and not args.wordlist:
        print("content-discovery requires --wordlist", file=sys.stderr)
        return 2
    settings = load_yaml(WORKBENCH_ROOT / "config" / "defaults.yaml")
    run_dir = RUNS_DIR / f"{utc_stamp()}-{str(scope.get('name', 'project')).lower()}-{args.profile}"
    for directory in (run_dir / "raw", run_dir / "sarif", run_dir / "logs", run_dir / "evidence"):
        directory.mkdir(parents=True, exist_ok=True)
    shutil.copy2(args.scope, run_dir / "scope.yaml")
    contract_path = args.governance_contract.expanduser() if args.governance_contract else None
    if contract_path and not contract_path.is_absolute():
        contract_path = WORKBENCH_ROOT / contract_path
    decision, contract = evaluate_governance(args.scope, scope, args.profile, mode=args.governance_mode, contract_path=contract_path, skill_id="web-mining", run_id=run_dir.name)
    write_governance_artifacts(run_dir, decision, contract)
    governance_summary = {
        "mode": decision["mode"],
        "outcome": decision["outcome"],
        "intent_fingerprint": decision["intent_fingerprint"],
        "contract_id": decision["contract_id"],
        "reason": decision["reason"],
        "skill_id": decision["intent"]["skill_id"],
        "run_id": decision["intent"]["run_id"],
        "scope_manifest_sha256": decision["intent"]["scope_manifest_sha256"],
        "target_set_hash": decision["intent"]["target_set_hash"],
        "action_class": decision["intent"]["action_class"],
        "evidence_reference": decision["intent"]["evidence_reference"],
    }
    if args.governance_mode == "enforce" and decision["outcome"] not in {"PERMIT_AND_LOG", "PERMIT_AND_NOTIFY"}:
        manifest = {
            "schema_version": 1,
            "run_id": run_dir.name,
            "profile": args.profile,
            "scope": str(args.scope),
            "local_tool_status": [],
            "hexstrike_status": args.hexstrike_status,
            "governance": governance_summary,
            "status": "blocked-policy",
        }
        write_json(run_dir / "run-manifest.json", manifest)
        write_governance_artifacts(run_dir, decision, contract, execution={
            "status": "blocked-policy",
            "verification_status": "not-run",
            "reason": decision["reason"],
        })
        print(json.dumps(manifest, ensure_ascii=False, indent=2), file=sys.stderr)
        return 4
    template_meta = _load_template(args.profile, run_dir)
    statuses: list[dict[str, Any]] = []
    asset_candidates: list[dict[str, Any]] = []
    if args.profile == "source":
        _source(scope, run_dir, statuses)
    elif args.profile == "web-baseline":
        _web(scope, run_dir, statuses, settings)
    elif args.profile == "api":
        _api(scope, run_dir, statuses, settings)
    elif args.profile == "active-dns-discovery":
        asset_candidates = _active_dns_discovery(scope, run_dir, statuses)
    else:
        candidate_file = args.input.expanduser() if args.input else None
        if candidate_file and not candidate_file.is_absolute():
            candidate_file = WORKBENCH_ROOT / candidate_file
        wordlist = args.wordlist.expanduser() if args.wordlist else None
        if wordlist and not wordlist.is_absolute():
            wordlist = WORKBENCH_ROOT / wordlist
        if args.profile == "verify-xss":
            _verify_xss(scope, run_dir, statuses, candidate_file)
        elif args.profile == "verify-sqli":
            _verify_sqli(scope, run_dir, statuses, candidate_file)
        elif args.profile in {"verify-jwt", "verify-nosql", "verify-race", "verify-ssrf-ssti", "verify-llm-injection"}:
            # Playbook-driven verification: the agent executes the steps in
            # run_template.md against in-scope candidates; evidence lands in
            # run_dir/evidence per templates/evidence-record.md.
            statuses.append({
                "tool": args.profile,
                "status": "playbook-ready",
                "reason": "template-based verification; steps in run_template.md",
                "requires_input": bool(candidate_file),
            })
        else:
            configured_limit = int(((scope.get("content_discovery") or {}).get("max_requests", 300)))
            _content_discovery(scope, run_dir, statuses, wordlist, max(1, min(args.max_requests if args.max_requests is not None else configured_limit, 10_000)))
    manifest = {"schema_version": 1, "run_id": run_dir.name, "profile": args.profile, "scope": str(args.scope), "local_tool_status": statuses, "hexstrike_status": args.hexstrike_status, "asset_candidates": {"count": len(asset_candidates), "path": str(run_dir / "raw" / "asset-candidates.json") if args.profile == "active-dns-discovery" else None}, "governance": governance_summary}
    if template_meta:
        manifest["template_applied"] = template_meta["template"]
    write_json(run_dir / "run-manifest.json", manifest)
    write_governance_artifacts(run_dir, decision, contract, execution={
        "status": "failed" if any(item.get("status") == "failed" for item in statuses) else "completed",
        "verification_status": "unverified",
        "tool_status_count": len(statuses),
    })
    print(json.dumps(manifest, ensure_ascii=False, indent=2))
    return 0 if not any(item.get("status") == "failed" for item in statuses) else 1


if __name__ == "__main__":
    sys.exit(main())
