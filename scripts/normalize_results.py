"""Normalize local tool output into schema-v2, redacted candidate evidence."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from common import write_json
from redaction import redact_text, redact_value
from triage import load_triage


MAX_JSONL_RECORDS_PER_FILE = 10_000
NORMALIZED_SARIF_NAME = "normalized.sarif"
EVIDENCE_INDEX_NAME = "findings.json"
CWE_BY_RULE_FRAGMENT = {
    "sqli": "CWE-89", "sql": "CWE-89", "xss": "CWE-79", "ssrf": "CWE-918",
    "path": "CWE-22", "traversal": "CWE-22", "deserialize": "CWE-502",
    "template": "CWE-1336", "upload": "CWE-434", "redirect": "CWE-601",
    "jwt": "CWE-347", "auth": "CWE-287", "idor": "CWE-639", "cors": "CWE-942",
}


def _normalized_severity(value: object) -> str:
    lowered = str(value).lower()
    if any(token in lowered for token in ("critical", "error", "high")):
        return "high"
    if any(token in lowered for token in ("warning", "medium", "moderate")):
        return "medium"
    if "low" in lowered:
        return "low"
    return "info"


def _confidence(rule: str, message: str) -> str:
    lowered = f"{rule} {message}".lower()
    if "review" in lowered or "idor" in lowered or "authorization" in lowered:
        return "review"
    if "taint" in lowered or "unsafe" in lowered or "disabled" in lowered:
        return "high"
    return "medium"


def _cwe(rule: str) -> str | None:
    lowered = rule.lower()
    return next((value for key, value in CWE_BY_RULE_FRAGMENT.items() if key in lowered), None)


def _fingerprint(tool: str, rule: str, endpoint: str, method: str, parameter: str) -> str:
    value = "|".join((tool, rule, endpoint, method, parameter))
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:32]


def _origin(endpoint: str) -> str:
    parsed = urlparse(endpoint)
    return parsed.netloc or "local-source" if endpoint else "unknown"


def _finding(tool: str, rule: str, severity: object, endpoint: object, message: object, evidence: Path, *, method: object = "", parameter: object = "", status: str = "candidate", cwe: str | None = None) -> dict[str, Any]:
    safe_endpoint = redact_text(endpoint)
    safe_message = redact_text(message)
    safe_method = redact_text(method)
    safe_parameter = redact_text(parameter)
    fingerprint = _fingerprint(str(tool), str(rule), safe_endpoint, safe_method, safe_parameter)
    return {
        "fingerprint": fingerprint,
        "source": {"tool": str(tool), "rule": str(rule), "version": None},
        "cwe": cwe or _cwe(str(rule)),
        "tool_severity": str(severity),
        "severity": _normalized_severity(severity),
        "confidence": _confidence(str(rule), safe_message),
        "status": status if status in {"candidate", "needs-review", "reproduced", "excluded"} else "candidate",
        "asset": {"origin": _origin(safe_endpoint), "endpoint": safe_endpoint, "method": safe_method},
        "parameter": safe_parameter,
        "message": safe_message,
        "evidence": {"reference": str(evidence), "redacted": True},
        "scope_snapshot_digest": "",
        "preconditions": [],
        "human_review": {"human_reviewed": False, "scope_confirmed": False},
    }


def _add(index: dict[str, dict[str, Any]], item: dict[str, Any]) -> None:
    index.setdefault(str(item["fingerprint"]), item)


def _sarif(path: Path, index: dict[str, dict[str, Any]]) -> None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError:
        return
    for run in payload.get("runs", []) if isinstance(payload, dict) else []:
        driver = run.get("tool", {}).get("driver", {}) if isinstance(run, dict) else {}
        tool = driver.get("name", path.stem) if isinstance(driver, dict) else path.stem
        for result in run.get("results", []) if isinstance(run, dict) else []:
            if not isinstance(result, dict):
                continue
            locations = result.get("locations", [])
            physical = locations[0].get("physicalLocation", {}) if locations and isinstance(locations[0], dict) else {}
            artifact = physical.get("artifactLocation", {}) if isinstance(physical, dict) else {}
            endpoint = artifact.get("uri", "") if isinstance(artifact, dict) else ""
            message = result.get("message", {}).get("text", "") if isinstance(result.get("message"), dict) else ""
            _add(index, _finding(str(tool), str(result.get("ruleId", "unknown")), result.get("level", "warning"), endpoint, message, path))


def _jsonl(path: Path, index: dict[str, dict[str, Any]]) -> None:
    for number, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines()):
        if number >= MAX_JSONL_RECORDS_PER_FILE:
            break
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(item, dict) or "template-id" not in item:
            continue
        info = item.get("info", {}) if isinstance(item.get("info"), dict) else {}
        _add(index, _finding(str(item.get("template-id")), str(item.get("template-id", item.get("matcher-name", "candidate"))), info.get("severity", "info"), item.get("matched-at", item.get("url", "")), info.get("name", ""), path, parameter=item.get("matcher-name", "")))


def _dalfox(path: Path, index: dict[str, dict[str, Any]]) -> None:
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict) and item.get("url"):
            _add(index, _finding("dalfox", str(item.get("type", "dalfox.xss-candidate")), "warning", item.get("url"), item.get("message", item.get("evidence", "Dalfox candidate")), path, parameter=item.get("param", "")))


def _ffuf(path: Path, index: dict[str, dict[str, Any]]) -> None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError:
        return
    for item in payload.get("results", []) if isinstance(payload, dict) else []:
        if isinstance(item, dict) and item.get("url"):
            _add(index, _finding("ffuf", "ffuf.content-discovery", "info", item["url"], f"Discovered content (HTTP {item.get('status', 'unknown')})", path))


def _zap(path: Path, index: dict[str, dict[str, Any]]) -> None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError:
        return
    alerts = payload.get("alerts", []) if isinstance(payload, dict) else []
    for alert in alerts if isinstance(alerts, list) else []:
        if not isinstance(alert, dict):
            continue
        _add(index, _finding("zap", str(alert.get("alert", alert.get("pluginId", "zap-alert"))), alert.get("riskdesc", alert.get("risk", "info")), alert.get("url", ""), alert.get("desc", alert.get("name", "ZAP alert")), path, parameter=alert.get("param", "")))


def _openapi_lint(path: Path, index: dict[str, dict[str, Any]]) -> None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError:
        return
    for item in payload.get("findings", []) if isinstance(payload, dict) else []:
        if isinstance(item, dict):
            _add(index, _finding("openapi-lint", str(item.get("rule", "openapi.candidate")), item.get("severity", "warning"), item.get("location", ""), item.get("message", "OpenAPI review candidate"), path, status="candidate"))


def _assets(path: Path) -> list[dict[str, Any]]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError:
        return []
    values = payload.get("candidates", []) if isinstance(payload, dict) else []
    return redact_value(values) if isinstance(values, list) else []


def _apply_triage(item: dict[str, Any], decisions: dict[str, dict[str, Any]]) -> dict[str, Any]:
    decision = decisions.get(str(item["fingerprint"]))
    if not decision:
        return item
    merged = dict(item)
    merged["status"] = decision["status"]
    for key in ("cwe", "preconditions"):
        if key in decision:
            merged[key] = redact_value(decision[key])
    merged["human_review"] = {
        "human_reviewed": bool(decision.get("human_reviewed", False)),
        "scope_confirmed": bool(decision.get("scope_confirmed", False)),
        "reviewer": redact_text(decision.get("reviewer", "")),
        "reviewed_at": redact_text(decision.get("reviewed_at", "")),
        "impact": redact_text(decision.get("impact", "")),
        "cvss_v4": redact_text(decision.get("cvss_v4", "")),
        "recommendation": redact_text(decision.get("recommendation", "")),
        "reproduction_steps": redact_value(decision.get("reproduction_steps", [])),
    }
    return merged


def _normalized_sarif(findings: list[dict[str, Any]]) -> dict[str, Any]:
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for item in findings:
        rule = str(item["source"]["rule"])
        rules.setdefault(rule, {"id": rule, "shortDescription": {"text": rule}})
        results.append({
            "ruleId": rule,
            "level": "error" if item["severity"] == "high" else "warning" if item["severity"] == "medium" else "note",
            "message": {"text": item["message"]},
            "partialFingerprints": {"webVulnMiningFingerprint": item["fingerprint"]},
            "properties": {"status": item["status"], "confidence": item["confidence"], "cwe": item["cwe"], "evidence_redacted": True},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": item["asset"]["endpoint"]}}}] if item["asset"]["endpoint"] else [],
        })
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0", "runs": [{"tool": {"driver": {"name": "web-vuln-mining-normalizer", "rules": list(rules.values())}}, "results": results}]}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("run_dir", type=Path)
    args = parser.parse_args()
    run = args.run_dir
    manifest = json.loads((run / "run-manifest.json").read_text(encoding="utf-8"))
    index: dict[str, dict[str, Any]] = {}
    for path in (run / "sarif").glob("*.sarif"):
        if path.name != NORMALIZED_SARIF_NAME:
            _sarif(path, index)
    for path in (run / "raw").glob("*.jsonl"):
        _jsonl(path, index)
        if path.name.startswith("dalfox"):
            _dalfox(path, index)
    for path in (run / "raw").glob("ffuf-*.json"):
        _ffuf(path, index)
    for path in (run / "raw").glob("zap*.json"):
        _zap(path, index)
    for path in (run / "raw").glob("openapi-lint.json"):
        _openapi_lint(path, index)
    scope_digest = hashlib.sha256((run / "scope.yaml").read_bytes()).hexdigest() if (run / "scope.yaml").is_file() else ""
    decisions = load_triage(run)
    findings = []
    for item in index.values():
        item["scope_snapshot_digest"] = scope_digest
        findings.append(_apply_triage(item, decisions))
    findings.sort(key=lambda item: item["fingerprint"])
    assets = [candidate for path in (run / "raw").glob("asset-candidates.json") for candidate in _assets(path)]
    counts = {status: sum(item["status"] == status for item in findings) for status in ("candidate", "needs-review", "reproduced", "excluded")}
    counts["asset_candidate"] = len(assets)
    compatibility = "v1-run-compatible" if int(manifest.get("schema_version", 1)) < 2 else None
    summary = {
        "schema_version": 2,
        "run_id": manifest["run_id"], "profile": manifest["profile"],
        "local_tool_status": redact_value(manifest.get("local_tool_status", [])),
        "hexstrike_status": redact_text(manifest.get("hexstrike_status", "optional-not-requested")),
        "findings": findings, "asset_candidates": assets, "counts": counts,
        "compatibility": compatibility,
    }
    write_json(run / "summary.json", summary)
    write_json(run / "evidence" / EVIDENCE_INDEX_NAME, {"schema_version": 2, "run_id": manifest["run_id"], "findings": findings, "asset_candidates": assets})
    write_json(run / "sarif" / NORMALIZED_SARIF_NAME, _normalized_sarif(findings))
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
