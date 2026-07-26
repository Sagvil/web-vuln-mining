"""Normalize SARIF, JSONL, and ZAP alerts into a de-duplicated summary."""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from common import write_json

# ============================ Configuration zone ============================
# MAX_JSONL_RECORDS_PER_FILE: cap raw records consumed from one JSONL file.
# NORMALIZED_SARIF_NAME: unified cross-tool SARIF emitted after de-duplication.
# EVIDENCE_INDEX_NAME: machine-readable evidence index stored in evidence/.
MAX_JSONL_RECORDS_PER_FILE = 10000
NORMALIZED_SARIF_NAME = "normalized.sarif"
EVIDENCE_INDEX_NAME = "findings.json"
# ============================================================================

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except AttributeError:
    pass


def _add(findings: dict[str, dict[str, Any]], item: dict[str, Any]) -> None:
    identity = "|".join(str(item.get(key, "")) for key in ("tool", "rule", "location", "method", "parameter"))
    fingerprint = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:20]
    item["fingerprint"] = fingerprint
    findings.setdefault(fingerprint, item)


def _sarif(path: Path, findings: dict[str, dict[str, Any]]) -> None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError:
        return
    for run in payload.get("runs", []):
        tool = run.get("tool", {}).get("driver", {}).get("name", path.stem)
        for result in run.get("results", []):
            location = result.get("locations", [{}])[0].get("physicalLocation", {}).get("artifactLocation", {}).get("uri", "")
            _add(findings, {"tool": tool, "rule": result.get("ruleId", "unknown"), "severity": result.get("level", "warning"), "location": location, "parameter": "", "status": "candidate", "message": result.get("message", {}).get("text", ""), "evidence": str(path)})


def _jsonl(path: Path, findings: dict[str, dict[str, Any]]) -> None:
    for index, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines()):
        if index >= MAX_JSONL_RECORDS_PER_FILE:
            break
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(item, dict):
            continue
        # httpx and Katana JSONL are inventory evidence, not vulnerability findings.
        if "template-id" not in item:
            continue
        _add(findings, {"tool": item.get("template-id", path.stem), "rule": item.get("template-id", item.get("matcher-name", "candidate")), "severity": item.get("info", {}).get("severity", "info"), "location": item.get("matched-at", item.get("url", "")), "parameter": item.get("matcher-name", ""), "status": "candidate", "message": item.get("info", {}).get("name", ""), "evidence": str(path)})


def _schemathesis_ndjson(path: Path, findings: dict[str, dict[str, Any]]) -> None:
    """Convert Schemathesis failed checks into reproducible API-test candidates."""
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            event = json.loads(line).get("ScenarioFinished", {})
        except json.JSONDecodeError:
            continue
        if event.get("status") != "failure":
            continue
        recorder = event.get("recorder", {}) if isinstance(event.get("recorder"), dict) else {}
        interactions = recorder.get("interactions", {}) if isinstance(recorder.get("interactions"), dict) else {}
        for case_id, checks in (recorder.get("checks", {}) or {}).items():
            interaction = interactions.get(case_id, {}) if isinstance(interactions.get(case_id), dict) else {}
            request = interaction.get("request", {}) if isinstance(interaction.get("request"), dict) else {}
            for check in checks if isinstance(checks, list) else []:
                if check.get("status") != "failure":
                    continue
                failure = ((check.get("failure_info") or {}).get("failure") or {})
                _add(findings, {"tool": "schemathesis", "rule": f"schemathesis.{check.get('name', 'failed-check')}", "severity": "warning", "location": str(request.get("uri", "")), "method": str(request.get("method", "")), "parameter": "", "status": "candidate", "message": str(failure.get("message", check.get("name", "Schemathesis failed check"))), "evidence": str(path)})


def _zap_json(path: Path, findings: dict[str, dict[str, Any]]) -> None:
    """Read ZAP JSON reports while keeping every alert as a candidate."""
    try:
        payload = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError:
        return
    for site in payload.get("site", []) if isinstance(payload, dict) else []:
        for alert in site.get("alerts", []) if isinstance(site, dict) else []:
            instances = alert.get("instances", []) if isinstance(alert, dict) else []
            for instance in instances or [{}]:
                uri = instance.get("uri", site.get("@name", "")) if isinstance(instance, dict) else site.get("@name", "")
                parameter = instance.get("param", "") if isinstance(instance, dict) else ""
                _add(findings, {"tool": "zap", "rule": str(alert.get("alert", alert.get("pluginid", "zap-alert"))), "severity": str(alert.get("riskdesc", alert.get("riskcode", "informational"))), "location": str(uri), "parameter": str(parameter), "status": "candidate", "message": str(alert.get("desc", alert.get("name", "ZAP alert"))), "evidence": str(path)})


def _dalfox_jsonl(path: Path, findings: dict[str, dict[str, Any]]) -> None:
    """Keep Dalfox output as candidate evidence; reproduction state is assigned later."""
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(item, dict):
            continue
        location = str(item.get("url") or item.get("target") or item.get("data") or "")
        if location:
            _add(findings, {"tool": "dalfox", "rule": str(item.get("type") or item.get("message_type") or "dalfox.xss-candidate"), "severity": "warning", "location": location, "parameter": str(item.get("param") or item.get("parameter") or ""), "status": "candidate", "message": str(item.get("message") or item.get("evidence") or "Dalfox candidate"), "evidence": str(path)})


def _ffuf_json(path: Path, findings: dict[str, dict[str, Any]]) -> None:
    """Normalize discovered in-scope content paths as inventory candidates."""
    try:
        payload = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError:
        return
    for item in payload.get("results", []) if isinstance(payload, dict) else []:
        if not isinstance(item, dict):
            continue
        location = str(item.get("url") or "")
        if location:
            _add(findings, {"tool": "ffuf", "rule": "ffuf.content-discovery", "severity": "info", "location": location, "parameter": "", "status": "candidate", "message": f"Discovered content (HTTP {item.get('status', 'unknown')})", "evidence": str(path)})


def _sqlmap_index(path: Path, findings: dict[str, dict[str, Any]]) -> None:
    """Promote sqlmap output only when its host log contains a confirmed parameter block."""
    try:
        payload = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError:
        return
    for candidate in payload.get("candidates", []) if isinstance(payload, dict) else []:
        output_dir = Path(str(candidate.get("output_dir", "")))
        for log in output_dir.rglob("log") if output_dir.is_dir() else []:
            text = log.read_text(encoding="utf-8", errors="replace")
            parameter = ""
            for line in text.splitlines():
                if line.strip().lower().startswith("parameter:"):
                    parameter = line.split(":", 1)[1].strip().split()[0]
                    break
            if parameter:
                _add(findings, {"tool": "sqlmap", "rule": "sqlmap.confirmed-sqli", "severity": "error", "location": str(candidate.get("url", "")), "parameter": parameter, "status": "reproduced", "message": "sqlmap recorded a confirmed injectable parameter", "evidence": str(log), "reproduction_command": candidate.get("command", [])})


def _sarif_level(severity: str) -> str:
    value = severity.lower()
    if any(token in value for token in ("error", "high", "critical")):
        return "error"
    if any(token in value for token in ("warning", "medium", "moderate")):
        return "warning"
    return "note"


def _normalized_sarif(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Create a portable SARIF view while preserving tool and evidence metadata."""
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for item in findings:
        rule_id = str(item.get("rule") or f"{item.get('tool', 'unknown')}.finding")
        rules.setdefault(rule_id, {"id": rule_id, "shortDescription": {"text": rule_id}})
        result: dict[str, Any] = {
            "ruleId": rule_id,
            "level": _sarif_level(str(item.get("severity", "warning"))),
            "message": {"text": str(item.get("message", rule_id))},
            "partialFingerprints": {"webVulnMiningFingerprint": str(item.get("fingerprint", ""))},
            "properties": {
                "tool": item.get("tool"),
                "status": item.get("status"),
                "parameter": item.get("parameter", ""),
                "evidence": item.get("evidence", ""),
            },
        }
        if item.get("location"):
            result["locations"] = [{"physicalLocation": {"artifactLocation": {"uri": str(item["location"])}}}]
        results.append(result)
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "web-vuln-mining-normalizer", "rules": list(rules.values())}}, "results": results}],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("run_dir", type=Path)
    args = parser.parse_args()
    findings: dict[str, dict[str, Any]] = {}
    for path in (args.run_dir / "sarif").glob("*.sarif"):
        if path.name == NORMALIZED_SARIF_NAME:
            continue
        _sarif(path, findings)
    for path in (args.run_dir / "raw").glob("*.jsonl"):
        _jsonl(path, findings)
    for path in (args.run_dir / "raw").glob("schemathesis-*.ndjson"):
        _schemathesis_ndjson(path, findings)
    for path in (args.run_dir / "raw").glob("zap*.json"):
        _zap_json(path, findings)
    for path in (args.run_dir / "raw").glob("dalfox*.jsonl"):
        _dalfox_jsonl(path, findings)
    for path in (args.run_dir / "raw").glob("ffuf-*.json"):
        _ffuf_json(path, findings)
    for path in (args.run_dir / "raw").glob("sqlmap-index.json"):
        _sqlmap_index(path, findings)
    manifest = json.loads((args.run_dir / "run-manifest.json").read_text(encoding="utf-8"))
    normalized = list(findings.values())
    summary = {"run_id": manifest["run_id"], "profile": manifest["profile"], "local_tool_status": manifest["local_tool_status"], "hexstrike_status": manifest["hexstrike_status"], "findings": normalized, "counts": {"candidate": sum(item.get("status") == "candidate" for item in normalized), "reproduced": sum(item.get("status") == "reproduced" for item in normalized), "excluded": sum(item.get("status") == "excluded" for item in normalized)}}
    write_json(args.run_dir / "summary.json", summary)
    write_json(args.run_dir / "evidence" / EVIDENCE_INDEX_NAME, {"run_id": manifest["run_id"], "findings": normalized})
    write_json(args.run_dir / "sarif" / NORMALIZED_SARIF_NAME, _normalized_sarif(normalized))
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
