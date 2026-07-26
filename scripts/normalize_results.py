"""Normalize SARIF, JSONL, and ZAP alerts into a de-duplicated summary."""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from common import write_json

# Configuration zone: cap the number of raw findings read from one JSONL file.
MAX_JSONL_RECORDS_PER_FILE = 10000

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


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("run_dir", type=Path)
    args = parser.parse_args()
    findings: dict[str, dict[str, Any]] = {}
    for path in (args.run_dir / "sarif").glob("*.sarif"):
        _sarif(path, findings)
    for path in (args.run_dir / "raw").glob("*.jsonl"):
        _jsonl(path, findings)
    for path in (args.run_dir / "raw").glob("schemathesis-*.ndjson"):
        _schemathesis_ndjson(path, findings)
    for path in (args.run_dir / "raw").glob("zap*.json"):
        _zap_json(path, findings)
    manifest = json.loads((args.run_dir / "run-manifest.json").read_text(encoding="utf-8"))
    summary = {"run_id": manifest["run_id"], "profile": manifest["profile"], "local_tool_status": manifest["local_tool_status"], "hexstrike_status": manifest["hexstrike_status"], "findings": list(findings.values()), "counts": {"candidate": len(findings), "reproduced": 0, "excluded": 0}}
    write_json(args.run_dir / "summary.json", summary)
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
