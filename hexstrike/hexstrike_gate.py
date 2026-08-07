#!/usr/bin/env python3
"""Hermes audit hook for optional HexStrike review; it never blocks local profiles."""
from __future__ import annotations

import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

# ============================ Configuration zone ============================
# STATE_DIR: session-local audit state. Override for tests with HEXSTRIKE_STATE_DIR.
STATE_DIR = Path(os.environ.get('HEXSTRIKE_STATE_DIR', str(Path.home() / '.hermes' / 'hexstrike-guard')))
# AUDIT_LOG: append-only local event log. Override for tests with HEXSTRIKE_AUDIT_LOG.
AUDIT_LOG = Path(os.environ.get('HEXSTRIKE_AUDIT_LOG', str(Path.home() / '.hermes' / 'logs' / 'hexstrike-guard.jsonl')))
# MAX_JSON_BYTES: refuse oversized hook payloads without delaying the gateway.
MAX_JSON_BYTES = 256 * 1024
# ============================================================================

ASSESSMENT_PATTERN = re.compile(r'(?:漏洞|渗透|攻击面|资产|扫描|探测|枚举|验证|\b(?:pentest|vulnerability|recon|scan|enumerat|probe|web assessment|security assessment)\b)', re.IGNORECASE)
NETWORK_COMMAND_PATTERN = re.compile(r'(?:^|[;&|()\s])(?:curl|wget|subfinder|amass|httpx|nmap|rustscan|nuclei|nikto|ffuf|gobuster|dirsearch|feroxbuster|katana|gau|waybackurls|arjun|paramspider|dalfox|sqlmap|wpscan|wafw00f)(?:\s|$)', re.IGNORECASE)
HEXSTRIKE_TOOL_PATTERN = re.compile(r'hexstrike_(?:run|job_status|preflight|capability_catalog)', re.IGNORECASE)


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def _read_payload() -> dict[str, Any]:
    raw = sys.stdin.buffer.read(MAX_JSON_BYTES + 1)
    if len(raw) > MAX_JSON_BYTES:
        return {}
    try:
        value = json.loads(raw.decode('utf-8'))
        return value if isinstance(value, dict) else {}
    except (UnicodeDecodeError, json.JSONDecodeError):
        return {}


def _text(value: Any) -> str:
    return value if isinstance(value, str) else ''


def _audit(event: str, session_id: str, **fields: Any) -> None:
    try:
        AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        record = {'timestamp': utc_now(), 'event': event, 'session_id': session_id, **fields}
        with AUDIT_LOG.open('a', encoding='utf-8') as handle:
            handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True, default=str) + '\n')
    except OSError:
        pass


def _nested_objects(value: Any, depth: int = 0) -> Iterable[dict[str, Any]]:
    if depth > 8:
        return
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from _nested_objects(child, depth + 1)
    elif isinstance(value, list):
        for child in value[:200]:
            yield from _nested_objects(child, depth + 1)
    elif isinstance(value, str) and len(value) <= MAX_JSON_BYTES:
        stripped = value.strip()
        if stripped.startswith(('{', '[')):
            try:
                yield from _nested_objects(json.loads(stripped), depth + 1)
            except json.JSONDecodeError:
                return


def _job_ids(payload: dict[str, Any]) -> list[str]:
    result = payload.get('extra', {}).get('result') if isinstance(payload.get('extra'), dict) else None
    values = []
    for item in _nested_objects(result):
        job_id = item.get('job_id')
        if isinstance(job_id, str) and job_id and job_id not in values:
            values.append(job_id)
    return values[:20]


def main() -> None:
    payload = _read_payload()
    event = _text(payload.get('hook_event_name'))
    session_id = _text(payload.get('session_id')) or 'anonymous'
    extra = payload.get('extra') if isinstance(payload.get('extra'), dict) else {}
    try:
        if event == 'pre_llm_call':
            message = _text(extra.get('user_message')).strip()
            if ASSESSMENT_PATTERN.search(message):
                _audit('assessment_intent', session_id, mode='audit-only', message=message[:500])
        elif event == 'pre_tool_call':
            tool_name = _text(payload.get('tool_name'))
            tool_input = payload.get('tool_input') if isinstance(payload.get('tool_input'), dict) else {}
            command = _text(tool_input.get('command') or tool_input.get('cmd'))
            if NETWORK_COMMAND_PATTERN.search(command):
                _audit('local_network_command', session_id, mode='allowed-local-profile', tool=tool_name, command=command[:500])
            elif HEXSTRIKE_TOOL_PATTERN.search(tool_name):
                _audit('hexstrike_requested', session_id, mode='optional-review', tool=tool_name)
        elif event == 'post_tool_call':
            tool_name = _text(payload.get('tool_name'))
            if HEXSTRIKE_TOOL_PATTERN.search(tool_name):
                _audit('hexstrike_result', session_id, tool=tool_name, job_ids=_job_ids(payload))
    except Exception as exc:  # Audit must never make an assessment unavailable.
        _audit('hook_error', session_id, error=repr(exc), hook_event=event)


if __name__ == '__main__':
    main()
