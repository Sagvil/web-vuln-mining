#!/usr/bin/env python3
"""Hermes shell hook: require an integrity-verified HexStrike job per assessment turn."""

from __future__ import annotations

import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

# ============================ 配置区 =========================================
# 会话状态目录：每个 Hermes session 一个 JSON 文件，避免不同会话相互放行。
STATE_DIR = Path(os.environ.get("HEXSTRIKE_STATE_DIR", str(Path.home() / ".hermes" / "hexstrike-guard")))
# 审计日志：JSONL，记录识别、拦截、作业完成和完整性校验事件。
AUDIT_LOG = Path(os.environ.get("HEXSTRIKE_AUDIT_LOG", str(Path.home() / ".hermes" / "logs" / "hexstrike-guard.jsonl")))
# 状态过期时间（秒）：长期闲置会话自动失效，避免“继续”意外继承旧授权状态。
STATE_TTL_SECONDS = 24 * 60 * 60
# Hook 输入最大字节数：超过上限时安全降级为不解析，防止异常大 payload 拖慢 Gateway。
MAX_JSON_BYTES = 256 * 1024

# 真实评估动作：命中后本轮必须完成 HexStrike 真实作业及 integrity 校验。
INTENT_PATTERN = re.compile(
    r"(?:漏洞(?:挖掘|扫描|验证|复现|测试)|渗透(?:测试)?|攻击面|资产(?:发现|梳理)|"
    r"(?:web|网站|接口|api|域名|主机|ip|端口).{0,24}(?:扫描|探测|枚举|侦察|测试|验证)|"
    r"\b(?:pentest|vulnerability|recon(?:naissance)?|scan(?:ning)?|enumerat(?:e|ion)|"
    r"probe|exploit|web assessment|security assessment)\b)",
    re.IGNORECASE,
)
# 简短继续指令：仅当 session 已在评估状态时，继续沿用同一门禁。
CONTINUE_PATTERN = re.compile(r"^(?:继续|继续执行|继续测试|继续扫描|continue|go on|proceed|next)\b", re.IGNORECASE)
# 纯离线工作：不产生网络流量，不强制新 job；它会结束当前轮门禁而不清除会话历史。
OFFLINE_PATTERN = re.compile(
    r"(?:只(?:整理|编辑|润色|汇总|复盘|分析|阅读|查看)|(?:报告|文档|证据|日志).{0,16}(?:整理|编辑|润色|汇总|复盘)|"
    r"(?:offline|report[- ]?(?:only|editing)|postmortem|write[- ]?up))",
    re.IGNORECASE,
)
# 识别 direct terminal 网络/扫描工具。只在“本轮需 HexStrike”且没有 integrity 作业时阻断。
DIRECT_NETWORK_COMMAND_PATTERN = re.compile(
    r"(?:^|[;&|()\s])(?:curl|wget|subfinder|amass|httpx|nmap|rustscan|nuclei|nikto|"
    r"ffuf|gobuster|dirsearch|feroxbuster|katana|gau|waybackurls|arjun|paramspider|"
    r"dalfox|sqlmap|wpscan|wafw00f)(?:\s|$)",
    re.IGNORECASE,
)
# policy MCP 显示名兼容：hexstrike_run_x、mcp__hexstrike-policy__hexstrike_run_x 等。
HEXSTRIKE_RUN_PATTERN = re.compile(r"hexstrike_run_([a-z0-9_]+)", re.IGNORECASE)
HEXSTRIKE_STATUS_PATTERN = re.compile(r"hexstrike_job_status(?:$|_)", re.IGNORECASE)
# 这些只读能力不算“执行参与”；即使返回 job_id，也不得放行 terminal。
NON_PARTICIPATION_CAPABILITIES = {
    "analyze_target_intelligence", "health", "dashboard", "metrics", "status",
    "system_health_check", "get_dashboard", "get_metrics",
}
# ============================================================================


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _safe_session_id(value: Any) -> str:
    raw = str(value or "anonymous")
    return re.sub(r"[^A-Za-z0-9_.-]", "_", raw)[:180] or "anonymous"


def _state_path(session_id: str) -> Path:
    return STATE_DIR / f"{_safe_session_id(session_id)}.json"


def _read_stdin() -> dict[str, Any]:
    raw = sys.stdin.buffer.read(MAX_JSON_BYTES + 1)
    if len(raw) > MAX_JSON_BYTES:
        return {}
    try:
        value = json.loads(raw.decode("utf-8"))
        return value if isinstance(value, dict) else {}
    except (UnicodeDecodeError, json.JSONDecodeError):
        return {}


def _load_state(session_id: str) -> dict[str, Any]:
    path = _state_path(session_id)
    try:
        state = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(state, dict):
            raise ValueError("state is not an object")
        updated = float(state.get("updated_epoch", 0))
        if updated and time.time() - updated > STATE_TTL_SECONDS:
            return _new_state(session_id)
        return state
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return _new_state(session_id)


def _new_state(session_id: str) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "session_id": session_id,
        "assessment_active": False,
        "turn_seq": 0,
        "turn_requires_hexstrike": False,
        "successful_jobs_this_turn": [],
        "integrity_verified_jobs_this_turn": [],
        "updated_epoch": time.time(),
        "last_updated": _utc_now(),
    }


def _save_state(state: dict[str, Any]) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    state["updated_epoch"] = time.time()
    state["last_updated"] = _utc_now()
    path = _state_path(str(state.get("session_id") or "anonymous"))
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, ensure_ascii=False, sort_keys=True), encoding="utf-8")
    os.replace(tmp, path)


def _audit(event: str, session_id: str, **fields: Any) -> None:
    try:
        AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
        entry = {"timestamp": _utc_now(), "event": event, "session_id": session_id, **fields}
        with AUDIT_LOG.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, ensure_ascii=False, sort_keys=True, default=str) + "\n")
    except OSError:
        pass


def _text(value: Any) -> str:
    if isinstance(value, str):
        return value
    return ""


def _collect_scope_roots(message: str) -> list[str]:
    candidates = re.findall(
        r"(?:https?://[^\s,，;；]+|\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?\b|\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b)",
        message,
        flags=re.IGNORECASE,
    )
    return list(dict.fromkeys(candidates))[:32]


def _nested_objects(value: Any, depth: int = 0) -> Iterable[dict[str, Any]]:
    """Yield JSON dictionaries from common MCP result wrappers without trusting a fixed schema."""
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
        if stripped.startswith(("{", "[")):
            try:
                parsed = json.loads(stripped)
            except json.JSONDecodeError:
                return
            yield from _nested_objects(parsed, depth + 1)


def _decode_result(payload: dict[str, Any]) -> Any:
    value = payload.get("extra", {}).get("result") if isinstance(payload.get("extra"), dict) else None
    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return value
    return value


def _find_job_records(value: Any) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for item in _nested_objects(value):
        job_id = item.get("job_id")
        artifact_dir = item.get("artifact_dir")
        if isinstance(job_id, str) and job_id:
            key = (job_id, str(artifact_dir or ""))
            if key not in seen:
                seen.add(key)
                records.append(item)
    return records


def _is_completed_success(record: dict[str, Any]) -> bool:
    return record.get("success") is True and str(record.get("status", "")).lower() == "completed"


def _is_integrity_success(record: dict[str, Any]) -> bool:
    return _is_completed_success(record) and record.get("integrity") is True


def _tool_name(payload: dict[str, Any]) -> str:
    return _text(payload.get("tool_name")).lower()


def _command(payload: dict[str, Any]) -> str:
    tool_input = payload.get("tool_input")
    if not isinstance(tool_input, dict):
        return ""
    return _text(tool_input.get("command") or tool_input.get("cmd"))


def _has_integrity(state: dict[str, Any]) -> bool:
    return bool(state.get("integrity_verified_jobs_this_turn"))


def _pre_llm(payload: dict[str, Any]) -> dict[str, str] | None:
    extra = payload.get("extra") if isinstance(payload.get("extra"), dict) else {}
    session_id = str(payload.get("session_id") or "anonymous")
    message = _text(extra.get("user_message")).strip()
    state = _load_state(session_id)
    is_offline = bool(OFFLINE_PATTERN.search(message))
    explicit_intent = bool(INTENT_PATTERN.search(message))
    continuing = bool(CONTINUE_PATTERN.search(message)) and bool(state.get("assessment_active"))

    if (explicit_intent or continuing) and not is_offline:
        state.update({
            "assessment_active": True,
            "turn_seq": int(state.get("turn_seq", 0)) + 1,
            "turn_requires_hexstrike": True,
            "successful_jobs_this_turn": [],
            "integrity_verified_jobs_this_turn": [],
        })
        roots = _collect_scope_roots(message)
        if roots:
            state["scope_roots"] = roots
        _save_state(state)
        _audit("turn_requires_hexstrike", session_id, turn_seq=state["turn_seq"], scope_roots=state.get("scope_roots", []))
        return {"context": (
            "HEXSTRIKE_RUNTIME_GATE: This is an active authorized assessment turn. Before any direct network "
            "probe, scan, or validation command, load pentest-hexstrike-executor; call hexstrike_preflight and "
            "hexstrike_capability_catalog; execute at least one scoped hexstrike_run_<capability> that produces "
            "discovery data; then call hexstrike_job_status for that job and require success=true, status=completed, "
            "integrity=true. Preflight, catalog, health, metrics, and analyze_target_intelligence do not satisfy this gate. "
            "After integrity verification, supplemental scoped terminal commands may be used."
        )}

    if is_offline:
        state["turn_requires_hexstrike"] = False
        _save_state(state)
        _audit("offline_turn", session_id)
    return None


def _pre_tool(payload: dict[str, Any]) -> dict[str, str] | None:
    session_id = str(payload.get("session_id") or "anonymous")
    state = _load_state(session_id)
    if not state.get("turn_requires_hexstrike") or _has_integrity(state):
        return None
    tool_name = _tool_name(payload)
    command = _command(payload)
    if tool_name == "terminal" and DIRECT_NETWORK_COMMAND_PATTERN.search(command):
        message = (
            "HEXSTRIKE_RUNTIME_GATE blocked this direct network command: this assessment turn has no "
            "integrity-verified HexStrike job. Next call hexstrike_preflight, hexstrike_capability_catalog, then a "
            "scoped hexstrike_run_<capability>; save its job_id and call hexstrike_job_status until "
            "success=true, status=completed, integrity=true."
        )
        _audit("blocked_direct_network_command", session_id, tool=tool_name, command=command[:500], turn_seq=state.get("turn_seq"))
        return {"action": "block", "message": message}
    return None


def _post_tool(payload: dict[str, Any]) -> None:
    session_id = str(payload.get("session_id") or "anonymous")
    state = _load_state(session_id)
    if not state.get("turn_requires_hexstrike"):
        return
    tool_name = _tool_name(payload)
    result = _decode_result(payload)
    records = _find_job_records(result)
    run_match = HEXSTRIKE_RUN_PATTERN.search(tool_name)

    if run_match:
        capability = run_match.group(1).lower()
        if capability not in NON_PARTICIPATION_CAPABILITIES:
            for record in records:
                if _is_completed_success(record) and record.get("artifact_dir"):
                    job_id = str(record["job_id"])
                    jobs = state.setdefault("successful_jobs_this_turn", [])
                    if job_id not in jobs:
                        jobs.append(job_id)
                    _audit("hexstrike_job_completed", session_id, tool=tool_name, capability=capability,
                           job_id=job_id, artifact_dir=record.get("artifact_dir"), turn_seq=state.get("turn_seq"))
            _save_state(state)
        return

    if HEXSTRIKE_STATUS_PATTERN.search(tool_name):
        for record in records:
            job_id = str(record["job_id"])
            if _is_integrity_success(record) and job_id in state.get("successful_jobs_this_turn", []):
                verified = state.setdefault("integrity_verified_jobs_this_turn", [])
                if job_id not in verified:
                    verified.append(job_id)
                _audit("hexstrike_job_integrity_verified", session_id, tool=tool_name, job_id=job_id,
                       artifact_dir=record.get("artifact_dir"), turn_seq=state.get("turn_seq"))
        _save_state(state)


def main() -> None:
    payload = _read_stdin()
    event = _text(payload.get("hook_event_name"))
    try:
        if event == "pre_llm_call":
            response = _pre_llm(payload)
            if response:
                print(json.dumps(response, ensure_ascii=False))
        elif event == "pre_tool_call":
            response = _pre_tool(payload)
            if response:
                print(json.dumps(response, ensure_ascii=False))
        elif event == "post_tool_call":
            _post_tool(payload)
    except Exception as exc:
        _audit("hook_error", str(payload.get("session_id") or "anonymous"), error=repr(exc), hook_event=event)


if __name__ == "__main__":
    main()
