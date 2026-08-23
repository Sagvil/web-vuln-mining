"""Deterministic, local governance records for bounded web-mining runs.

The module deliberately does not execute tools, prompt for approval, or infer
scope.  It turns an already validated profile invocation into a small Action
Contract decision and writes evidence artifacts that can be replayed offline.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA_VERSION = 1
OUTCOMES = frozenset({"DENY", "REQUIRE_APPROVAL", "PERMIT_AND_NOTIFY", "PERMIT_AND_LOG"})

_PROFILE_ACTIONS = {
    "source": "read-source",
    "web-baseline": "bounded-network-read",
    "api": "bounded-network-read",
    "content-discovery": "bounded-network-read",
    "active-dns-discovery": "bounded-dns-discovery",
    "verify-xss": "bounded-active-verification",
    "verify-sqli": "bounded-active-verification",
    "verify-jwt": "bounded-active-verification",
    "verify-nosql": "bounded-active-verification",
    "verify-race": "bounded-active-verification",
    "verify-ssrf-ssti": "bounded-active-verification",
    "verify-llm-injection": "bounded-active-verification",
}


def _canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def file_sha256(path: Path) -> str:
    return _sha256_bytes(path.read_bytes())


def fingerprint(value: Any) -> str:
    return "sha256:" + _sha256_bytes(_canonical(value).encode("utf-8"))


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def action_class(profile: str) -> str:
    return _PROFILE_ACTIONS.get(profile, "unknown-profile")


def intent_for(
    scope_path: Path, scope: dict[str, Any], profile: str, *, skill_id: str = "web-mining", run_id: str = "",
) -> dict[str, Any]:
    """Bind one invocation without placing raw scope paths, hosts, or targets in the ledger."""
    targets = list(scope.get("base_urls", [])) + list(scope.get("openapi", []))
    target_set = sorted(str(item).strip().lower() for item in [*targets, *scope.get("include_hosts", [])])
    scope_sha256 = file_sha256(scope_path)
    return {
        "schema_version": SCHEMA_VERSION,
        "skill_id": skill_id,
        "run_id": run_id,
        "profile": profile,
        "action_class": action_class(profile),
        "scope": {"sha256": scope_sha256},
        "scope_manifest_sha256": scope_sha256,
        "target_set_hash": fingerprint(target_set),
        "target_count": len(targets),
        "rate_limit": scope.get("rate_limit"),
        "crawl_budget": scope.get("crawl_budget", {}),
        "evidence_reference": "governance/evidence-index.json",
    }


def load_contract(path: Path | None) -> tuple[dict[str, Any] | None, str | None]:
    if path is None:
        return None, None
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return None, f"contract unreadable: {exc}"
    if not isinstance(value, dict):
        return None, "contract must be a JSON object"
    return value, None


def _decision(outcome: str, reason: str, intent: dict[str, Any], contract: dict[str, Any] | None, *, mode: str) -> dict[str, Any]:
    if outcome not in OUTCOMES:
        raise ValueError(f"unknown governance outcome: {outcome}")
    return {
        "schema_version": SCHEMA_VERSION,
        "created_at": utc_now(),
        "mode": mode,
        "outcome": outcome,
        "reason": reason,
        "intent": intent,
        "intent_fingerprint": fingerprint(intent),
        "contract_id": contract.get("contract_id") if contract else None,
        "contract_sha256": fingerprint(contract) if contract else None,
    }


def evaluate(scope_path: Path, scope: dict[str, Any], profile: str, *, mode: str, contract_path: Path | None = None, now: datetime | None = None, skill_id: str = "web-mining", run_id: str = "") -> tuple[dict[str, Any], dict[str, Any] | None]:
    """Classify one profile invocation without executing it.

    In ``shadow`` mode missing or invalid authority is recorded but never
    changes the caller's execution decision.  ``enforce`` is interpreted by
    the runner, which blocks non-permit outcomes before any profile tool runs.
    """
    intent = intent_for(scope_path, scope, profile, skill_id=skill_id, run_id=run_id)
    if mode not in {"shadow", "enforce", "off"}:
        raise ValueError("mode must be off, shadow, or enforce")
    if mode == "off":
        return _decision("PERMIT_AND_LOG", "governance disabled", intent, None, mode=mode), None
    contract, error = load_contract(contract_path)
    if error:
        return _decision("REQUIRE_APPROVAL", error, intent, None, mode=mode), None
    if contract is None:
        return _decision("REQUIRE_APPROVAL", "no Action Contract supplied for this profile", intent, None, mode=mode), None
    if int(contract.get("schema_version", 0)) != SCHEMA_VERSION:
        return _decision("REQUIRE_APPROVAL", "contract schema version is unsupported", intent, contract, mode=mode), contract
    if contract.get("status") != "active":
        return _decision("REQUIRE_APPROVAL", "contract is not active", intent, contract, mode=mode), contract
    expires = _parse_time(contract.get("valid_until"))
    current = now or datetime.now(timezone.utc)
    if expires is None or expires <= current:
        return _decision("REQUIRE_APPROVAL", "contract is expired or lacks valid_until", intent, contract, mode=mode), contract
    scope_ref = contract.get("scope_ref") if isinstance(contract.get("scope_ref"), dict) else {}
    if scope_ref.get("sha256") != intent["scope"]["sha256"]:
        return _decision("REQUIRE_APPROVAL", "contract scope hash does not match this invocation", intent, contract, mode=mode), contract
    skipped = {str(item) for item in contract.get("skipped_profiles", [])}
    if profile in skipped:
        return _decision("DENY", f"profile {profile!r} is explicitly skipped by contract", intent, contract, mode=mode), contract
    allowed_profiles = {str(item) for item in contract.get("allowed_profiles", [])}
    if profile not in allowed_profiles:
        return _decision("REQUIRE_APPROVAL", f"profile {profile!r} is not authorized by contract", intent, contract, mode=mode), contract
    allowed_actions = {str(item) for item in contract.get("allowed_actions", [])}
    if intent["action_class"] not in allowed_actions:
        return _decision("REQUIRE_APPROVAL", f"action class {intent['action_class']!r} is not authorized", intent, contract, mode=mode), contract
    budgets = contract.get("budgets") if isinstance(contract.get("budgets"), dict) else {}
    if int(budgets.get("max_targets", intent["target_count"])) < intent["target_count"]:
        return _decision("REQUIRE_APPROVAL", "target count exceeds contract budget", intent, contract, mode=mode), contract
    rate_budget = budgets.get("max_rate_limit")
    if rate_budget is not None and int(rate_budget) < int(intent["rate_limit"] or 0):
        return _decision("REQUIRE_APPROVAL", "rate limit exceeds contract budget", intent, contract, mode=mode), contract
    outcome = "PERMIT_AND_LOG" if profile == "source" else "PERMIT_AND_NOTIFY"
    return _decision(outcome, "active contract matches profile, scope, action, and budgets", intent, contract, mode=mode), contract


def write_artifacts(run_dir: Path, decision: dict[str, Any], contract: dict[str, Any] | None, *, execution: dict[str, Any] | None = None) -> None:
    """Write append-only-style decision and execution receipts under one run."""
    root = run_dir / "governance"
    root.mkdir(parents=True, exist_ok=True)
    if contract is not None:
        (root / "contract.json").write_text(json.dumps(contract, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (root / "decision.json").write_text(json.dumps(decision, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    ledger = root / "action-ledger.jsonl"
    records: list[dict[str, Any]] = []
    if not ledger.exists():
        records.append({"event": "policy_decision", **decision})
    if execution is not None:
        records.append({"event": "execution_receipt", "created_at": utc_now(), **execution})
    with ledger.open("a", encoding="utf-8") as handle:
        for record in records:
            handle.write(_canonical(record) + "\n")
    evidence = {
        "schema_version": SCHEMA_VERSION,
        "decision": "governance/decision.json",
        "ledger": "governance/action-ledger.jsonl",
        "contract": "governance/contract.json" if contract is not None else None,
        "independent_verification": "not-run-by-governance",
    }
    (root / "evidence-index.json").write_text(json.dumps(evidence, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
