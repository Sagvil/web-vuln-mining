"""Load the sole human-decision input used for report submission drafts."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from common import load_yaml


VALID_STATUSES = {"candidate", "needs-review", "reproduced", "excluded"}


def load_triage(run_dir: Path) -> dict[str, dict[str, Any]]:
    """Read an optional ``triage.yaml`` and map entries by fingerprint.

    Invalid human input never upgrades a candidate: callers receive an empty
    mapping for malformed files and preserve the normalized tool status.
    """
    path = run_dir / "triage.yaml"
    if not path.is_file():
        return {}
    try:
        payload = load_yaml(path)
    except (OSError, ValueError, RuntimeError):
        return {}
    entries = payload.get("findings", []) if isinstance(payload, dict) else []
    mapped: dict[str, dict[str, Any]] = {}
    for item in entries if isinstance(entries, list) else []:
        if not isinstance(item, dict):
            continue
        fingerprint = str(item.get("fingerprint", "")).strip()
        status = str(item.get("status", "needs-review")).strip().lower()
        if fingerprint and status in VALID_STATUSES:
            mapped[fingerprint] = dict(item, status=status)
    return mapped


def submission_eligible(finding: dict[str, Any]) -> bool:
    """Only human-reviewed, scope-confirmed reproductions enter drafts."""
    review: dict[str, Any] = {}
    candidate_review = finding.get("human_review")
    if isinstance(candidate_review, dict):
        review = candidate_review
    return bool(
        finding.get("status") == "reproduced"
        and review.get("human_reviewed") is True
        and review.get("scope_confirmed") is True
    )
