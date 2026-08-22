"""Centralized redaction for evidence, SARIF, and human-facing reports.

The workbench deliberately keeps raw tool output in a run directory for a
reviewer, but derived output must not reproduce credentials.  Keep this module
small and dependency-free so it is also usable by CI validation code.
"""
from __future__ import annotations

import re
from typing import Any


REDACTED = "[REDACTED]"
_PATTERNS = (
    # HTTP authorization headers and query parameters.
    (re.compile(r"(?i)\b(Bearer)\s+[A-Za-z0-9._~+/-]+=*"), r"\1 " + REDACTED),
    (re.compile(r"(?i)\b(Basic)\s+[A-Za-z0-9+/=]{6,}"), r"\1 " + REDACTED),
    (re.compile(r"(?i)(Cookie\s*[:=]\s*)[^\r\n;]+"), r"\1" + REDACTED),
    (re.compile(r"(?i)(Set-Cookie\s*[:=]\s*)[^\r\n;]+"), r"\1" + REDACTED),
    (re.compile(r"(?i)(?:api[_-]?key|access[_-]?token|auth[_-]?token|password|secret|token)=([^&#\s]+)"), lambda match: match.group(0).split("=", 1)[0] + "=" + REDACTED),
    # JWTs and PEM private key material often appear without a field name.
    (re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"), REDACTED),
    (re.compile(r"-----BEGIN(?: [A-Z]+)? PRIVATE KEY-----.*?-----END(?: [A-Z]+)? PRIVATE KEY-----", re.DOTALL), REDACTED),
)


def redact_text(value: object) -> str:
    """Return a safe, display-ready representation of *value*."""
    text = str(value)
    for pattern, replacement in _PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def redact_value(value: Any) -> Any:
    """Recursively redact JSON-compatible values without changing structure."""
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, list):
        return [redact_value(item) for item in value]
    if isinstance(value, dict):
        return {str(key): redact_value(item) for key, item in value.items()}
    return value
