"""Offline OpenAPI security linting; never follows references or ``servers``."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

try:
    import yaml  # type: ignore[import-untyped]
except ImportError:  # pragma: no cover - user receives a clear CLI error
    yaml = None


SENSITIVE_WORDS = ("admin", "account", "user", "password", "token", "payment", "order")


def _candidate(rule: str, message: str, location: str, severity: str = "warning") -> dict[str, str]:
    return {"tool": "openapi-lint", "rule": rule, "severity": severity, "status": "candidate", "location": location, "message": message}


def load_schema(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8", errors="replace")
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        value = yaml.safe_load(text) if yaml else None
    if not isinstance(value, dict):
        raise ValueError("OpenAPI document must be a mapping")
    return value


def lint_openapi(document: dict[str, Any], label: str = "openapi") -> list[dict[str, str]]:
    """Return conservative review candidates from one already-downloaded document."""
    findings: list[dict[str, str]] = []
    version = str(document.get("openapi", ""))
    if not version.startswith("3."):
        findings.append(_candidate("openapi.version", "Document is not OpenAPI 3.x; verify parser assumptions.", label, "info"))
    servers = document.get("servers", [])
    for index, server in enumerate(servers if isinstance(servers, list) else []):
        url = str(server.get("url", "")) if isinstance(server, dict) else ""
        if url.startswith("http://"):
            findings.append(_candidate("openapi.insecure-transport", "Server uses unencrypted HTTP.", f"{label}#/servers/{index}", "warning"))
    schemes = document.get("components", {}).get("securitySchemes", {}) if isinstance(document.get("components"), dict) else {}
    if not isinstance(schemes, dict) or not schemes:
        findings.append(_candidate("openapi.missing-auth-scheme", "No security scheme is declared; review authentication requirements.", label))
    paths = document.get("paths", {})
    if not isinstance(paths, dict):
        return findings
    global_security = document.get("security")
    for route, item in paths.items():
        if not isinstance(item, dict):
            continue
        lowered = str(route).lower()
        for method, operation in item.items():
            if method.lower() not in {"get", "post", "put", "patch", "delete", "head", "options"} or not isinstance(operation, dict):
                continue
            location = f"{label}#/paths/{route}/{method}"
            if any(word in lowered for word in SENSITIVE_WORDS) and "security" not in operation and global_security is None:
                findings.append(_candidate("openapi.sensitive-operation-auth", "Sensitive-looking operation has no declared security requirement; manual authorization review required.", location))
            if method.lower() in {"post", "put", "patch"}:
                body = operation.get("requestBody", {})
                content = body.get("content", {}) if isinstance(body, dict) else {}
                if not content:
                    findings.append(_candidate("openapi.input-constraints", "State-changing operation declares no request-body schema.", location, "info"))
                else:
                    for media in content.values() if isinstance(content, dict) else []:
                        schema = media.get("schema", {}) if isinstance(media, dict) else {}
                        if isinstance(schema, dict) and not any(key in schema for key in ("maxLength", "maxItems", "maximum", "pattern", "$ref")):
                            findings.append(_candidate("openapi.input-constraints", "Input schema has no visible size or format constraints; review manually.", location, "info"))
                            break
            responses = operation.get("responses")
            if not isinstance(responses, dict) or not responses:
                findings.append(_candidate("openapi.responses", "Operation has no declared response contract.", location, "info"))
    return findings


def lint_openapi_file(path: Path) -> list[dict[str, str]]:
    return lint_openapi(load_schema(path), str(path))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("schema", type=Path, help="an already-downloaded local schema file")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    findings = lint_openapi_file(args.schema)
    payload = {"schema_version": 1, "source": str(args.schema), "followed_external_refs": False, "findings": findings}
    encoded = json.dumps(payload, ensure_ascii=False, indent=2)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")
    print(encoded)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
