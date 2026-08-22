"""Offline validation that local Nuclei templates are passive GET/HEAD only."""
from __future__ import annotations

import argparse
from pathlib import Path

import yaml  # type: ignore[import-untyped]


def validate(directory: Path) -> list[str]:
    errors: list[str] = []
    for path in sorted(directory.glob("*.yaml")):
        try:
            document = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            errors.append(f"{path.name}: invalid YAML: {exc}")
            continue
        if not isinstance(document, dict) or not document.get("id"):
            errors.append(f"{path.name}: missing id")
            continue
        requests = document.get("http", [])
        if not isinstance(requests, list) or not requests:
            errors.append(f"{path.name}: missing http request")
            continue
        for request in requests:
            method = str(request.get("method", "")).upper() if isinstance(request, dict) else ""
            if method not in {"GET", "HEAD"}:
                errors.append(f"{path.name}: disallowed method {method}")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("directory", type=Path, nargs="?", default=Path(__file__).resolve().parents[1] / "rules" / "nuclei")
    args = parser.parse_args()
    errors = validate(args.directory)
    if errors:
        print("\n".join(errors))
        return 2
    print("All local Nuclei templates are passive GET/HEAD templates.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
