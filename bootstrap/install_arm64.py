#!/usr/bin/env python3
"""Backward-compatible ARM64 entry point for the unified locked installer."""
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--only-tools", default="")
    parser.add_argument("--repair", action="store_true", help="accepted for compatibility; installation is explicit")
    args = parser.parse_args()
    command = [sys.executable, str(ROOT / "scripts" / "install_toolchain.py"), "--lock", "tool-lock.linux-arm64.json"]
    if args.only_tools:
        command.extend(["--only-tools", args.only_tools])
    return subprocess.run(command, cwd=ROOT).returncode


if __name__ == "__main__":
    raise SystemExit(main())
