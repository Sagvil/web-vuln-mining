"""Emit a machine-readable portable-workbench installation status."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from common import WORKBENCH_ROOT, command_for, data_root, load_json, platform_lock_path

# ============================ Configuration zone ============================
# STATE_FILE_NAME: installer state file written below the selected data root.
STATE_FILE_NAME = "install-state.json"
# ============================================================================


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true", help="print JSON only")
    args = parser.parse_args()
    state_path = data_root() / STATE_FILE_NAME
    state = load_json(state_path) if state_path.is_file() else {}
    lock = load_json(platform_lock_path())
    tools = [{"name": name, "version": item["version"], "command": command_for(name), "installed": command_for(name) is not None} for name, item in lock["tools"].items()]
    report = {"repository": str(WORKBENCH_ROOT), "data_root": str(data_root()), "state": state, "tools": tools}
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
