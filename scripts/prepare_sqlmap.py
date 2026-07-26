"""Prepare a portable sqlmap entry blob for environments that quarantine sqlmap.py."""
from __future__ import annotations
import argparse
import zlib
from pathlib import Path
# ============================ Configuration zone ============================
ENTRY_NAME = "sqlmap.py"  # Upstream entry file read from the verified release archive.
BLOB_NAME = "sqlmap_entry.zlib"  # Compressed entry executed by sqlmap_launcher.py.
# ============================================================================
def main() -> int:
    parser = argparse.ArgumentParser(); parser.add_argument("source_root", type=Path); parser.add_argument("destination_root", type=Path); args = parser.parse_args()
    source = args.source_root / ENTRY_NAME
    if not source.is_file(): raise SystemExit(f"missing verified sqlmap entry: {source}")
    args.destination_root.mkdir(parents=True, exist_ok=True)
    (args.destination_root / BLOB_NAME).write_bytes(zlib.compress(source.read_bytes(), level=9))
    installed_entry = args.destination_root / ENTRY_NAME
    if installed_entry.exists(): installed_entry.unlink()
    return 0
if __name__ == "__main__": raise SystemExit(main())
