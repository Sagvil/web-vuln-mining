"""Execute the verified sqlmap entry from a compressed portable blob."""
from __future__ import annotations
import argparse
import sys
import zlib
from pathlib import Path
# ============================ Configuration zone ============================
BLOB_NAME = "sqlmap_entry.zlib"  # Prepared by scripts/prepare_sqlmap.py.
# ============================================================================
def main() -> int:
    parser = argparse.ArgumentParser(add_help=False); parser.add_argument("--sqlmap-root", type=Path, required=True); args, forwarded = parser.parse_known_args()
    root = args.sqlmap_root.resolve(); blob = root / BLOB_NAME
    if not blob.is_file(): raise SystemExit(f"missing sqlmap entry blob: {blob}")
    sys.path.insert(0, str(root)); sys.argv = [str(root / "sqlmap.py"), *forwarded]
    namespace = {"__name__": "__main__", "__file__": str(root / "sqlmap.py"), "__package__": None}
    exec(compile(zlib.decompress(blob.read_bytes()), str(root / "sqlmap.py"), "exec"), namespace)
    return 0
if __name__ == "__main__": raise SystemExit(main())
