"""Create a concise Markdown report from a normalized run summary."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Configuration zone: report title prefix.
REPORT_TITLE_PREFIX = "Web Vulnerability Mining"

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except AttributeError:
    pass


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("run_dir", type=Path)
    args = parser.parse_args()
    summary = json.loads((args.run_dir / "summary.json").read_text(encoding="utf-8"))
    lines = [f"# {REPORT_TITLE_PREFIX} — {summary['run_id']}", "", f"- Profile: `{summary['profile']}`", f"- HEXSTRIKE_STATUS: `{summary['hexstrike_status']}`", f"- Candidate findings: `{summary['counts']['candidate']}`", f"- Reproduced findings: `{summary['counts']['reproduced']}`", f"- Excluded findings: `{summary['counts']['excluded']}`", "", "## LOCAL_TOOL_STATUS"]
    for tool in summary["local_tool_status"]:
        detail = tool.get("reason") or tool.get("fallback") or tool.get("output") or ""
        lines.append(f"- `{tool.get('tool', 'unknown')}`: `{tool.get('status', 'unknown')}` {detail}")
    lines.extend(["", "## Candidates"])
    for finding in summary["findings"]:
        lines.extend([f"### {finding['rule']}", f"- Tool: `{finding['tool']}`", f"- Severity: `{finding['severity']}`", f"- Location: `{finding['location']}`", f"- Evidence status: `{finding['status']}`", f"- Message: {finding['message']}", ""])
        if finding.get("method"):
            lines.insert(len(lines) - 1, f"- Method: `{finding['method']}`")
        if finding.get("parameter"):
            lines.insert(len(lines) - 1, f"- Parameter: `{finding['parameter']}`")
        if finding.get("evidence"):
            lines.insert(len(lines) - 1, f"- Evidence: `{finding['evidence']}`")
        if finding.get("reproduction_command"):
            lines.insert(len(lines) - 1, f"- Reproduction command: `{' '.join(str(part) for part in finding['reproduction_command'])}`")
    output = args.run_dir / "report.md"
    output.write_text("\n".join(lines), encoding="utf-8")
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
