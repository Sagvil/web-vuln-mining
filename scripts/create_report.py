"""Render redacted reports and manual-only HackerOne/Bugcrowd/Intigriti drafts."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from redaction import redact_text
from triage import submission_eligible


def _finding_lines(item: dict[str, Any], chinese: bool = False) -> list[str]:
    source = item.get("source", {}) if isinstance(item.get("source"), dict) else {}
    asset = item.get("asset", {}) if isinstance(item.get("asset"), dict) else {}
    review = item.get("human_review", {}) if isinstance(item.get("human_review"), dict) else {}
    labels = {
        "tool": "工具" if chinese else "Tool", "severity": "严重性" if chinese else "Severity",
        "confidence": "置信度" if chinese else "Confidence", "status": "状态" if chinese else "Evidence status",
        "endpoint": "端点" if chinese else "Endpoint", "message": "说明" if chinese else "Message",
        "impact": "影响" if chinese else "Impact", "reproduction": "最小复现" if chinese else "Minimal reproduction",
    }
    lines = [f"### {redact_text(source.get('rule', 'finding'))}"]
    lines.extend([
        f"- {labels['tool']}: `{redact_text(source.get('tool', 'unknown'))}`",
        f"- CWE: `{redact_text(item.get('cwe', 'unclassified'))}`",
        f"- {labels['severity']}: `{redact_text(item.get('severity', 'info'))}`",
        f"- {labels['confidence']}: `{redact_text(item.get('confidence', 'medium'))}`",
        f"- {labels['status']}: `{redact_text(item.get('status', 'candidate'))}`",
        f"- {labels['endpoint']}: `{redact_text(asset.get('endpoint', ''))}`",
        f"- {labels['message']}: {redact_text(item.get('message', ''))}",
        f"- Fingerprint: `{redact_text(item.get('fingerprint', ''))}`",
    ])
    if review.get("impact"):
        lines.append(f"- {labels['impact']}: {redact_text(review['impact'])}")
    steps = review.get("reproduction_steps", [])
    if isinstance(steps, list) and steps:
        lines.append(f"- {labels['reproduction']}:")
        lines.extend(f"  {number}. {redact_text(step)}" for number, step in enumerate(steps, 1))
    return lines + [""]


def _submission(item: dict[str, Any], platform: str) -> str:
    review = item.get("human_review", {}) if isinstance(item.get("human_review"), dict) else {}
    asset = item.get("asset", {}) if isinstance(item.get("asset"), dict) else {}
    source = item.get("source", {}) if isinstance(item.get("source"), dict) else {}
    steps = review.get("reproduction_steps", []) if isinstance(review.get("reproduction_steps"), list) else []
    lines = [
        f"# {redact_text(source.get('rule', 'Security finding'))}", "",
        f"- Target: `{redact_text(asset.get('endpoint', ''))}`",
        f"- CWE: `{redact_text(item.get('cwe', 'unclassified'))}`",
        f"- Severity (reviewer assessment): `{redact_text(item.get('severity', 'info'))}`",
        f"- CVSS v4: `{redact_text(review.get('cvss_v4', 'not supplied'))}`", "",
        "## Summary", "", redact_text(item.get("message", "")), "",
        "## Scope and authorization", "", "The reviewer marked this finding as scope-confirmed. Re-check the program's current policy before submitting.", "",
        "## Steps to reproduce", "",
    ]
    lines.extend(f"{index}. {redact_text(step)}" for index, step in enumerate(steps, 1))
    if not steps:
        lines.append("1. Add the minimum redacted reproduction steps after independent validation.")
    lines.extend(["", "## Impact", "", redact_text(review.get("impact", "Describe demonstrated impact without credentials or live secrets.")), "", "## Recommendation", "", redact_text(review.get("recommendation", "Add a remediation recommendation after review.")), "", f"_Prepared as a manual {platform} draft. This tool does not submit reports or retain platform credentials._", ""])
    return "\n".join(lines)


def _triage_starter(path: Path, findings: list[dict[str, Any]]) -> None:
    if path.exists():
        return
    lines = ["# This is the sole human-decision input. Empty values never make a finding submit-ready.", "findings:"]
    for finding in findings:
        lines.extend([
            f"  - fingerprint: {finding.get('fingerprint', '')}", "    status: needs-review",
            "    human_reviewed: false", "    scope_confirmed: false", "    reviewer: ''", "    reviewed_at: ''",
            "    impact: ''", "    cwe: ''", "    cvss_v4: ''", "    recommendation: ''", "    reproduction_steps: []",
        ])
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("run_dir", type=Path)
    args = parser.parse_args()
    run = args.run_dir
    summary = json.loads((run / "summary.json").read_text(encoding="utf-8"))
    findings = summary.get("findings", []) if isinstance(summary.get("findings"), list) else []
    counts = summary.get("counts", {}) if isinstance(summary.get("counts"), dict) else {}
    compatibility = summary.get("compatibility")
    english = [f"# Web Vulnerability Mining — {redact_text(summary.get('run_id', 'run'))}", "", f"- Profile: `{redact_text(summary.get('profile', ''))}`", f"- Candidate findings: `{counts.get('candidate', 0)}`", f"- Needs review: `{counts.get('needs-review', 0)}`", f"- Reproduced findings: `{counts.get('reproduced', 0)}`", f"- Excluded findings: `{counts.get('excluded', 0)}`", "- All displayed evidence is redacted; raw evidence remains local for authorized review."]
    if compatibility:
        english.append("- Compatibility: this report was rendered from a v1 run directory; unavailable v2 fields are intentionally empty.")
    english.extend(["", "## Findings", ""])
    for finding in findings:
        english.extend(_finding_lines(finding))
    assets = summary.get("asset_candidates", []) if isinstance(summary.get("asset_candidates"), list) else []
    if assets:
        english.extend(["## DNS Asset Candidates", "", "Inventory candidates only; they are not Web targets, scan scope, or vulnerability conclusions."])
        for item in assets:
            english.append(f"- `{redact_text(item.get('hostname', ''))}`")
    (run / "report.md").write_text("\n".join(english) + "\n", encoding="utf-8")

    chinese = [f"# Web 漏洞挖掘审阅摘要 — {redact_text(summary.get('run_id', 'run'))}", "", f"- Profile：`{redact_text(summary.get('profile', ''))}`", f"- 候选：`{counts.get('candidate', 0)}`；待审阅：`{counts.get('needs-review', 0)}`；已复现：`{counts.get('reproduced', 0)}`", "- 自动化结果均为候选；只有人工确认范围、复现和影响后才可形成平台草稿。", "", "## 发现"]
    for finding in findings:
        chinese.extend(_finding_lines(finding, chinese=True))
    (run / "review.zh-CN.md").write_text("\n".join(chinese) + "\n", encoding="utf-8")

    _triage_starter(run / "triage.yaml", findings)
    submission = run / "submission"
    submission.mkdir(parents=True, exist_ok=True)
    eligible = [item for item in findings if isinstance(item, dict) and submission_eligible(item)]
    for name in ("hackerone", "bugcrowd", "intigriti"):
        draft = "\n\n---\n\n".join(_submission(item, name.title()) for item in eligible)
        if not draft:
            draft = f"# {name.title()} submission draft\n\nNo finding is eligible. A finding must be `reproduced`, `human_reviewed: true`, and `scope_confirmed: true` in `triage.yaml`.\n"
        (submission / f"{name}.md").write_text(draft, encoding="utf-8")
    checklist = ["# Manual submission checklist", "", "- [ ] The program policy and Safe Harbor terms are currently valid.", "- [ ] The affected asset and exact endpoint are in scope.", "- [ ] Reproduction was performed manually with the minimum safe steps.", "- [ ] Impact is demonstrated, not inferred from a scanner alert.", "- [ ] Tokens, cookies, credentials, private keys, and sensitive query values are redacted.", "- [ ] `triage.yaml` records `reproduced`, `human_reviewed: true`, and `scope_confirmed: true`.", "- [ ] The selected platform's current duplicate, disclosure, and severity rules were checked.", "", "The workbench does not call platform APIs or store platform credentials."]
    (submission / "checklist.md").write_text("\n".join(checklist) + "\n", encoding="utf-8")
    print(run / "report.md")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
