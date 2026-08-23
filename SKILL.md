---
name: web-mining
description: Portable Web/API vulnerability-mining skill with bounded profiles, evidence-first candidate handling, and optional remote review.
---
# Web Mining

Set `WEB_VULN_MINING_ROOT` to this repository. `skills/web-mining` is the only maintained publishable Hermes skill; the earlier pentest router/executor pair is archived and must not be installed or enabled. Start with read-only `scripts/preflight.py --json`; use `--repair` only as an explicit operator action. A real Profile repeats an integrity check automatically. Treat all automation as candidate evidence: IDOR, authorization, and business logic require manual review, and platform drafts require a reproduced, human-reviewed, scope-confirmed `triage.yaml` record. The workbench never auto-submits or stores platform credentials.
