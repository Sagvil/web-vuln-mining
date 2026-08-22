---
name: web-mining
description: Run portable Web/API source review, Web baseline, API, verification, and explicit DNS candidate-mining profiles.
---
# Web Mining

Set `WEB_VULN_MINING_ROOT` to this cloned repository. Run read-only `preflight.py --json` first; use `--repair` only as an explicit operator action. A real profile performs its own integrity preflight. Preserve host, path, rate, and crawl limits. DNS candidates do not become targets automatically. Dalfox/sqlmap use explicit candidate files, ffuf uses a bounded wordlist, and HexStrike review status remains separate from local tool status. Automated authorization/IDOR signals require manual review, and platform drafts require an eligible `triage.yaml` decision; never auto-submit.
