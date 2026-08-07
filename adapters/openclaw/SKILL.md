---
name: web-mining
description: Run portable Web/API source review, Web baseline, API, verification, and explicit DNS candidate-mining profiles.
---
# Web Mining

Set `WEB_VULN_MINING_ROOT` to this cloned repository. Run `preflight.py --repair` once after cloning, then invoke one scoped profile. Preserve host, path, rate, and crawl limits. DNS candidates do not become targets automatically. Dalfox/sqlmap use explicit candidate files, ffuf uses a bounded wordlist, and HexStrike review status remains separate from local tool status.
