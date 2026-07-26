---
name: web-vuln-mining
description: Run portable Web/API source review, Web baseline, and OpenAPI vulnerability-mining profiles.
---
# Web Vulnerability Mining
Set `WEB_VULN_MINING_ROOT` to this cloned repository. Run `preflight.py --repair` once after cloning, then invoke one scoped profile. Preserve manifest host, path, rate, and crawl limits. Dalfox/sqlmap accept only explicit candidate files and ffuf accepts only a bounded wordlist. HexStrike policy status is separate from local tool status.
