---
name: web-vuln-mining
description: Portable Web/API vulnerability-mining workbench launcher.
version: 0.1.0
platforms: [windows, linux]
metadata:
  hermes:
    requires:
      bins: [python]
      env: [WEB_VULN_MINING_ROOT]
---
# Web Vulnerability Mining
On a new clone run `python $WEB_VULN_MINING_ROOT/scripts/preflight.py --repair --json --check-policy`; later checks stay read-only. Limit work to exact hosts and budgets in TARGET.yaml. `verify-xss` and `verify-sqli` require an explicit candidate file; `content-discovery` requires a bounded wordlist. HexStrike is an independent policy/audit component.
