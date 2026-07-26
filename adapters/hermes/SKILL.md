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
Run `python $WEB_VULN_MINING_ROOT/scripts/preflight.py --json --check-policy` before a profile. Limit work to the exact hosts and budgets in TARGET.yaml. Use `source`, `web-baseline`, and `api`; HexStrike is an independent policy/audit component.
