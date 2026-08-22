---
name: web-mining
description: Hermes compatibility entry for scoped local Web/API mining; canonical publishable skills live under skills/.
version: 4.0.0
platforms: [windows, linux]
metadata:
  hermes:
    config:
      - key: WEB_VULN_MINING_ROOT
        env: [WEB_VULN_MINING_ROOT]
---
# Web Mining

Use the flat `web-mining` skill for local profile execution and `pentest-orchestrator` for routing. Define exact Web/API scope and budgets in `scopes/PROJECT.yaml`; preserve each generated run directory and treat automated output as a candidate. Lock/provenance preflight is mandatory before real execution; `--validate-only` does not repair. `active-dns-discovery` is explicit, DNS-only candidate collection. Submission drafts require `triage.yaml` with reproduced, scope-confirmed, human-reviewed evidence and are never auto-submitted. HexStrike is optional review/audit support and never blocks local Profiles.
