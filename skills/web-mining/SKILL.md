---
name: web-mining
description: Execute bounded local Web/API vulnerability-mining profiles with immutable run artifacts, candidate normalization, and reproducible validation.
version: 3.0.0
metadata:
  hermes:
    tags: [web, api, evidence, profiles]
---
# Web Mining v3

Set `WEB_VULN_MINING_ROOT` to the repository root. Select exactly one profile declared in `scopes/PROJECT.yaml`.

```bash
python "$WEB_VULN_MINING_ROOT/scripts/preflight.py" --json --required-profiles web-baseline
python "$WEB_VULN_MINING_ROOT/scripts/run_profile.py" "$WEB_VULN_MINING_ROOT/scopes/PROJECT.yaml" --profile web-baseline
python "$WEB_VULN_MINING_ROOT/scripts/normalize_results.py" RUN_DIR
python "$WEB_VULN_MINING_ROOT/scripts/create_report.py" RUN_DIR
```

Profiles: `source`, `web-baseline`, `api`, `verify-xss`, `verify-sqli`, `content-discovery`, and explicit `active-dns-discovery`.

`active-dns-discovery` calls Nmap only for DNS-brute candidate collection under explicit roots. It writes `asset-candidates.json`; it does not add Web targets or start HTTP, port, directory, or vulnerability scans. Add an approved candidate to a new manifest before follow-up work.

Each run preserves the scope snapshot, command logs, raw output, local status, optional HexStrike status, normalized summary, and report. Scan output is a candidate, not a confirmed finding.
