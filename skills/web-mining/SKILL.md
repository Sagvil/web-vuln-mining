---
name: web-mining
description: Execute bounded local Web/API vulnerability-mining profiles with immutable run artifacts, candidate normalization, and reproducible validation.
version: 4.0.0
metadata:
  hermes:
    tags: [web, api, evidence, profiles]
---
# Web Mining v4

Set `WEB_VULN_MINING_ROOT` to the repository root. Select exactly one profile declared in `scopes/PROJECT.yaml`.

```bash
python "$WEB_VULN_MINING_ROOT/scripts/preflight.py" --json --required-profiles web-baseline
python "$WEB_VULN_MINING_ROOT/scripts/run_profile.py" "$WEB_VULN_MINING_ROOT/scopes/PROJECT.yaml" --profile web-baseline
python "$WEB_VULN_MINING_ROOT/scripts/normalize_results.py" RUN_DIR
python "$WEB_VULN_MINING_ROOT/scripts/create_report.py" RUN_DIR
```

Profiles: `source`, `web-baseline`, `api`, `verify-xss`, `verify-sqli`, `content-discovery`, and explicit `active-dns-discovery`.

`active-dns-discovery` calls Nmap only for DNS-brute candidate collection under explicit roots. It writes `asset-candidates.json`; it does not add Web targets or start HTTP, port, directory, or vulnerability scans. Add an approved candidate to a new manifest before follow-up work.

`run_profile.py` invokes profile-scoped read-only integrity preflight before a real run. `--validate-only` does not invoke preflight repair. Do not bypass a failed provenance, binary hash, or Python `RECORD` check.

The local Semgrep packs support Python and JavaScript/TypeScript. Local Nuclei templates use GET/HEAD only. OpenAPI lint parses already-downloaded schema bytes and does not follow external `$ref` or `servers`. ZAP is an API-keyed loopback-only control plane; do not put credentials in output or logs.

Each run preserves a scope snapshot, raw local evidence, redacted schema-v2 summary, SARIF, English report, Chinese review summary, and manual submission drafts. Scan output is a candidate, not a confirmed finding. IDOR, authorization, and business logic are review heuristics only. A platform draft is eligible only when `triage.yaml` records `status: reproduced`, `human_reviewed: true`, and `scope_confirmed: true`. Never store platform credentials or call platform submission APIs.
