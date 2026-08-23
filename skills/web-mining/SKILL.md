---
name: web-mining
description: Execute bounded local Web/API vulnerability-mining profiles with immutable run artifacts, deterministic governance records, and reproducible validation.
version: 4.1.0
metadata:
  hermes:
    tags: [web, api, evidence, profiles, governance]
---
# Web Mining v4.1

Set `WEB_VULN_MINING_ROOT` to the repository root. Select exactly one real,
approved scope file under `scopes/`; `scopes/PROJECT.yaml` is only an example
placeholder and must not be assumed to exist.

```bash
python "$WEB_VULN_MINING_ROOT/scripts/preflight.py" --json --required-profiles web-baseline
python "$WEB_VULN_MINING_ROOT/scripts/run_profile.py" "$WEB_VULN_MINING_ROOT/scopes/local-lab.yaml" --profile web-baseline
python "$WEB_VULN_MINING_ROOT/scripts/normalize_results.py" RUN_DIR
python "$WEB_VULN_MINING_ROOT/scripts/create_report.py" RUN_DIR
```

Every real run defaults to `--governance-mode shadow`. It writes the bounded
intent, policy decision, tool outcome, and evidence references below the run
directory without changing profile execution. Review shadow evidence before
using enforcement.

`--governance-mode enforce` requires `--governance-contract PATH`. The contract
is an exact, time-limited JSON approval bound to the selected scope SHA-256,
profile, action class, targets, and rate budget. A missing, expired, revoked,
or mismatched contract blocks before profile tools start; a profile listed in
`skipped_profiles` is denied. See `docs/action-governance.md` and
`contracts/action-contract.example.json`. LLM, payment/transfer, external
submission, credential, production, and out-of-scope actions remain excluded
unless separately and explicitly authorized.

Profiles: `source`, `web-baseline`, `api`, `verify-xss`, `verify-sqli`,
`content-discovery`, and explicit `active-dns-discovery`.

`active-dns-discovery` calls Nmap only for DNS-brute candidate collection under
explicit roots. It writes `asset-candidates.json`; it does not add Web targets
or start HTTP, port, directory, or vulnerability scans. Add an approved
candidate to a new scope manifest before follow-up work.

`run_profile.py` invokes profile-scoped read-only integrity preflight before a
real run. `--validate-only` does not invoke preflight repair. Do not bypass a
failed provenance, binary hash, or Python `RECORD` check.

The local Semgrep packs support Python and JavaScript/TypeScript. Local Nuclei
templates use GET/HEAD only. OpenAPI lint parses already-downloaded schema bytes
and does not follow external `$ref` or `servers`. ZAP is an API-keyed loopback-
only control plane; do not put credentials in output or logs.

Each run preserves a scope snapshot, raw local evidence, redacted schema-v2
summary, SARIF, English report, Chinese review summary, manual submission
drafts, and governance records. Scan output is a candidate, not a confirmed
finding. IDOR, authorization, and business logic are review heuristics only. A
platform draft is eligible only when `triage.yaml` records `status: reproduced`,
`human_reviewed: true`, and `scope_confirmed: true`. Never store platform
credentials or call platform submission APIs.
