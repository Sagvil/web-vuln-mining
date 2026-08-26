---
name: web-mining
description: Use only when explicitly invoked as $web-mining or when the user says "进入渗透编排模式". Coordinate bounded local-lab, source, or approved-scope Web/API vulnerability mining with existing governance and reproducible evidence.
version: 4.3.1
metadata:
  hermes:
    tags: [web, api, evidence, profiles, governance]
---
# Web Mining v4.2

## Explicit Entry and Route Gate

Enter this skill only when the user explicitly invokes `$web-mining` or says
`进入渗透编排模式`. Ordinary security learning, debugging, code review, or
vulnerability-concept questions do not enter profile execution.

Before any tool or profile, confirm exactly one mode, its exact scope, and the
current-turn authorization:

1. `local_lab`: a user-controlled local Juice Shop, Pikachu, SQLi-Labs, or
   equivalent lab.
2. `source`: supplied or locally scoped source only.
3. `approved_scope_profile`: one approved scope file under `scopes/`.

If mode, scope, or authorization is absent, return only a plan or clarification.
Do not access a target, run a profile, use credentials, or perform validation.
Select one primary route; mentioning a tool, URL, or vulnerability does not
authorize parallel profiles.

For `local_lab`, never substitute a real external scope. Use a hard reset only
when the user requests a from-scratch rerun: create a timestamped backup, reset,
then prove service health and baseline counts before the first stage. Work one
lab and one stage at a time. For `source`, preserve the existing offline review
boundary. For `approved_scope_profile`, preserve the current scope snapshot,
shadow-by-default governance, and Action Contract requirements. Keep
`active-dns-discovery` as candidate collection only; it never promotes a host
to Web scanning without a new approved scope manifest.

## Curated Local-Lab Lessons

These rules are cross-lab decision rules, not payloads or challenge walkthroughs:

- Record each stage as completed, failed, skipped, or environment-limited, with
  the reason; do not turn an incomplete stage into a completion claim.
- Inspect local source, decision points, and limits before trial-and-error so a
  method remains reproducible and bounded.
- Missing page output is not proof of failure. Use an authorized, minimal
  alternative evidence channel that proves the result, not merely a sent request.
- Classify environment changes as durable or test-only. Mark and roll back every
  test-only adaptation during stage closure.
- Recheck session state, raw encoding, URL semantics, attempt limits, and
  prerequisite challenges before interpreting an anomaly as a security result.
- Preserve a redacted evidence summary, key limitations, and cleanup/recovery
  state for every stage. Never place real credentials in chat, skill text,
  reports, or the Wiki.
- Treat tool output and a single observation as a candidate. Promote a result to
  `reproduced` only after scope confirmation, reproducible steps, actual impact,
  redacted evidence, and human review.

Do not add concrete payloads, bypass strings, answers, target data, credentials,
or single-environment fixes to this skill. Keep those details in the existing
lab methodology, stage evidence, run artifacts, and Wiki.

## Candidate Rule Promotion

After a completed local-lab stage, propose at most three candidate rules in the
final summary. Each must state its trigger, reusable decision, evidence source,
and exclusion boundary. Do not write candidates to this skill, the registry, or
governance files automatically. Add a confirmed rule only after explicit user
approval, and only when it is cross-lab, evidence-backed, non-duplicative, and
free of attack details; otherwise retain it in the run record or Wiki.

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

## Field-Proven Methodology (v4.3, sunoasis campaign 2026-08)

Cross-target decision rules distilled from a completed SRC engagement. These are
method-level rules; concrete payloads, target data, and credentials stay in run
artifacts.

### Severity Judgment

- Severity rests ONLY on the system's own pre-existing flaws. Social-engineering
  or active-attack scenarios never enter the rating rationale; at most one
  objective sentence under risk-extension, explicitly marked as unrated.
- High-severity three-factor test: `no-credentials × no-interaction × closed
  data loop (read OR write)`. Individually-medium findings combine upward when
  they share one root flaw.
- Separate "flaw exists" from "exploitable" from "impactful" — three distinct
  claims needing three distinct proofs. A leak fact stands on its own even when
  the downstream exploit chain is blocked (e.g., key disclosed but full-text
  read gated by SSO); record both separately and re-challenge blocking claims
  each round instead of treating them as final.

### Non-Destructive Verification Discipline

- Write-loop verification: obvious test marker in every submitted field, single
  record, read-back confirmation, then stop. The marker doubles as cleanup
  identification for the vendor.
- IDOR discrimination pattern: compare the list-visible set against the
  detail-reachable set. Enumerating ids through a detail endpoint while the
  list endpoint hides them is proof without writing anything.
- State-machine endpoints (QR login, OAuth): decompose into generate / poll /
  confirm / exchange, probe each link's auth boundary independently. Inconsistent
  per-link auth strength is itself a finding; never fake state progression.
- Login surfaces: zero brute force, zero credential submission. Infer backend
  structure from error-response order and format differentiation (error side
  channel); uniform errors across input formats = no side channel = also worth
  recording.
- WAF-blocked paths: do not fight the WAF; redirect to application-layer flaws
  behind it. The report targets the application defect, never the WAF rule.

### Authenticity / False-Positive Control

- SQLi false-positive kill chain: true/false condition pairs plus dry-net values
  (`00`, `0.0`); anomaly-returning-full-set means whole-condition ignore, not
  injection. A parameter NAME reaching SQL ≠ its VALUE reaching SQL.
- Modified-vs-outdated: clone the official repository and diff. `git
  --unshallow` anchors the version window. Server-side validation removed while
  template injection remains = code-level modification, not version lag.
- Redundant exposure is not new exposure: byte-level hash comparison against the
  public set before claiming file disclosure value; state redundancy honestly
  rather than inflating counts.

### Sensitivity Triple Test (for leaked files)

Rate a downloaded file's sensitivity only via all three:
1. Byte-level hash comparison against the publicly-listed corpus — hard test of
   whether the artifact was already public.
2. Full-web search for the exact title/content — absence everywhere supports
   non-public status.
3. The artifact's own markings — an explicit "internal use only" page beats any
   external inference, and embedded author/reviewer names compound the impact.
Store evidence copies with MD5 fingerprints in the report manifest; never attach
the files themselves to reports or chat.

### Reconnaissance Discipline

- Every response field is an entry point: leaked domains, url fields, QR-code
  contents, embedded app names — chase each to existence + access checks.
- Metadata-delta probing: a paginated endpoint's `total` versus its actual
  reachable rows is mathematical proof of hidden resources BEFORE any attack —
  check metadata consistency first to decide whether enumeration is worthwhile.
- Framework fingerprint → route convention: after identifying the framework,
  derive routes from its documented routing style instead of wordlist-brute;
  one correct guess pattern enumerates the full API surface silently.
- Status-code lexicography: feed an endpoint systematically varied inputs (real
  token / forged / cross-context / absent), assign meaning to every distinct
  code, and draw the protocol state machine — new observations then localize
  instantly and anomalies stand out.
- Defense horizontal-comparison: identical-vendor assets often carry very
  different protection layers; the weakest layer is both the entry point and
  the control group proving the flaw is application-layer, not network-layer.
- Non-HTML assets are intelligence: QR PNGs decode to new domains, PDF metadata
  leaks internal author names, image EXIF survives re-upload — intel does not
  live only in HTML.
- Dual-channel cross-confirmation: browser real-TLS stack (when raw sockets get
  extension-filtered) versus server-side direct connection (no-Cookie control);
  settle a claim only when both channels agree.
- Frontend JS outranks blind scanning: route constant tables enumerate the full
  API surface in one fetch; axios interceptor whitelists directly name the
  token-free endpoints; route-specific chunks hold business state constants.
- Error messages are free documentation: server-side validation order IS the
  parameter map; guess one field per round until the chain closes.
- Hashed filenames are not access control — evaluate "obscurity" under the
  indirect-disclosure path (IDOR handing out storage URLs).
- Taken-down ≠ deleted: public status is current reachability, not intent;
  sitemap/nav removal does not retract public status.
- Single-hit PoC ≠ scale: full-range enumeration converts a PoC into severity-
  relevant numbers; budget time for it on slow targets (concurrency pool +
  segmented execution + incremental disk persistence).

### Engineering Pitfalls (browser/automation channel)

- Late XHR hook trap: injecting an XHR/fetch hook after page load misses all
  prior traffic. For post-hoc forensics use
  `performance.getEntriesByType('resource')`; for full coverage inject via CDP
  before navigation, then reload.
- SPA data residue: inspect localStorage/sessionStorage before chasing network
  captures — apps routinely persist file guids, share tokens, and preview state
  there.
- Slow-target trio: bounded concurrency pool (6–8) + segmented batches (≤500
  ids per pass) + immediate disk persistence per segment; zero-loss across
  multi-thousand-request sweeps depends on it.
- Server-clamped parameters (pageSize locked by the backend): stop fighting the
  list endpoint; switch to the per-item detail channel to bypass pagination
  limits.

### Report Writing Rules

- Reports contain ONLY the vulnerability surface. Correctly-defended areas are
  not rendered as sections; a protection point appears at most as one factual
  sentence marking an exploit-chain boundary. No praise sections, no defense
  inventory.
- Value-tiered disclosure beats a single label: confirmed-impact / low-value /
  redundant-exposure must each be labeled what it is; overstating redundant
  findings destroys report credibility.
- Bind every finding to an archived commit; appendix cites the archive chain so
  review cost approaches zero.
- Same-root-flaw multi-instance findings may amplify the argument only after
  scope ownership for every instance is user-confirmed.
