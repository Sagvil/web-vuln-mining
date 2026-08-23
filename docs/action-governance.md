# Web-Mining Action Governance

`scripts/run_profile.py` records a deterministic policy decision for every
non-validation run. The default is `--governance-mode shadow`: the decision is
written but does not change the existing profile execution path. It is intended
to replay and review evidence before enforcement is enabled.

## Artifacts

Each run contains `governance/decision.json`, `governance/action-ledger.jsonl`,
and `governance/evidence-index.json`. A supplied contract is copied to
`governance/contract.json`. The ledger distinguishes a policy decision from an
execution receipt; it deliberately records no model reasoning or credentials.
The runner does not label a profile result as independently verified.

## Enforce mode

Use enforcement only with an exact, human-approved JSON Action Contract:

```bash
python scripts/run_profile.py scopes/local-lab.yaml \
  --profile verify-sqli \
  --governance-mode enforce \
  --governance-contract contracts/local-lab-001.json
```

Before any profile tool is started, enforce mode checks: active status,
expiration, exact scope SHA-256, profile, action class, target count, and rate
limit. Missing or mismatched authority returns exit code `4` and writes a
`blocked-policy` manifest. An explicitly skipped profile returns `DENY`.

`contracts/action-contract.example.json` is a template only. Copy it, set the
scope SHA-256 after the scope has been approved, and give it a short validity
window. A previous contract must not be reused after a target, scope, profile,
or budget change.

## Review boundary

This mechanism governs only the runner's profile invocation. It does not
authorize a human terminal command, submit to vulnerability platforms, use
credentials, or turn candidate scan output into a confirmed finding. Continue
to use the existing normalization, triage, and manual review gates.
