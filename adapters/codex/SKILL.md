---
name: web-vuln-mining
description: Run portable local Web and API vulnerability mining for source repositories, websites, OpenAPI, and GraphQL services. Use for SQL injection, XSS, IDOR, authentication, authorization, SSRF, uploads, path traversal, redirects, dependency risks, Web DAST, and API property testing. Do not use host, port, cloud, wireless, or operating-system assessment.
---
# Web Vulnerability Mining
Set `WEB_VULN_MINING_ROOT` to the cloned repository root, then run:
```powershell
python $env:WEB_VULN_MINING_ROOT\scripts\preflight.py --json --check-policy
python $env:WEB_VULN_MINING_ROOT\scripts\run_profile.py $env:WEB_VULN_MINING_ROOT\scopes\PROJECT.yaml --profile web-baseline
```
Use `source`, `web-baseline`, or `api` only. Normalize and report each completed run. HexStrike is optional for local profile completion; report its status independently.
