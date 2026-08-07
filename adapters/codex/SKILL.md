---
name: web-mining
description: Run portable local Web and API vulnerability mining for source repositories, websites, OpenAPI, and GraphQL services with bounded evidence-first profiles.
---
# Web Mining

Set `WEB_VULN_MINING_ROOT` to the cloned repository root, then run `preflight.py --json --check-policy` and a single declared Profile. Use `source`, `web-baseline`, `api`, `verify-xss`, `verify-sqli`, `content-discovery`, or explicit `active-dns-discovery`. DNS discovery emits candidates only; add an approved hostname and URL to a new scope before Web work. HexStrike status is optional and separate from local completion.
