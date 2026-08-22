# Web Vulnerability Mining Workbench

[中文文档](README.zh-CN.md)

## Goal

This project provides a portable, version-locked local workbench for Web applications and Web APIs. It produces static and passive **candidates** for SQL injection, XSS, SSRF, uploads, path traversal, redirects, dependency risks, and API input-validation defects. IDOR, authorization, and business-logic signals are review heuristics only, never an automated vulnerability conclusion. Host, port, cloud, wireless, and operating-system scanning are outside the project scope. The explicit `active-dns-discovery` Profile is a DNS-only candidate inventory exception; it does not perform port or HTTP scanning.

## How it works

1. A `TARGET.yaml` manifest defines the source tree, exact Web/API scope, exclusions, request rate, and crawl budget.
2. The bootstrapper installs pinned tools into a user-owned data directory and verifies release hashes.
3. A selected profile runs source analysis, Web baseline discovery, or schema-driven API tests.
4. Raw outputs, redacted SARIF, normalized schema-v2 evidence, bilingual review material, and manual-only platform drafts are saved under one immutable run directory.
5. HexStrike is an optional, independent remote policy/audit and recheck component; `LOCAL_TOOL_STATUS` and `HEXSTRIKE_STATUS` remain separate.

## Required projects and runtime environment

| Category | Requirement | Purpose |
| --- | --- | --- |
| Operating system | Windows 10/11 x64, Ubuntu/Debian x64, or Ubuntu/Debian ARM64 | Bootstrap platform |
| Prerequisites | Git, Python 3.11+, Java 17, OpenSSH client, `curl`, `tar`, and `unzip` | Repository, Python tools, ZAP, SSH integration, archive handling |
| Package manager | Windows: `winget`; Ubuntu/Debian x64: `apt`; Ubuntu/Debian ARM64: none | ARM64 bootstrap is user-space |
| Source profile | [Gitleaks](https://github.com/gitleaks/gitleaks), [Trivy](https://github.com/aquasecurity/trivy), [Semgrep](https://github.com/semgrep/semgrep), [CodeQL](https://github.com/github/codeql) | Secrets, dependencies, IaC, rules, and data-flow analysis |
| Web profile | [ProjectDiscovery httpx](https://github.com/projectdiscovery/httpx), [Katana](https://github.com/projectdiscovery/katana), [Nuclei](https://github.com/projectdiscovery/nuclei), [OWASP ZAP](https://www.zaproxy.org/) | HTTP inventory, route discovery, local templates, and passive DAST |
| API profile | [Schemathesis](https://github.com/schemathesis/schemathesis), OWASP ZAP | OpenAPI/GraphQL property tests and passive API inspection |
| Candidate verification | [Dalfox](https://github.com/hahwul/dalfox), [sqlmap](https://github.com/sqlmapproject/sqlmap) | Explicit XSS and SQL-injection candidate validation |
| Content discovery | [ffuf](https://github.com/ffuf/ffuf) | Bounded route discovery when crawler coverage is insufficient |
| Optional agents | Codex, [Hermes](https://github.com/NousResearch/hermes-agent), [OpenClaw](https://github.com/openclaw/openclaw) | Skill-based orchestration |
| Optional policy service | Linux host with Python 3, systemd, SSH access, and `sudo` | HexStrike remote policy/audit deployment |

The platform lock files in `config/tool-lock.windows.json`, `config/tool-lock.linux.json`, and `config/tool-lock.linux-arm64.json` use schema v2. They contain a static asset URL and SHA-256, install method, executable path, and platform status. The installer does not fetch checksum manifests, source-build Go binaries, or use mutable Docker tags. It records the installed executable digest, Python wheel `RECORD` verification, and lock digest in `provenance.json`; read-only preflight refuses a Profile when those values do not match. CodeQL and Dalfox are explicitly unavailable on Linux ARM64 rather than silently falling back.

## Install

Clone the repository, set `WEB_VULN_MINING_ROOT` to the clone, then install the pinned local toolchain. Executables are stored in the user data directory rather than the repository.

```powershell
git clone https://github.com/OWNER/web-vuln-mining.git
cd web-vuln-mining
$env:WEB_VULN_MINING_ROOT = $PWD
.\bootstrap\install.ps1 -Profile default -InstallCodexSkill
```

```bash
git clone https://github.com/OWNER/web-vuln-mining.git
cd web-vuln-mining
export WEB_VULN_MINING_ROOT="$PWD"
./bootstrap/install.sh --profile default --install-codex-skill
```

The installer installs only immutable locked assets into an isolated user-owned location, installs Python packages with `pip --require-hashes`, writes `provenance.json`, and runs preflight. It does not use Docker, Go, `uvx --from`, or a mutable release checksum at install time. Use `--dry-run` before an installation. `python scripts/preflight.py --repair --json` is an explicit repair request; ordinary preflight and profile startup are read-only.

## Agent adapters

```powershell
python .\scripts\install_agent.py codex
python .\scripts\install_agent.py hermes
python .\scripts\install_agent.py openclaw
```

Hermes can also install the publishable flat skills from Git: `hermes skills tap add OWNER/web-vuln-mining`, then `hermes skills install web-mining` and `hermes skills install pentest-orchestrator`. OpenClaw can install the root Skill with `openclaw skills install git:OWNER/web-vuln-mining@main --global`.

## Configuration zone

- **Project manifest:** copy `scopes/TARGET.example.yaml` to `scopes/<project>.yaml`.
- **Scope controls:** set exact `include_hosts`, `exclude_paths`, `rate_limit`, `crawl_budget.max_depth`, and `crawl_budget.max_pages` before running a profile.
- **Scope validation:** `run_profile.py` rejects placeholder names, out-of-scope URLs, credential-bearing URLs, unsupported paths, unbounded crawl budgets, and profiles not declared by the manifest.
- **Authentication headers:** set `auth.headers_file` to a UTF-8 text file containing one `Name: value` request header per line when the supported tools need an authenticated context.
- **Versions:** platform locks under `config/tool-lock.*.json` are the pinned executable/package inventory.
- **Private runtime:** copy `config/runtime.example.yaml` to `config/local.runtime.yaml` only when overriding tool locations or a HexStrike bridge.

## Commands

```powershell
$workbench = $PWD
$scope = "$workbench\scopes\PROJECT.yaml"

python "$workbench\scripts\preflight.py" --json --check-policy
python "$workbench\scripts\preflight.py" --repair --json
python "$workbench\scripts\run_profile.py" $scope --profile web-baseline --validate-only
python "$workbench\scripts\run_profile.py" $scope --profile source
python "$workbench\scripts\run_profile.py" $scope --profile web-baseline
python "$workbench\scripts\run_profile.py" $scope --profile api
```

Each command creates an immutable directory under `runs/<timestamp>-<project>-<profile>/`. Then run:

```powershell
python "$workbench\scripts\normalize_results.py" <RUN_DIR>
python "$workbench\scripts\create_report.py" <RUN_DIR>
```

`run_profile.py` invokes a narrowed, read-only preflight immediately before a real profile execution. `--validate-only` checks only scope syntax and never repairs or downloads anything.

## Profiles

- `source`: Gitleaks → Trivy → local Semgrep packs → CodeQL, plus a local CycloneDX SBOM.
- `web-baseline`: ProjectDiscovery `pd-httpx` → Katana → local GET/HEAD-only Nuclei rules → loopback-only, API-keyed ZAP passive scan.
- `api`: Schemathesis → downloaded in-scope schema only → offline OpenAPI lint (no external `$ref`/`servers` fetching) → loopback-only ZAP passive scan.
- `verify-xss`: Dalfox against an explicit in-scope candidate URL file supplied by `--input`.
- `verify-sqli`: sqlmap at level 1/risk 1 against an explicit in-scope candidate URL file supplied by `--input`.
- `content-discovery`: ffuf against a bounded copy of `--wordlist`, without recursion.
- `active-dns-discovery`: explicit Nmap `dns-brute` candidate inventory. It requires `active_dns_discovery` in TARGET.yaml and the system `nmap` binary; it never promotes returned names into HTTP scope.

The three second-batch tools are installed by default but never execute in `source`, `web-baseline`, or `api`. Their profiles must be declared by TARGET.yaml and invoked explicitly:

```powershell
python .\scripts\run_profile.py $scope --profile verify-xss --input .\candidates\xss-urls.txt
python .\scripts\run_profile.py $scope --profile verify-sqli --input .\candidates\sqli-urls.txt
python .\scripts\run_profile.py $scope --profile content-discovery --wordlist .\wordlists\paths.txt --max-requests 300
```

## Coverage matrix and evidence levels

| Area | Automated output | Review heuristic | Explicit validation required |
| --- | --- | --- | --- |
| Python and JavaScript/TypeScript | Local Semgrep rules for injection, dynamic execution, SSRF, paths, deserialization, templates, uploads, crypto, JWT, redirect, and DOM sinks | Authorization/IDOR-shaped object access | Yes; scanner output is a candidate |
| Web baseline | GET/HEAD-only local Nuclei checks for cookie attributes, CORS, cache policy, headers, debug markers, and HTTPS redirects | Header and cache context | Yes; verify behavior and impact manually |
| OpenAPI | Offline lint of already downloaded schema bytes | Auth declaration, sensitive operations, transport, and constraints | Yes; no `$ref` or `servers` requests are followed |
| Submission | Redacted English report, Chinese review summary, SARIF, JSON evidence | None | `triage.yaml`: `reproduced`, `human_reviewed: true`, and `scope_confirmed: true` |

Run `python scripts/create_report.py <RUN_DIR>` after normalization. It writes `report.md`, `review.zh-CN.md`, SARIF/JSON evidence, a starter `triage.yaml`, and `submission/hackerone.md`, `submission/bugcrowd.md`, `submission/intigriti.md`, plus a manual checklist. Drafts contain only the human-reviewed, scope-confirmed reproductions. The workbench never stores platform credentials, calls platform APIs, or submits a report.

ZAP is a local control plane only: the runner fixes the bind address to `127.0.0.1`, creates a new high-entropy API key and temporary session directory for every run, and removes its process and temporary directory on success, timeout, or exception. API keys and ZAP launch commands are intentionally omitted from normal run logs.

## CI guarantees

CI runs `python -m unittest discover -s tests -v` on Linux, Windows, and an ARM64 runner. Actions are pinned by commit SHA in `config/ci-actions.lock.json`, and the ARM64 container is pinned by image digest. CI only uses repository fixtures, temporary directories, and loopback services; it never scans an external target.

## DNS Candidate Discovery

`active-dns-discovery` is disabled unless the manifest declares it. It runs `nmap -sn -n -Pn --script dns-brute` against the explicitly listed parent roots, writes XML, bounded wordlist copies, logs, and `asset-candidates.json`, then stops. DNS candidates are inventory evidence only. Add a reviewed hostname and URL to a new `include_hosts`/`base_urls` manifest before follow-up Web work.

```yaml
profiles: [active-dns-discovery]
active_dns_discovery:
  roots: [example.test]
  wordlist: wordlists/dns-subdomains.txt
  max_words: 10000
  threads: 20
  max_candidates: 5000
```

## HexStrike

HexStrike remains an independent optional policy/audit and remote-recheck component. A local profile does not depend on a HexStrike job. Reports retain `LOCAL_TOOL_STATUS` and `HEXSTRIKE_STATUS` separately.

To deploy the bundled loopback-only remote policy service, copy `config/hexstrike.remote.example.yaml` to the ignored `config/hexstrike.remote.local.yaml`, fill in the SSH fields, then run:

```powershell
.\bootstrap\install.ps1 -WithHexStrike -HexStrikeConfig .\config\hexstrike.remote.local.yaml
python .\scripts\hexstrike_verify.py --config .\config\hexstrike.remote.local.yaml
```

The deployer uploads the packaged HexStrike components, creates the managed `systemd` unit, and verifies `/health` through SSH. SSH credentials, remote addresses, audit logs, and local runtime overrides remain outside Git.
