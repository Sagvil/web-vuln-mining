# Web Vulnerability Mining Workbench

[中文文档](README.zh-CN.md)

## Goal

This project provides a portable, version-locked local workbench for Web applications and Web APIs. It focuses on SQL injection, XSS, IDOR, authentication and authorization issues, SSRF, uploads, path traversal, redirects, dependency risks, and API input-validation defects. Host, port, cloud, wireless, and operating-system scanning are outside the project scope. The explicit `active-dns-discovery` Profile is a DNS-only candidate inventory exception; it does not perform port or HTTP scanning.

## How it works

1. A `TARGET.yaml` manifest defines the source tree, exact Web/API scope, exclusions, request rate, and crawl budget.
2. The bootstrapper installs pinned tools into a user-owned data directory and verifies release hashes.
3. A selected profile runs source analysis, Web baseline discovery, or schema-driven API tests.
4. Raw outputs, SARIF, request evidence, normalized findings, and a Markdown report are saved under one immutable run directory.
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

The platform lock files in `config/tool-lock.windows.json`, `config/tool-lock.linux.json`, and `config/tool-lock.linux-arm64.json` define the supported tool versions. ARM64 installs use a user-owned Python environment and do not require `sudo`; native release assets are verified against their release checksum manifests and missing assets fall back to a locked Go source build. CodeQL is platform-disabled on Linux ARM64 and is replaced by local Semgrep taint rules; no AMD64 emulation is used.

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

The installer installs all twelve pinned tools, verifies hashes, creates an installation state file, and runs preflight. On ARM64 it uses the existing Python, Java, Docker, and Go runtimes without `apt` or `sudo`. Use `--dry-run` before an installation. On an existing clone, `python scripts/preflight.py --repair --json` explicitly repairs missing or damaged tools; preflight without `--repair` remains read-only.

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

## Profiles

- `source`: Gitleaks → Trivy → Semgrep → CodeQL.
- `web-baseline`: ProjectDiscovery `pd-httpx` → Katana → local Nuclei rules → loopback-only ZAP passive scan.
- `api`: Schemathesis → ZAP OpenAPI import and passive scan; skips cleanly when no in-scope schema exists.
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
