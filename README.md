# Web Vulnerability Mining Workbench

This workbench is limited to Web applications and Web APIs. It coordinates source review, HTTP inventory, route crawling, template-driven checks, passive DAST, and OpenAPI property tests. It does not run host, port, cloud, wireless, or operating-system scanners.

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

The installer uses the platform package manager for prerequisites, downloads pinned releases, verifies hashes, creates an installation state file, and runs preflight. Use `--dry-run` before an installation to inspect prerequisite actions.

## Agent adapters

```powershell
python .\scripts\install_agent.py codex
python .\scripts\install_agent.py hermes
python .\scripts\install_agent.py openclaw
```

Hermes can also install from Git: `hermes skills tap add https://github.com/OWNER/web-vuln-mining.git` then `hermes skills install web-vuln-mining`. OpenClaw can install the root Skill with `openclaw skills install git:OWNER/web-vuln-mining@main --global`.

## Configuration zone

- **Project manifest:** copy `scopes/TARGET.example.yaml` to `scopes/<project>.yaml`.
- **Scope controls:** set exact `include_hosts`, `exclude_paths`, `rate_limit`, `crawl_budget.max_depth`, and `crawl_budget.max_pages` before running a profile.
- **Authentication headers:** set `auth.headers_file` to a UTF-8 text file containing one `Name: value` request header per line when the supported tools need an authenticated context.
- **Versions:** platform locks under `config/tool-lock.*.json` are the pinned executable/package inventory.
- **Private runtime:** copy `config/runtime.example.yaml` to `config/local.runtime.yaml` only when overriding tool locations or a HexStrike bridge.

## Commands

```powershell
$workbench = $PWD
$scope = "$workbench\scopes\PROJECT.yaml"

python "$workbench\scripts\preflight.py" --json --check-policy
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

`verify-xss`, `verify-sqli`, and `content-discovery` are reserved for candidate-specific Dalfox, sqlmap, and ffuf workflows. They are intentionally not part of the default profiles.

## HexStrike

HexStrike remains an independent optional policy/audit and remote-recheck component. A local profile does not depend on a HexStrike job. Reports retain `LOCAL_TOOL_STATUS` and `HEXSTRIKE_STATUS` separately.

To deploy the bundled loopback-only remote policy service, copy `config/hexstrike.remote.example.yaml` to the ignored `config/hexstrike.remote.local.yaml`, fill in the SSH fields, then run:

```powershell
.\bootstrap\install.ps1 -WithHexStrike -HexStrikeConfig .\config\hexstrike.remote.local.yaml
python .\scripts\hexstrike_verify.py --config .\config\hexstrike.remote.local.yaml
```

The deployer uploads the packaged HexStrike components, creates the managed `systemd` unit, and verifies `/health` through SSH. SSH credentials, remote addresses, audit logs, and local runtime overrides remain outside Git.
