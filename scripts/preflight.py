"""Check the Web/API and explicit DNS-candidate toolchain before a profile run."""
from __future__ import annotations

import argparse
import concurrent.futures
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

from common import WORKBENCH_ROOT, command_for, data_root, load_json, platform_lock_path, runtime_settings, write_json

# ============================ Configuration zone ============================
# CORE_TOOLS: default Web/API tool set installed by Bootstrap. System Nmap is
# intentionally excluded because active-dns-discovery is opt-in.
CORE_TOOLS = ['semgrep', 'codeql', 'trivy', 'gitleaks', 'pd-httpx', 'katana', 'nuclei', 'zap', 'schemathesis', 'dalfox', 'sqlmap', 'ffuf']
# PROFILE_TOOLS maps portable, locked tools to an execution profile.
PROFILE_TOOLS = {
    'source': ['gitleaks', 'trivy', 'semgrep', 'codeql'],
    'web-baseline': ['pd-httpx', 'katana', 'nuclei', 'zap'],
    'api': ['schemathesis', 'zap'],
    'verify-xss': ['dalfox'],
    'verify-sqli': ['sqlmap'],
    'content-discovery': ['ffuf'],
    'active-dns-discovery': [],
}
# SYSTEM_PROFILE_BINARIES are checked only when the named profile is requested.
SYSTEM_PROFILE_BINARIES = {'active-dns-discovery': ['/usr/bin/nmap']}
# VERSION_PROBE_* bound only local version probing, not any assessment command.
VERSION_PROBE_TIMEOUT_SECONDS = 12
MAX_VERSION_PROBE_WORKERS = 6
VERSION_ARGS = {
    'semgrep': ['--version'], 'codeql': ['version'], 'trivy': ['--version'], 'gitleaks': ['version'],
    'pd-httpx': ['-version'], 'katana': ['-version'], 'nuclei': ['-version'], 'dalfox': ['--version'],
    'sqlmap': ['--batch', '--version'], 'ffuf': ['-V'],
}
# ============================================================================


def policy_bridge() -> Path | None:
    configured = os.environ.get('WEB_VULN_MINING_HEXSTRIKE_BRIDGE', '').strip() or str(runtime_settings().get('hexstrike_bridge') or '').strip()
    return Path(configured).expanduser() if configured else None


def runtime_dependencies(bridge: Path | None) -> list[dict[str, object]]:
    names = ['yaml', 'requests']
    if bridge:
        names.append('mcp')
    return [{'name': name, 'present': importlib.util.find_spec(name) is not None} for name in names]


def repair_toolchain(names: list[str]) -> dict[str, object]:
    if os.name == 'nt':
        command = ['powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', str(WORKBENCH_ROOT / 'bootstrap' / 'install.ps1'), '-Repair', '-OnlyTools', ','.join(names)]
    else:
        command = ['bash', str(WORKBENCH_ROOT / 'bootstrap' / 'install.sh'), '--repair', '--only-tools', ','.join(names)]
    result = subprocess.run(command, cwd=WORKBENCH_ROOT, capture_output=True, text=True, encoding='utf-8', errors='replace')
    return {'command': command, 'returncode': result.returncode, 'stdout': result.stdout, 'stderr': result.stderr, 'status': 'completed' if result.returncode == 0 else 'failed'}


def actual_version(name: str, command: list[str] | None, expected: str) -> str | None:
    if not command or name not in VERSION_ARGS:
        return None
    try:
        result = subprocess.run(command + VERSION_ARGS[name], input='', capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=VERSION_PROBE_TIMEOUT_SECONDS)
    except (OSError, subprocess.TimeoutExpired):
        return None
    ansi = re.compile(r'\x1b\[[0-9;]*m')
    lines = [ansi.sub('', line).strip() for line in (result.stdout + '\n' + result.stderr).splitlines() if line.strip()]
    return next((line for line in lines if expected in line), lines[0] if lines else None)


def inspect_tools(required: list[str], lock: dict[str, object]) -> tuple[list[dict[str, object]], list[str], list[str]]:
    tools: list[dict[str, object]] = []
    missing: list[str] = []
    repair_targets: list[str] = []
    records = lock.get('tools', {}) if isinstance(lock.get('tools'), dict) else {}
    for name in required:
        record = records[name]
        if record.get('kind') == 'platform-disabled':
            tools.append({'name': name, 'locked_version': None, 'actual_version': None, 'present': False, 'command': None, 'source': record.get('kind'), 'disabled_reason': record.get('reason', 'platform-disabled')})
            continue
        command = command_for(name)
        present = command is not None and (name == 'schemathesis' or all(Path(part).exists() for part in command if part.lower().endswith(('.exe', '.py', '.bat', '.sh'))))
        locked_version = str(record['version'])
        tools.append({'name': name, 'locked_version': locked_version, 'actual_version': None, 'present': present, 'command': command, 'source': record.get('url') or record.get('kind')})
        if not present:
            missing.append(name)
            repair_targets.append(name)
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_VERSION_PROBE_WORKERS) as executor:
        futures = {executor.submit(actual_version, str(item['name']), item['command'], str(item['locked_version'])): item for item in tools if item['present']}
        for future, item in futures.items():
            found_version = future.result()
            item['actual_version'] = found_version
            if found_version is not None and str(item['locked_version']) not in found_version:
                repair_targets.append(str(item['name']))
    return tools, missing, repair_targets


def inspect_system_binaries(profiles: set[str]) -> tuple[list[dict[str, object]], list[str]]:
    """Check explicit system paths without letting bootstrap manage those packages."""
    binaries = list(dict.fromkeys(binary for profile in profiles for binary in SYSTEM_PROFILE_BINARIES.get(profile, [])))
    rows: list[dict[str, object]] = []
    for binary in binaries:
        candidate = Path(binary)
        if candidate.is_absolute():
            present = candidate.is_file() and os.access(candidate, os.X_OK)
            path = str(candidate) if present else None
            name = candidate.name
        else:
            path = shutil.which(binary)
            present = bool(path)
            name = binary
        rows.append({'name': name, 'present': present, 'path': path, 'source': 'system-dependency'})
    return rows, [str(row['name']) for row in rows if not row['present']]


try:
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
except AttributeError:
    pass


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--json', action='store_true')
    parser.add_argument('--check-policy', action='store_true')
    parser.add_argument('--repair', action='store_true', help='install or repair locked Web/API tools; system dependencies remain operator-managed')
    parser.add_argument('--required-profiles', nargs='+', choices=sorted(PROFILE_TOOLS), help='report only tools required by these profiles')
    args = parser.parse_args()
    lock = load_json(platform_lock_path())
    requested_profiles = set(args.required_profiles or PROFILE_TOOLS.keys() - {'active-dns-discovery'})
    required = list(dict.fromkeys(tool for profile in requested_profiles for tool in PROFILE_TOOLS[profile])) if args.required_profiles else CORE_TOOLS
    tools, missing, repair_targets = inspect_tools(required, lock)
    system_tools, missing_system_tools = inspect_system_binaries(requested_profiles)
    bridge = policy_bridge()
    preliminary_dependencies = runtime_dependencies(bridge if args.check_policy else None)
    preliminary_prerequisites = [{'name': name, 'present': shutil.which(name) is not None} for name in ('git', 'java', 'ssh')]
    required_prerequisites = ({'git'} if 'source' in requested_profiles else set()) | ({'java'} if requested_profiles & {'web-baseline', 'api'} else set()) | ({'ssh'} if args.check_policy and bridge else set())
    if any(not item['present'] for item in preliminary_dependencies) or any(not item['present'] and item['name'] in required_prerequisites for item in preliminary_prerequisites):
        repair_targets.append('runtime')
    repair_targets = list(dict.fromkeys(repair_targets))
    repair = repair_toolchain(repair_targets) if args.repair and repair_targets else {'status': 'not-needed', 'tools': []} if args.repair else None
    if args.repair and repair_targets and repair and repair['status'] == 'completed':
        tools, missing, remaining = inspect_tools(required, lock)
        repair['remaining'] = remaining
    dependencies = runtime_dependencies(bridge if args.check_policy else None)
    missing_dependencies = [str(item['name']) for item in dependencies if not item['present']]
    prerequisites = [{'name': name, 'present': shutil.which(name) is not None} for name in ('git', 'java', 'ssh')]
    missing_prerequisites = [str(item['name']) for item in prerequisites if not item['present'] and item['name'] in required_prerequisites]
    result = {
        'workbench': str(WORKBENCH_ROOT), 'data_root': str(data_root()), 'lock': str(platform_lock_path()),
        'required_profiles': args.required_profiles or 'default-web-api', 'tools': tools, 'missing': missing,
        'system_tools': system_tools, 'missing_system_tools': missing_system_tools,
        'runtime_dependencies': dependencies, 'missing_runtime_dependencies': missing_dependencies,
        'system_prerequisites': prerequisites, 'missing_system_prerequisites': missing_prerequisites,
        'hexstrike_policy_bridge': bridge.exists() if args.check_policy and bridge else False if args.check_policy else None,
        'repair': repair,
    }
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        for item in tools + system_tools:
            print(f"{item['name']}: {'OK' if item['present'] else 'MISSING'}")
        if args.check_policy:
            print(f"hexstrike-policy: {'OK' if bridge and bridge.exists() else 'MISSING'}")
    write_json(WORKBENCH_ROOT / 'runs' / 'preflight-latest.json', result)
    return 0 if not missing and not missing_system_tools and not missing_dependencies and not missing_prerequisites and (repair is None or repair['status'] in {'completed', 'not-needed'}) else 2


if __name__ == '__main__':
    sys.exit(main())
