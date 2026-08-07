"""Synchronize web-mining v3 into a Hermes runtime with backup and rollback."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from common import WORKBENCH_ROOT

# ============================ Configuration zone ============================
# HERMES_HOME_ENV / HEXSTRIKE_POLICY_ROOT_ENV target an isolated runtime in
# tests or a separate server without editing repository files.
HERMES_HOME_ENV = 'HERMES_HOME'
HEXSTRIKE_POLICY_ROOT_ENV = 'HEXSTRIKE_POLICY_ROOT'
# RUNTIME_SKILLS are installed as first-level directories for Hermes discovery.
RUNTIME_SKILLS = ('web-mining', 'pentest-orchestrator', 'pentest-hexstrike-executor')
# LEGACY_NESTED_SKILL is archived after canonical flat web-mining is installed.
LEGACY_NESTED_SKILL = Path('skills/pentest/web-mining')
# BACKUP_PREFIX identifies only backups owned by this synchronizer.
BACKUP_PREFIX = 'web-mining-v3-'
# ============================================================================


def utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')


def sha256(path: Path) -> str | None:
    if not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open('rb') as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def copy_path(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists() or destination.is_symlink():
        if destination.is_dir() and not destination.is_symlink():
            shutil.rmtree(destination)
        else:
            destination.unlink()
    if source.is_dir():
        shutil.copytree(source, destination)
    else:
        shutil.copy2(source, destination)


def remove_path(path: Path) -> None:
    if path.is_dir() and not path.is_symlink():
        shutil.rmtree(path)
    elif path.exists() or path.is_symlink():
        path.unlink()


def snapshot(backup: Path, targets: list[Path]) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for index, target in enumerate(targets):
        existed = target.exists() or target.is_symlink()
        entry: dict[str, Any] = {'target': str(target), 'exists': existed, 'backup': None}
        if existed:
            relative = Path('paths') / str(index)
            copy_path(target, backup / relative)
            entry['backup'] = str(relative)
        entries.append(entry)
    return entries


def remove_disabled_skill(config_path: Path, skill: str) -> None:
    """Remove exactly one item under skills.disabled without reformatting config."""
    current = config_path.read_text(encoding='utf-8') if config_path.exists() else ''
    lines = current.splitlines(keepends=True)
    output: list[str] = []
    skills_indent: int | None = None
    disabled_indent: int | None = None
    found_skills = False
    found_disabled = False
    for line in lines:
        stripped = line.strip()
        indent = len(line) - len(line.lstrip(' '))
        if stripped == 'skills:' and not line.lstrip().startswith('#'):
            skills_indent, disabled_indent, found_skills = indent, None, True
        elif skills_indent is not None and indent <= skills_indent and stripped and not line.lstrip().startswith('#'):
            skills_indent, disabled_indent = None, None
        if skills_indent is not None and stripped == 'disabled:' and indent > skills_indent:
            disabled_indent, found_disabled = indent, True
            output.append(line)
            continue
        if disabled_indent is not None and indent <= disabled_indent and stripped and not line.lstrip().startswith('#'):
            disabled_indent = None
        if disabled_indent is not None and stripped == f'- {skill}':
            continue
        output.append(line)
    if not found_skills:
        if output and not output[-1].endswith('\n'):
            output[-1] += '\n'
        output += ['\nskills:\n', '  disabled: []\n']
    elif not found_disabled:
        for index, line in enumerate(output):
            if line.strip() == 'skills:':
                output.insert(index + 1, '  disabled: []\n')
                break
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(''.join(output), encoding='utf-8')


def inventory_skills(skills_root: Path) -> set[str]:
    if not skills_root.is_dir():
        return set()
    return {child.name for child in skills_root.iterdir() if child.is_dir() and not child.name.startswith('.') and ((child / 'SKILL.md').is_file() or (child / 'DESCRIPTION.md').is_file())}


def classify_skill(name: str, prior: dict[str, str]) -> str:
    """Apply v3 registry governance before retaining an unrelated prior category."""
    if name == 'zhouyi-divination':
        return 'personal/traditional-culture'
    if name.endswith('-history-ingest') or name == 'agent-history-ingest':
        return 'history'
    if name in {'claude-code-router', 'memory-governance'}:
        return 'system'
    if name.startswith('pentest-') or name.startswith('butian-') or name in {'authorized-web-assessment-gate', 'web-mining', 'pentest-orchestrator'}:
        return 'pentest'
    return prior.get(name, 'system')


def _yaml_mapping(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        value = yaml.safe_load(path.read_text(encoding='utf-8')) or {}
    except (OSError, yaml.YAMLError):
        return {}
    return value if isinstance(value, dict) else {}


def disabled_skills(config_path: Path) -> set[str]:
    """Read only skills.disabled so comments or unrelated keys do not affect check."""
    config = _yaml_mapping(config_path)
    skills = config.get('skills', {})
    disabled = skills.get('disabled', []) if isinstance(skills, dict) else []
    return {str(item) for item in disabled} if isinstance(disabled, list) else set()


def _registry_membership(path: Path) -> tuple[dict[str, str], bool]:
    payload = _yaml_mapping(path)
    categories = payload.get('categories', {})
    members: dict[str, str] = {}
    duplicate = False
    if not isinstance(categories, dict):
        return members, True
    for category, names in categories.items():
        if not isinstance(names, list):
            duplicate = True
            continue
        for name in names:
            normalized = str(name)
            if normalized in members:
                duplicate = True
            members[normalized] = str(category)
    return members, duplicate


def registry_check(skills_root: Path, wiki_root: Path) -> dict[str, Any]:
    """Confirm registries enumerate exactly the active flat skills with v3 routing."""
    runtime_path = skills_root / 'skills-registry.yaml'
    wiki_path = wiki_root / 'systems' / 'skills-registry.yaml'
    inventory = inventory_skills(skills_root)
    runtime_members, runtime_duplicate = _registry_membership(runtime_path)
    wiki_members, wiki_duplicate = _registry_membership(wiki_path)
    governed = {
        name for name in inventory
        if name.startswith('pentest-') or name.startswith('butian-')
        or name in {'authorized-web-assessment-gate', 'web-mining', 'pentest-orchestrator', 'agent-history-ingest', 'claude-code-router', 'memory-governance'}
    }
    classifications = all(runtime_members.get(name) == classify_skill(name, {}) for name in governed)
    runtime_inventory_match = set(runtime_members) == inventory and not runtime_duplicate
    wiki_inventory_match = set(wiki_members) == inventory and not wiki_duplicate
    hashes_match = sha256(runtime_path) is not None and sha256(runtime_path) == sha256(wiki_path)
    return {
        'runtime_registry': str(runtime_path),
        'wiki_registry': str(wiki_path),
        'runtime_sha256': sha256(runtime_path),
        'wiki_sha256': sha256(wiki_path),
        'inventory_count': len(inventory),
        'runtime_inventory_match': runtime_inventory_match,
        'wiki_inventory_match': wiki_inventory_match,
        'hashes_match': hashes_match,
        'governed_classifications_match': classifications,
        'ok': runtime_inventory_match and wiki_inventory_match and hashes_match and classifications,
    }


def registry_payload(skills_root: Path, registry_path: Path) -> dict[str, Any]:
    prior: dict[str, str] = {}
    if registry_path.is_file():
        try:
            old = yaml.safe_load(registry_path.read_text(encoding='utf-8')) or {}
        except yaml.YAMLError:
            old = {}
        for category, names in (old.get('categories', {}) if isinstance(old, dict) else {}).items():
            for name in names if isinstance(names, list) else []:
                prior.setdefault(str(name), str(category))
    values: dict[str, list[str]] = {}
    for name in sorted(inventory_skills(skills_root)):
        values.setdefault(classify_skill(name, prior), []).append(name)
    ordered = ['system', 'pentest', 'research', 'productivity', 'personal/traditional-culture', 'integration', 'development', 'content', 'data', 'reference', 'history', 'wiki']
    return {
        'schema_version': 1,
        'generated_at': datetime.now(timezone.utc).date().isoformat(),
        'runtime_root': str(skills_root),
        'discovery_policy': 'keep-active-skills-flat',
        'categories': {category: sorted(values[category]) for category in ordered if values.get(category)},
        'fiverr_boundary': {'allowed_domains': ['client-delivery', 'data-processing', 'spreadsheets', 'reports'], 'forbidden_skills': ['zhouyi-divination'], 'note': '分类通过注册表和 Wiki 表达；运行目录保持平铺。'},
        'operational_rules': ['Active skills remain first-level directories for Hermes discovery compatibility.', 'Skill changes require a backup and a Wiki changelog entry.', 'Never store credentials or tokens in this registry.'],
    }


def write_registry(skills_root: Path, wiki_root: Path) -> list[Path]:
    runtime_registry = skills_root / 'skills-registry.yaml'
    wiki_registry = wiki_root / 'systems' / 'skills-registry.yaml'
    source = wiki_registry if wiki_registry.is_file() else runtime_registry
    payload = registry_payload(skills_root, source)
    content = yaml.safe_dump(payload, allow_unicode=True, sort_keys=False)
    for path in (runtime_registry, wiki_registry):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding='utf-8')
    return [runtime_registry, wiki_registry]


def desired_targets(hermes_home: Path, policy_root: Path, wiki_root: Path) -> list[Path]:
    return [*(hermes_home / 'skills' / name for name in RUNTIME_SKILLS), hermes_home / LEGACY_NESTED_SKILL, hermes_home / 'config.yaml', hermes_home / 'agent-hooks' / 'hexstrike_gate.py', policy_root / 'hexstrike_policy_mcp.py', hermes_home / 'skills' / 'skills-registry.yaml', wiki_root / 'systems' / 'skills-registry.yaml', wiki_root / 'operations' / 'hermes-web-mining-v3-20260807.md']


def source_targets(hermes_home: Path, policy_root: Path) -> list[tuple[Path, Path]]:
    return [(WORKBENCH_ROOT / 'skills' / name, hermes_home / 'skills' / name) for name in RUNTIME_SKILLS] + [(WORKBENCH_ROOT / 'hexstrike' / 'hexstrike_gate.py', hermes_home / 'agent-hooks' / 'hexstrike_gate.py'), (WORKBENCH_ROOT / 'hexstrike' / 'hexstrike_policy_mcp.py', policy_root / 'hexstrike_policy_mcp.py')]


def check(hermes_home: Path, policy_root: Path, wiki_root: Path | None = None) -> tuple[dict[str, Any], int]:
    """Compare canonical source, flat runtime, configuration and both registries."""
    wiki_root = wiki_root or Path.home() / 'wiki'
    rows = []
    for source, target in source_targets(hermes_home, policy_root):
        source_file = source / 'SKILL.md' if source.is_dir() else source
        target_file = target / 'SKILL.md' if target.is_dir() else target
        source_hash, target_hash = sha256(source_file), sha256(target_file)
        rows.append({'source': str(source_file), 'target': str(target_file), 'source_sha256': source_hash, 'target_sha256': target_hash, 'match': source_hash is not None and source_hash == target_hash})
    config = hermes_home / 'config.yaml'
    disabled = sorted(disabled_skills(config))
    legacy = (hermes_home / LEGACY_NESTED_SKILL).exists()
    registry = registry_check(hermes_home / 'skills', wiki_root)
    result = {
        'in_sync': all(row['match'] for row in rows) and 'pentest-orchestrator' not in disabled and not legacy and registry['ok'],
        'files': rows,
        'config': str(config),
        'disabled_skills': disabled,
        'legacy_nested_skill': legacy,
        'pentest_orchestrator_disabled': 'pentest-orchestrator' in disabled,
        'registry': registry,
    }
    return result, 0 if result['in_sync'] else 2


def apply(hermes_home: Path, policy_root: Path, wiki_root: Path, restart_gateway: bool) -> tuple[Path, dict[str, Any]]:
    backup = hermes_home / 'maintenance' / 'backups' / f'{BACKUP_PREFIX}{utc_stamp()}'
    backup.mkdir(parents=True, exist_ok=False)
    entries = snapshot(backup, desired_targets(hermes_home, policy_root, wiki_root))
    for source, target in source_targets(hermes_home, policy_root):
        if not source.exists():
            raise FileNotFoundError(f'missing canonical source: {source}')
        copy_path(source, target)
    legacy = hermes_home / LEGACY_NESTED_SKILL
    if legacy.exists():
        remove_path(legacy)
        if legacy.parent.exists() and not any(legacy.parent.iterdir()):
            legacy.parent.rmdir()
    remove_disabled_skill(hermes_home / 'config.yaml', 'pentest-orchestrator')
    registries = write_registry(hermes_home / 'skills', wiki_root)
    commit = subprocess.run(['git', '-C', str(WORKBENCH_ROOT), 'rev-parse', 'HEAD'], capture_output=True, text=True, check=False).stdout.strip()
    changelog = wiki_root / 'operations' / 'hermes-web-mining-v3-20260807.md'
    changelog.parent.mkdir(parents=True, exist_ok=True)
    changelog.write_text(f"""---
title: Hermes web-mining v3 deployment
date: {datetime.now(timezone.utc).isoformat()}
commit: {commit}
backup_id: {backup.name}
---

# Hermes Web-Mining v3 Deployment

- Canonical flat skills: {', '.join(RUNTIME_SKILLS)}
- Legacy nested web-mining skill archived in backup `{backup}`.
- HexStrike gate deployed in audit mode; local Profiles no longer require a remote job.
- Registry rebuilt from first-level runtime skills and mirrored to the Wiki.
- Registry files: {', '.join(str(path) for path in registries)}
""", encoding='utf-8')
    manifest = {'schema_version': 1, 'backup_id': backup.name, 'created_at': datetime.now(timezone.utc).isoformat(), 'entries': entries, 'commit': commit}
    (backup / 'manifest.json').write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    restart: dict[str, Any] = {'requested': restart_gateway, 'returncode': None}
    if restart_gateway:
        completed = subprocess.run(['systemctl', '--user', 'restart', 'hermes-gateway.service'], capture_output=True, text=True, encoding='utf-8', errors='replace')
        restart = {'requested': True, 'returncode': completed.returncode, 'stdout': completed.stdout, 'stderr': completed.stderr}
    return backup, {'backup': str(backup), 'restart': restart, 'registry': [str(path) for path in registries]}


def rollback(backup: Path) -> dict[str, Any]:
    manifest = json.loads((backup / 'manifest.json').read_text(encoding='utf-8'))
    for entry in reversed(manifest.get('entries', [])):
        target = Path(entry['target'])
        remove_path(target)
        if entry.get('exists') and entry.get('backup'):
            copy_path(backup / entry['backup'], target)
    return {'rolled_back': str(backup), 'entries': len(manifest.get('entries', []))}


def main() -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--check', action='store_true')
    mode.add_argument('--apply', action='store_true')
    mode.add_argument('--rollback', metavar='BACKUP_ID')
    parser.add_argument('--hermes-home', type=Path, default=Path(os.environ.get(HERMES_HOME_ENV, str(Path.home() / '.hermes'))))
    parser.add_argument('--policy-root', type=Path, default=Path(os.environ.get(HEXSTRIKE_POLICY_ROOT_ENV, str(Path.home() / 'hexstrike-policy'))))
    parser.add_argument('--wiki-root', type=Path, default=Path.home() / 'wiki')
    parser.add_argument('--restart-gateway', action='store_true')
    args = parser.parse_args()
    hermes_home, policy_root, wiki_root = args.hermes_home.expanduser(), args.policy_root.expanduser(), args.wiki_root.expanduser()
    if args.check:
        result, code = check(hermes_home, policy_root, wiki_root)
    elif args.apply:
        backup, result = apply(hermes_home, policy_root, wiki_root, args.restart_gateway)
        result['backup_id'] = backup.name
        code = 0 if result['restart'].get('returncode') in {None, 0} else 1
    else:
        backup = hermes_home / 'maintenance' / 'backups' / args.rollback
        result, code = rollback(backup), 0
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return code


if __name__ == '__main__':
    raise SystemExit(main())
