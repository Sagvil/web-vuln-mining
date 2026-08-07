"""Install portable skill adapters and canonical Hermes v3 skills."""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

# ============================ Configuration zone ============================
# MANAGED_* delimit the small configuration block owned by this installer.
MANAGED_BEGIN = '# BEGIN web-vuln-mining managed block'
MANAGED_END = '# END web-vuln-mining managed block'
# HERMES_SKILLS are copied as flat directories for Hermes discovery.
HERMES_SKILLS = ('web-mining', 'pentest-orchestrator', 'pentest-hexstrike-executor')
# ============================================================================

ROOT = Path(__file__).resolve().parents[1]


def backup(path: Path) -> None:
    if path.exists():
        stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
        shutil.copy2(path, path.with_suffix(path.suffix + '.' + stamp + '.bak'))


def _replace_managed_block(current: str) -> str:
    managed = f'{MANAGED_BEGIN}\n# WEB_VULN_MINING_ROOT: {ROOT}\n# HexStrike is optional remote review/audit support.\n{MANAGED_END}\n'
    if MANAGED_BEGIN in current and MANAGED_END in current:
        start = current.index(MANAGED_BEGIN)
        end = current.index(MANAGED_END, start) + len(MANAGED_END)
        return current[:start] + managed + current[end:].lstrip('\n')
    return current + ('\n' if current and not current.endswith('\n') else '') + managed


def _copy_skill(source: Path, target: Path) -> None:
    target.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, target / 'SKILL.md')


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('agent', choices=('codex', 'hermes', 'openclaw'))
    parser.add_argument('--skip-repair', action='store_true', help='install only the skill files without first-run tool repair')
    args = parser.parse_args()
    home = Path.home()
    installed: list[Path] = []
    if args.agent == 'hermes':
        for name in HERMES_SKILLS:
            source = ROOT / 'skills' / name / 'SKILL.md'
            target = home / '.hermes' / 'skills' / name
            _copy_skill(source, target)
            installed.append(target)
        config = home / '.hermes' / 'config.yaml'
        backup(config)
        current = config.read_text(encoding='utf-8') if config.exists() else ''
        config.parent.mkdir(parents=True, exist_ok=True)
        config.write_text(_replace_managed_block(current), encoding='utf-8')
    else:
        adapter = ROOT / 'adapters' / args.agent / 'SKILL.md'
        target = home / ('.codex' if args.agent == 'codex' else '.openclaw') / 'skills' / 'web-mining'
        _copy_skill(adapter, target)
        installed.append(target)
        if args.agent == 'openclaw':
            config = home / '.openclaw' / 'web-mining.managed.json'
            backup(config)
            config.write_text(json.dumps({'web_vuln_mining_root': str(ROOT), 'skill_path': str(target)}, indent=2) + '\n', encoding='utf-8')
    if not args.skip_repair:
        result = subprocess.run([sys.executable, str(ROOT / 'scripts' / 'preflight.py'), '--repair', '--json'])
        if result.returncode:
            return result.returncode
    print('\n'.join(str(path) for path in installed))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
