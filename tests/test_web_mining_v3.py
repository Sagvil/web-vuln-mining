"""Offline regression tests for web-mining v3 routing and durable evidence."""
from __future__ import annotations

import importlib.util
import json
import os
import stat
import subprocess
import sys
import tempfile
import types
import unittest

import yaml
from pathlib import Path
from unittest import mock

# ============================ Configuration zone ============================
# ROOT: repository under test; fixtures never contact a network target.
ROOT = Path(__file__).resolve().parents[1]
# ============================================================================

sys.path.insert(0, str(ROOT / 'scripts'))
import run_profile as runner
from scope_validation import validate_scope
import sync_hermes


class WebMiningV3Tests(unittest.TestCase):
    def dns_scope(self, wordlist: str) -> dict:
        return {
            'name': 'dns-fixture', 'source_root': 'fixtures/web-vuln-sample',
            'base_urls': ['https://www.example.test/'], 'openapi': [],
            'include_hosts': ['www.example.test'], 'exclude_paths': ['/logout'],
            'rate_limit': 2, 'crawl_budget': {'max_depth': 1, 'max_pages': 10},
            'profiles': ['active-dns-discovery'],
            'active_dns_discovery': {'roots': ['example.test'], 'wordlist': wordlist, 'max_words': 10, 'threads': 2, 'max_candidates': 10},
        }

    def test_dns_scope_rejects_unapproved_root_and_bounds(self) -> None:
        scope = self.dns_scope('wordlists/dns-subdomains.txt')
        scope['profiles'] = []
        scope['active_dns_discovery']['roots'] = ['outside.test']
        scope['active_dns_discovery']['threads'] = 21
        scope['active_dns_discovery']['max_words'] = 10_001
        scope['active_dns_discovery']['max_candidates'] = 5_001
        scope['active_dns_discovery']['wordlist'] = '../outside.txt'
        errors = validate_scope(scope, 'active-dns-discovery')
        fields = {item.field for item in errors}
        self.assertIn('profiles', fields)
        self.assertIn('active_dns_discovery.roots', fields)
        self.assertIn('active_dns_discovery.threads', fields)
        self.assertIn('active_dns_discovery.max_words', fields)
        self.assertIn('active_dns_discovery.max_candidates', fields)
        self.assertIn('active_dns_discovery.wordlist', fields)

    def test_dns_profile_uses_only_fake_nmap_and_writes_candidates(self) -> None:
        with tempfile.TemporaryDirectory() as raw_temp:
            temp = Path(raw_temp)
            wordlist = temp / 'words.txt'
            wordlist.write_text('www\napi\napi\n# comment\n', encoding='utf-8')
            fake = temp / 'nmap'
            fake.write_text("""#!/usr/bin/env python3
import pathlib, sys
out = pathlib.Path(sys.argv[sys.argv.index('-oX') + 1])
out.write_text('<nmaprun><host><address addr="192.0.2.10"/><hostnames><hostname name="api.example.test"/></hostnames></host><host><address addr="192.0.2.10"/><hostnames><hostname name="api.example.test"/></hostnames></host></nmaprun>', encoding='utf-8')
""", encoding='utf-8')
            fake.chmod(fake.stat().st_mode | stat.S_IEXEC)
            scope = self.dns_scope(str(wordlist))
            run_dir = temp / 'run'
            for directory in ('raw', 'logs', 'sarif', 'evidence'):
                (run_dir / directory).mkdir(parents=True, exist_ok=True)
            statuses: list[dict] = []
            env = os.environ.copy()
            env['PATH'] = str(temp) + os.pathsep + env.get('PATH', '')
            with mock.patch.dict(os.environ, env, clear=True):
                candidates = runner._active_dns_discovery(scope, run_dir, statuses)
            self.assertEqual([item['hostname'] for item in candidates], ['api.example.test'])
            self.assertEqual(candidates[0]['addresses'], ['192.0.2.10'])
            log = json.loads(next((run_dir / 'logs').glob('nmap-*.json')).read_text(encoding='utf-8'))
            self.assertIn('-sn', log['command'])
            self.assertNotIn('-sV', log['command'])
            self.assertNotIn('-p', log['command'])
            self.assertTrue((run_dir / 'raw' / 'asset-candidates.json').is_file())
            self.assertEqual(len(statuses), 1)
            self.assertTrue(all('http' not in str(item['tool']) for item in statuses))

    def test_dns_profile_timeout_and_no_records_stay_candidates_only(self) -> None:
        with tempfile.TemporaryDirectory() as raw_temp:
            temp = Path(raw_temp)
            wordlist = temp / 'words.txt'
            wordlist.write_text('api\n', encoding='utf-8')
            fake = temp / 'nmap'
            fake.write_text("""#!/usr/bin/env python3
import os, pathlib, sys, time
if os.environ.get('DNS_FIXTURE_MODE') == 'timeout':
    time.sleep(1)
out = pathlib.Path(sys.argv[sys.argv.index('-oX') + 1])
out.write_text('<nmaprun/>', encoding='utf-8')
""", encoding='utf-8')
            fake.chmod(fake.stat().st_mode | stat.S_IEXEC)
            scope = self.dns_scope(str(wordlist))
            env = os.environ.copy()
            env['PATH'] = str(temp) + os.pathsep + env.get('PATH', '')
            status_by_mode: dict[str, str] = {}
            for mode, timeout in (('timeout', 0.01), ('no-records', runner.ACTIVE_DNS_NMAP_TIMEOUT_SECONDS)):
                run_dir = temp / mode
                for directory in ('raw', 'logs', 'sarif', 'evidence'):
                    (run_dir / directory).mkdir(parents=True, exist_ok=True)
                statuses: list[dict] = []
                env['DNS_FIXTURE_MODE'] = mode
                with mock.patch.dict(os.environ, env, clear=True), mock.patch.object(runner, 'ACTIVE_DNS_NMAP_TIMEOUT_SECONDS', timeout):
                    candidates = runner._active_dns_discovery(scope, run_dir, statuses)
                self.assertEqual(candidates, [])
                self.assertEqual(json.loads((run_dir / 'raw' / 'asset-candidates.json').read_text(encoding='utf-8'))['candidates'], [])
                self.assertEqual(len(statuses), 1)
                self.assertEqual(statuses[0]['tool'].split('-', 3)[:3], ['nmap', 'dns', 'brute'])
                status_by_mode[mode] = statuses[0]['status']
            self.assertEqual(status_by_mode['timeout'], 'failed')
            self.assertEqual(status_by_mode['no-records'], 'completed')

    def test_dns_profile_missing_nmap_is_failed_not_promoted(self) -> None:
        with tempfile.TemporaryDirectory() as raw_temp, mock.patch.object(runner.shutil, 'which', return_value=None):
            temp = Path(raw_temp)
            wordlist = temp / 'words.txt'
            wordlist.write_text('api\n', encoding='utf-8')
            run_dir = temp / 'run'
            for directory in ('raw', 'logs', 'sarif', 'evidence'):
                (run_dir / directory).mkdir(parents=True, exist_ok=True)
            statuses: list[dict] = []
            candidates = runner._active_dns_discovery(self.dns_scope(str(wordlist)), run_dir, statuses)
            self.assertEqual(candidates, [])
            self.assertEqual(statuses[0]['status'], 'failed')
            self.assertTrue((run_dir / 'logs' / 'nmap-preflight.json').is_file())
            self.assertEqual(json.loads((run_dir / 'raw' / 'asset-candidates.json').read_text(encoding='utf-8'))['candidates'], [])

    def test_normalizer_and_report_keep_assets_out_of_findings(self) -> None:
        with tempfile.TemporaryDirectory() as raw_temp:
            run_dir = Path(raw_temp) / 'run'
            for directory in ('raw', 'sarif', 'logs', 'evidence'):
                (run_dir / directory).mkdir(parents=True, exist_ok=True)
            (run_dir / 'run-manifest.json').write_text(json.dumps({'run_id': 'dns-fixture', 'profile': 'active-dns-discovery', 'local_tool_status': [], 'hexstrike_status': 'optional-not-requested'}), encoding='utf-8')
            (run_dir / 'raw' / 'asset-candidates.json').write_text(json.dumps({'candidates': [{'hostname': 'api.example.test', 'addresses': ['192.0.2.10'], 'root': 'example.test', 'source': 'nmap-dns-brute'}]}), encoding='utf-8')
            subprocess.run([sys.executable, str(ROOT / 'scripts' / 'normalize_results.py'), str(run_dir)], check=True, capture_output=True, text=True)
            summary = json.loads((run_dir / 'summary.json').read_text(encoding='utf-8'))
            self.assertEqual(summary['counts']['asset_candidate'], 1)
            self.assertEqual(summary['findings'], [])
            subprocess.run([sys.executable, str(ROOT / 'scripts' / 'create_report.py'), str(run_dir)], check=True, capture_output=True, text=True)
            report = (run_dir / 'report.md').read_text(encoding='utf-8')
            self.assertIn('DNS Asset Candidates', report)
            self.assertIn('not Web targets', report)

    def test_audit_gate_allows_local_nmap_and_records_event(self) -> None:
        with tempfile.TemporaryDirectory() as raw_temp:
            temp = Path(raw_temp)
            env = os.environ.copy()
            env.update({'HEXSTRIKE_AUDIT_LOG': str(temp / 'audit.jsonl'), 'HEXSTRIKE_STATE_DIR': str(temp / 'state')})
            payload = {'hook_event_name': 'pre_tool_call', 'session_id': 'fixture', 'tool_name': 'terminal', 'tool_input': {'command': 'nmap -sn example.test'}}
            result = subprocess.run([sys.executable, str(ROOT / 'hexstrike' / 'hexstrike_gate.py')], input=json.dumps(payload), text=True, capture_output=True, env=env, check=True)
            self.assertEqual(result.stdout, '')
            record = json.loads((temp / 'audit.jsonl').read_text(encoding='utf-8').splitlines()[-1])
            self.assertEqual(record['event'], 'local_network_command')
            self.assertEqual(record['mode'], 'allowed-local-profile')

    def policy_module(self):
        fake_mcp = types.ModuleType('mcp')
        fake_server = types.ModuleType('mcp.server')
        fake_fastmcp = types.ModuleType('mcp.server.fastmcp')
        class FastMCP:
            def __init__(self, *_args, **_kwargs):
                pass
            def tool(self, function=None):
                return function if function is not None else (lambda item: item)
            def run(self):
                return None
        fake_fastmcp.FastMCP = FastMCP
        with mock.patch.dict(sys.modules, {'mcp': fake_mcp, 'mcp.server': fake_server, 'mcp.server.fastmcp': fake_fastmcp}):
            spec = importlib.util.spec_from_file_location('policy_fixture', ROOT / 'hexstrike' / 'hexstrike_policy_mcp.py')
            assert spec and spec.loader
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            return module

    def test_policy_timeout_and_terminal_integrity_contract(self) -> None:
        module = self.policy_module()
        self.assertIn('--timeout 600', module._upstream_command(600))
        with tempfile.TemporaryDirectory() as raw_temp:
            module.JOB_ROOT = Path(raw_temp)
            job_id = 'HX-fixture-job'
            directory = module._job_dir(job_id)
            directory.mkdir(parents=True)
            request = {'job_id': job_id, 'capability': 'fixture', 'tier': 'A', 'arguments': {}, 'scope_roots': ['example.test'], 'exact_targets': []}
            module._atomic_json(directory / 'request.json', request)
            module._write_state(directory, 'queued')
            module._finalize_job(directory, request, {'success': True, 'status': 'completed', 'result': {}}, 'completed')
            status = module.hexstrike_job_status(job_id)
            self.assertTrue(status['success'])
            self.assertTrue(status['integrity'])
            (directory / 'result.json').write_text('{}', encoding='utf-8')
            tampered = module.hexstrike_job_status(job_id)
            self.assertFalse(tampered['integrity'])

            worker_id = 'HX-worker-fixture'
            worker_directory = module._job_dir(worker_id)
            worker_directory.mkdir(parents=True)
            worker_request = {**request, 'job_id': worker_id}
            module._atomic_json(worker_directory / 'request.json', worker_request)
            module._write_state(worker_directory, 'queued')
            execution = {'success': True, 'status': 'completed', 'result': {'fixture': True}}
            with mock.patch.object(module, '_call_upstream', return_value=execution):
                self.assertEqual(module._run_job(worker_id), 0)
            worker_status = module.hexstrike_job_status(worker_id)
            self.assertTrue(worker_status['success'])
            self.assertTrue(worker_status['integrity'])
            self.assertEqual(json.loads((worker_directory / 'job-state.json').read_text(encoding='utf-8'))['status'], 'completed')

    def test_sync_apply_and_rollback_preserve_unrelated_runtime(self) -> None:
        with tempfile.TemporaryDirectory() as raw_temp:
            temp = Path(raw_temp)
            hermes_home, policy_root, wiki_root = temp / 'hermes', temp / 'policy', temp / 'wiki'
            (hermes_home / 'skills' / 'pentest' / 'web-mining').mkdir(parents=True)
            (hermes_home / 'skills' / 'pentest' / 'web-mining' / 'SKILL.md').write_text('legacy', encoding='utf-8')
            (hermes_home / 'skills' / 'unrelated').mkdir(parents=True)
            (hermes_home / 'skills' / 'unrelated' / 'SKILL.md').write_text('unrelated', encoding='utf-8')
            for name in ('authorized-web-assessment-gate', 'butian-fixture', 'pentest-fixture', 'agent-history-ingest', 'claude-code-router', 'memory-governance'):
                (hermes_home / 'skills' / name).mkdir(parents=True)
                (hermes_home / 'skills' / name / 'SKILL.md').write_text(name, encoding='utf-8')
            (wiki_root / 'systems').mkdir(parents=True)
            (wiki_root / 'systems' / 'skills-registry.yaml').write_text('categories:\n  system: [computer-use, pentest-fixture]\n', encoding='utf-8')
            (hermes_home / 'config.yaml').write_text('skills:\n  disabled:\n    - pentest-orchestrator\n    - unrelated\n', encoding='utf-8')
            backup, result = sync_hermes.apply(hermes_home, policy_root, wiki_root, False)
            self.assertTrue((hermes_home / 'skills' / 'web-mining' / 'SKILL.md').is_file())
            self.assertFalse((hermes_home / 'skills' / 'pentest' / 'web-mining').exists())
            self.assertTrue((hermes_home / 'skills' / 'unrelated' / 'SKILL.md').is_file())
            config = (hermes_home / 'config.yaml').read_text(encoding='utf-8')
            self.assertNotIn('pentest-orchestrator', config)
            self.assertIn('unrelated', config)
            registry = yaml.safe_load((hermes_home / 'skills' / 'skills-registry.yaml').read_text(encoding='utf-8'))
            category_by_skill = {name: category for category, names in registry['categories'].items() for name in names}
            self.assertNotIn('computer-use', category_by_skill)
            self.assertEqual(category_by_skill['authorized-web-assessment-gate'], 'pentest')
            self.assertEqual(category_by_skill['butian-fixture'], 'pentest')
            self.assertEqual(category_by_skill['pentest-fixture'], 'pentest')
            self.assertEqual(category_by_skill['agent-history-ingest'], 'history')
            self.assertEqual(category_by_skill['claude-code-router'], 'system')
            self.assertEqual(category_by_skill['memory-governance'], 'system')
            _check, check_code = sync_hermes.check(hermes_home, policy_root, wiki_root)
            self.assertEqual(check_code, 0)
            sync_hermes.rollback(backup)
            self.assertTrue((hermes_home / 'skills' / 'pentest' / 'web-mining' / 'SKILL.md').is_file())
            self.assertTrue((hermes_home / 'skills' / 'unrelated' / 'SKILL.md').is_file())


if __name__ == '__main__':
    unittest.main()
