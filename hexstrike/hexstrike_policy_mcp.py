#!/usr/bin/env python3
"""Policy-controlled MCP façade for the upstream HexStrike MCP server."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
import uuid
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Sequence

from mcp.server.fastmcp import FastMCP


# ============================== Configuration ==============================
# Local-only upstream HexStrike REST endpoint.
HEXSTRIKE_API_URL = os.environ.get("HEXSTRIKE_API_URL", "http://127.0.0.1:8888")
# Upstream MCP implementation containing the original 150 tool wrappers.
UPSTREAM_MCP = Path(
    os.environ.get("HEXSTRIKE_UPSTREAM_MCP", "/home/sagvil/hexstrike-ai/hexstrike_mcp.py")
)
# Python and FastMCP executables used to invoke one upstream tool per job.
HEXSTRIKE_PYTHON = os.environ.get(
    "HEXSTRIKE_PYTHON", "/home/sagvil/hexstrike-ai/hexstrike-env/bin/python"
)
FASTMCP_BIN = os.environ.get(
    "HEXSTRIKE_FASTMCP", "/home/sagvil/hexstrike-ai/hexstrike-env/bin/fastmcp"
)
# Capability classification written during the 150-tool audit.
POLICY_FILE = Path(
    os.environ.get(
        "HEXSTRIKE_POLICY_FILE",
        str(Path(__file__).with_name("capability-policy.json")),
    )
)
# Private execution records. Every network or local analysis call lands here.
JOB_ROOT = Path(os.environ.get("HEXSTRIKE_JOB_ROOT", "/home/sagvil/渗透/hexstrike-jobs"))
# Deterministic binary lookup path. Hermes may prepend its virtualenv to PATH,
# where an unrelated Python package also installs an executable named httpx.
TOOL_SEARCH_PATH = os.environ.get(
    "HEXSTRIKE_TOOL_PATH",
    "/home/sagvil/go/bin:/home/sagvil/.local/bin:/usr/local/bin:/usr/bin:/bin",
)
# Local artifact roots accepted by C-tier binary/forensics tools.
LOCAL_ARTIFACT_ROOTS = tuple(
    Path(p).resolve()
    for p in os.environ.get(
        "HEXSTRIKE_LOCAL_ROOTS",
        "/home/sagvil/渗透:/home/sagvil/hexstrike-policy",
    ).split(":")
    if p
)
# Per-call wall-clock ceilings by risk tier.
TIER_TIMEOUTS = {"A": 300, "B": 600, "C": 900}
# WORKER_START_GRACE_SECONDS: status checks wait this long before classifying a
# missing worker as aborted. It protects the durable job contract after callers disconnect.
WORKER_START_GRACE_SECONDS = 15
# TERMINAL_JOB_STATES are the only states that may have integrity=true.
TERMINAL_JOB_STATES = {"completed", "failed", "timeout", "aborted"}
# JOB_STATE_FILE stores durable lifecycle metadata separately from result.json.
JOB_STATE_FILE = "job-state.json"
# ===========================================================================


ALLOWED_MODES = {"src", "contracted", "lab", "ctf"}
CONTRACTED_MODES = {"contracted", "lab", "ctf"}
SHELL_META = re.compile(r"[;&|`$<>\r\n]")
SAFE_JOB_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$")
HOST_KEYS = {
    "base_url",
    "domain",
    "endpoint",
    "host",
    "schema_url",
    "target",
    "target_url",
    "targets",
    "url",
}
LOCAL_PATH_KEYS = {
    "binary",
    "cover_file",
    "directory",
    "file_path",
    "hash_file",
    "iac_dir",
    "image",
    "input_file",
    "libc",
    "libc_path",
    "memory_file",
    "target_binary",
}

# These wrappers execute local programs. Capabilities not listed here are
# HexStrike-native planners/frameworks or are allowed to fail closed upstream.
CAPABILITY_BINARIES = {
    "amass_scan": "amass",
    "angr_symbolic_execution": "angr",
    "arjun_parameter_discovery": "arjun",
    "arjun_scan": "arjun",
    "arp_scan_discovery": "arp-scan",
    "autorecon_comprehensive": "autorecon",
    "autorecon_scan": "autorecon",
    "binwalk_analyze": "binwalk",
    "burpsuite_scan": "burpsuite",
    "checkov_iac_scan": "checkov",
    "checksec_analyze": "checksec",
    "clair_vulnerability_scan": "clair",
    "cloudmapper_analysis": "cloudmapper",
    "dalfox_xss_scan": "dalfox",
    "dirb_scan": "dirb",
    "dirsearch_scan": "dirsearch",
    "dnsenum_scan": "dnsenum",
    "docker_bench_security_scan": "docker-bench-security",
    "dotdotpwn_scan": "dotdotpwn",
    "enum4linux_ng_advanced": "enum4linux-ng",
    "enum4linux_scan": "enum4linux",
    "exiftool_extract": "exiftool",
    "falco_runtime_monitoring": "falco",
    "feroxbuster_scan": "feroxbuster",
    "ffuf_scan": "ffuf",
    "fierce_scan": "fierce",
    "foremost_carving": "foremost",
    "gau_discovery": "gau",
    "gdb_analyze": "gdb",
    "gdb_peda_debug": "gdb",
    "ghidra_analysis": "ghidra",
    "gobuster_scan": "gobuster",
    "hakrawler_crawl": "hakrawler",
    "hashpump_attack": "hashpump",
    "httpx_probe": "httpx",
    "jaeles_vulnerability_scan": "jaeles",
    "katana_crawl": "katana",
    "kube_bench_cis": "kube-bench",
    "kube_hunter_scan": "kube-hunter",
    "metasploit_run": "msfconsole",
    "msfvenom_generate": "msfvenom",
    "nbtscan_netbios": "nbtscan",
    "netexec_scan": "nxc",
    "nikto_scan": "nikto",
    "nmap_advanced_scan": "nmap",
    "nmap_scan": "nmap",
    "nuclei_scan": "nuclei",
    "objdump_analyze": "objdump",
    "one_gadget_search": "one_gadget",
    "paramspider_discovery": "paramspider",
    "paramspider_mining": "paramspider",
    "prowler_scan": "prowler",
    "pwninit_setup": "pwninit",
    "radare2_analyze": "radare2",
    "ropgadget_search": "ROPgadget",
    "ropper_gadget_search": "ropper",
    "rpcclient_enumeration": "rpcclient",
    "rustscan_fast_scan": "rustscan",
    "scout_suite_assessment": "scout",
    "smbmap_scan": "smbmap",
    "sqlmap_scan": "sqlmap",
    "steghide_analysis": "steghide",
    "strings_extract": "strings",
    "subfinder_scan": "subfinder",
    "terrascan_iac_scan": "terrascan",
    "trivy_scan": "trivy",
    "volatility3_analyze": "vol",
    "volatility_analyze": "volatility",
    "wafw00f_scan": "wafw00f",
    "waybackurls_discovery": "waybackurls",
    "wfuzz_scan": "wfuzz",
    "wpscan_analyze": "wpscan",
    "x8_parameter_discovery": "x8",
    "xsser_scan": "xsser",
    "xxd_hexdump": "xxd",
    "zap_scan": "zap.sh",
}

# Fixed low-impact parameters are injected after caller arguments are checked.
FIXED_SAFE_ARGS: Dict[str, Dict[str, Any]] = {
    "dalfox_xss_scan": {"blind": False, "additional_args": "--worker 2 --delay 500"},
    "ffuf_scan": {"additional_args": "-rate 2 -t 2 -maxtime 60"},
    "gobuster_scan": {"additional_args": "--delay 500ms --threads 2 --timeout 5s"},
    "graphql_scanner": {"test_mutations": False, "query_depth": 5},
    "httpx_probe": {"threads": 5, "additional_args": "-rate-limit 5 -timeout 5 -retries 0"},
    "nmap_advanced_scan": {"additional_args": "-T2 --max-retries 1 --host-timeout 120s"},
    "nmap_scan": {"additional_args": "-T2 --max-retries 1 --host-timeout 120s"},
    "nuclei_scan": {"additional_args": "-rate-limit 5 -c 2 -timeout 5 -retries 0"},
    "sqlmap_scan": {
        "additional_args": "--batch --level=1 --risk=1 --threads=1 --timeout=5 --retries=0"
    },
}


def _load_policy() -> Dict[str, List[str]]:
    data = json.loads(POLICY_FILE.read_text(encoding="utf-8"))
    tiers = data.get("tiers", {})
    if set(tiers) != {"A", "B", "C", "D"}:
        raise RuntimeError("capability policy must define A, B, C, and D tiers")
    flattened = [name for tier in tiers.values() for name in tier]
    if len(flattened) != 150 or len(set(flattened)) != 150:
        raise RuntimeError("capability policy must contain 150 unique capabilities")
    return {tier: list(names) for tier, names in tiers.items()}


POLICY = _load_policy()
CAPABILITY_TIER = {
    capability: tier
    for tier, capabilities in POLICY.items()
    for capability in capabilities
}
EXPOSED_CAPABILITIES = tuple(sorted(POLICY["A"] + POLICY["B"] + POLICY["C"]))


def _parse_list(value: str | Sequence[str]) -> List[str]:
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return []
        if text.startswith("["):
            parsed = json.loads(text)
            if not isinstance(parsed, list):
                raise ValueError("list input must decode to a JSON array")
            return [str(item).strip() for item in parsed if str(item).strip()]
        return [item.strip() for item in text.split(",") if item.strip()]
    return [str(item).strip() for item in value if str(item).strip()]


def _extract_host(value: str) -> str | None:
    text = value.strip()
    if not text or text.startswith("/"):
        return None
    parsed = urllib.parse.urlsplit(text if "://" in text else f"//{text}")
    host = parsed.hostname
    if not host:
        return None
    return host.rstrip(".").lower()


def _normalize_scope_item(value: str) -> str:
    host = _extract_host(value)
    return host or value.strip().rstrip(".").lower()


def _host_in_scope(host: str, roots: Iterable[str]) -> bool:
    for raw_root in roots:
        root = _normalize_scope_item(raw_root)
        if not root:
            continue
        if host == root or host.endswith(f".{root}"):
            return True
        try:
            if ipaddress.ip_address(host) in ipaddress.ip_network(root, strict=False):
                return True
        except ValueError:
            pass
    return False


def _host_is_exact(host: str, exact_targets: Iterable[str]) -> bool:
    return any(host == _normalize_scope_item(item) for item in exact_targets)


def _is_local_path(value: str) -> bool:
    text = value.strip()
    if not text:
        return False
    parsed = urllib.parse.urlsplit(text)
    if parsed.scheme and parsed.scheme != "file":
        return False
    path_value = urllib.parse.unquote(parsed.path) if parsed.scheme == "file" else text
    candidate_input = Path(path_value).expanduser()
    if not candidate_input.is_absolute() and not text.startswith(("./", "../", "~")):
        return False
    try:
        candidate = candidate_input.resolve(strict=False)
    except (OSError, RuntimeError):
        return False
    return any(candidate == root or root in candidate.parents for root in LOCAL_ARTIFACT_ROOTS)


def _reject_shell_meta(value: Any, path: str = "arguments") -> None:
    if isinstance(value, str) and SHELL_META.search(value):
        raise ValueError(f"{path} contains forbidden shell metacharacters")
    if isinstance(value, Mapping):
        for key, item in value.items():
            _reject_shell_meta(item, f"{path}.{key}")
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for index, item in enumerate(value):
            _reject_shell_meta(item, f"{path}[{index}]")


def _port_count(port_spec: str) -> int:
    count = 0
    for token in [item.strip() for item in port_spec.split(",") if item.strip()]:
        if "-" in token:
            start_text, end_text = token.split("-", 1)
            start, end = int(start_text), int(end_text)
            if not (1 <= start <= end <= 65535):
                raise ValueError("invalid port range")
            count += end - start + 1
        else:
            port = int(token)
            if not 1 <= port <= 65535:
                raise ValueError("invalid port")
            count += 1
    return count


def _validate_paths(arguments: Mapping[str, Any]) -> None:
    for key in LOCAL_PATH_KEYS:
        value = arguments.get(key)
        if isinstance(value, str) and value and not _is_local_path(value):
            raise ValueError(f"{key} must stay under an allowed local artifact root")


def _validate_scope(
    capability: str,
    tier: str,
    arguments: Mapping[str, Any],
    scope_roots: Sequence[str],
    exact_targets: Sequence[str],
) -> None:
    network_hosts: List[str] = []
    for key in HOST_KEYS:
        value = arguments.get(key)
        values = value if isinstance(value, list) else [value]
        for item in values:
            if not isinstance(item, str) or not item:
                continue
            if key == "target" and _is_local_path(item):
                continue
            host = _extract_host(item)
            if host:
                network_hosts.append(host)

    for host in network_hosts:
        if not _host_in_scope(host, scope_roots):
            raise ValueError(f"target host {host} is outside declared scope")
        if tier in {"B", "C"} and not _host_is_exact(host, exact_targets):
            raise ValueError(f"active capability {capability} requires exact target {host}")

    if tier in {"B", "C"} and not exact_targets and capability not in {
        "http_set_rules",
        "http_set_scope",
    }:
        raise ValueError("active capabilities require at least one exact target")


def _prepare_arguments(capability: str, mode: str, raw: Mapping[str, Any]) -> Dict[str, Any]:
    arguments = dict(raw)
    if "additional_args" in arguments:
        raise ValueError("caller-controlled additional_args is disabled")
    _reject_shell_meta(arguments)
    _validate_paths(arguments)

    if capability in {"nmap_scan", "nmap_advanced_scan", "rustscan_fast_scan"}:
        ports = str(arguments.get("ports", ""))
        if ports and _port_count(ports) > 100:
            raise ValueError("network scans are limited to 100 explicit ports")
    if capability == "http_intruder":
        arguments["max_requests"] = min(int(arguments.get("max_requests", 20)), 20)
    if capability == "browser_agent_inspect" and mode == "src":
        arguments["active_tests"] = False
    if capability == "burpsuite_alternative_scan" and mode == "src":
        arguments["scan_type"] = "passive"
        arguments["max_depth"] = min(int(arguments.get("max_depth", 2)), 2)
        arguments["max_pages"] = min(int(arguments.get("max_pages", 20)), 20)
    if capability == "zap_scan" and mode == "src":
        arguments["scan_type"] = "baseline"
    if capability == "graphql_scanner" and mode == "src":
        arguments["test_mutations"] = False

    arguments.update(FIXED_SAFE_ARGS.get(capability, {}))
    return arguments


def _tool_path(capability: str) -> str | None:
    binary = CAPABILITY_BINARIES.get(capability)
    return shutil.which(binary, path=TOOL_SEARCH_PATH) if binary else None


def _new_job_id(capability: str) -> str:
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    suffix = uuid.uuid4().hex[:8]
    return f"HX-{stamp}-{capability[:24]}-{suffix}"


def _job_dir(job_id: str) -> Path:
    if not SAFE_JOB_ID.fullmatch(job_id):
        raise ValueError("invalid job_id")
    root = JOB_ROOT.resolve()
    target = (root / job_id).resolve()
    if root not in target.parents:
        raise ValueError("job path escapes job root")
    return target


def _atomic_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=path.parent, delete=False
    ) as handle:
        json.dump(data, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")
        temp_name = handle.name
    os.replace(temp_name, path)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_json(path: Path) -> Dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding='utf-8'))
        return value if isinstance(value, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def _state_path(directory: Path) -> Path:
    return directory / JOB_STATE_FILE


def _write_state(directory: Path, status: str, **fields: Any) -> Dict[str, Any]:
    if status not in {'queued', 'running', *TERMINAL_JOB_STATES}:
        raise ValueError(f'invalid job status: {status}')
    state = _read_json(_state_path(directory))
    state.update(fields)
    state['schema_version'] = 1
    state['status'] = status
    state['updated_at'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
    _atomic_json(_state_path(directory), state)
    return state


def _upstream_command(timeout: int) -> str:
    """Keep the upstream client and FastMCP timeout budgets identical."""
    return ' '.join(shlex.quote(part) for part in (str(HEXSTRIKE_PYTHON), str(UPSTREAM_MCP), '--server', str(HEXSTRIKE_API_URL), '--timeout', str(timeout)))


def _call_upstream(capability: str, arguments: Mapping[str, Any], timeout: int) -> Dict[str, Any]:
    command = [
        FASTMCP_BIN,
        'call',
        '--command',
        _upstream_command(timeout),
        '--target',
        capability,
        '--input-json',
        json.dumps(arguments, ensure_ascii=False, separators=(',', ':')),
        '--json',
        '--timeout',
        str(timeout),
    ]
    started = time.time()
    command_environment = os.environ.copy()
    command_environment['PATH'] = TOOL_SEARCH_PATH
    try:
        completed = subprocess.run(command, capture_output=True, text=True, timeout=timeout + 20, check=False, env=command_environment)
    except subprocess.TimeoutExpired as exc:
        return {'success': False, 'status': 'timeout', 'error': str(exc), 'execution_time': time.time() - started}
    parsed: Any = None
    if completed.stdout.strip():
        try:
            parsed = json.loads(completed.stdout)
        except json.JSONDecodeError:
            parsed = None
    return {
        'success': completed.returncode == 0 and parsed is not None,
        'status': 'completed' if completed.returncode == 0 and parsed is not None else 'failed',
        'returncode': completed.returncode,
        'execution_time': time.time() - started,
        'result': parsed,
        'stdout': completed.stdout,
        'stderr': completed.stderr,
    }


def _finalize_job(directory: Path, request: Mapping[str, Any], execution: Mapping[str, Any], status: str) -> Dict[str, Any]:
    """Write terminal artifacts atomically for every accepted job."""
    final_status = status if status in TERMINAL_JOB_STATES else 'failed'
    result_record = {
        **dict(request),
        'completed_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        'status': final_status,
        'execution': dict(execution),
        'claim_state': 'candidate',
        'verified': False,
    }
    result_path = directory / 'result.json'
    _atomic_json(result_path, result_record)
    request_path = directory / 'request.json'
    sums = {'request.json': _sha256(request_path), 'result.json': _sha256(result_path)}
    _atomic_json(directory / 'SHA256SUMS.json', sums)
    _write_state(directory, final_status, completed_at=result_record['completed_at'])
    return result_record


def _run_job(job_id: str) -> int:
    """Detached worker entrypoint; always leaves a terminal result artifact."""
    try:
        directory = _job_dir(job_id)
        request = _read_json(directory / 'request.json')
        if not request:
            return 2
        _write_state(directory, 'running', started_at=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()), worker_pid=os.getpid())
        timeout = TIER_TIMEOUTS.get(str(request.get('tier')), TIER_TIMEOUTS['A'])
        execution = _call_upstream(str(request.get('capability')), request.get('arguments', {}), timeout)
        status = str(execution.get('status', 'failed'))
        _finalize_job(directory, request, execution, status)
        return 0 if status == 'completed' else 1
    except BaseException as exc:  # Worker must preserve a terminal record even after an internal error.
        try:
            directory = _job_dir(job_id)
            request = _read_json(directory / 'request.json')
            if request:
                _finalize_job(directory, request, {'success': False, 'status': 'failed', 'error': repr(exc)}, 'failed')
        except BaseException:
            pass
        return 1


def _worker_is_alive(pid: Any) -> bool:
    try:
        value = int(pid)
        if value <= 0:
            return False
        os.kill(value, 0)
        return True
    except (TypeError, ValueError, ProcessLookupError):
        return False
    except PermissionError:
        return True


def execute_capability(
    capability: str,
    arguments_json: str = '{}',
    mode: str = 'src',
    scope_roots: str = '',
    exact_targets: str = '',
    job_id: str = '',
) -> Dict[str, Any]:
    """Validate, enqueue, and durably record one optional upstream capability."""
    tier = CAPABILITY_TIER.get(capability)
    if tier not in {'A', 'B', 'C'}:
        return {'success': False, 'status': 'blocked', 'error': 'capability is not exposed'}
    if mode not in ALLOWED_MODES:
        return {'success': False, 'status': 'blocked', 'error': 'invalid assessment mode'}
    if tier == 'C' and mode not in CONTRACTED_MODES:
        return {'success': False, 'status': 'blocked', 'error': 'C-tier capability requires contracted, lab, or ctf mode'}
    try:
        raw_arguments = json.loads(arguments_json or '{}')
        if not isinstance(raw_arguments, dict):
            raise ValueError('arguments_json must contain a JSON object')
        roots = _parse_list(scope_roots)
        exact = _parse_list(exact_targets)
        if not roots:
            raise ValueError('scope_roots is required')
        arguments = _prepare_arguments(capability, mode, raw_arguments)
        if capability in {'nmap_scan', 'nmap_advanced_scan'} and not arguments.get('target'):
            if len(exact) != 1:
                raise ValueError('nmap requires exactly one exact target when arguments_json omits target')
            target = _extract_host(exact[0])
            if not target:
                raise ValueError('nmap exact target has no valid host')
            arguments['target'] = target
        _validate_scope(capability, tier, arguments, roots, exact)
        effective_job_id = job_id or _new_job_id(capability)
        directory = _job_dir(effective_job_id)
    except (ValueError, TypeError, json.JSONDecodeError) as exc:
        return {'success': False, 'status': 'blocked', 'error': str(exc)}
    binary = CAPABILITY_BINARIES.get(capability)
    tool_path = _tool_path(capability)
    if binary and not tool_path:
        return {'success': False, 'status': 'unavailable', 'capability': capability, 'required_binary': binary, 'error': f'required binary {binary} is not installed or not on PATH'}
    request_record = {
        'schema_version': 2,
        'job_id': effective_job_id,
        'capability': capability,
        'tier': tier,
        'mode': mode,
        'scope_roots': roots,
        'exact_targets': exact,
        'arguments': arguments,
        'tool_path': tool_path,
        'started_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
    }
    try:
        directory.mkdir(parents=True, exist_ok=False)
        _atomic_json(directory / 'request.json', request_record)
        _write_state(directory, 'queued', accepted_at=request_record['started_at'])
        worker_log = directory / 'worker.log'
        with worker_log.open('a', encoding='utf-8') as handle:
            process = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), '--worker', effective_job_id], stdout=handle, stderr=handle, start_new_session=True, close_fds=True)
        state = _read_json(_state_path(directory))
        if str(state.get('status')) not in TERMINAL_JOB_STATES:
            _write_state(directory, str(state.get('status') or 'queued'), worker_pid=process.pid)
    except (OSError, ValueError) as exc:
        if directory.exists() and (directory / 'request.json').exists():
            _finalize_job(directory, request_record, {'success': False, 'status': 'failed', 'error': repr(exc)}, 'failed')
        return {'success': False, 'status': 'failed', 'job_id': effective_job_id, 'error': str(exc)}
    return {'success': True, 'status': 'queued', 'job_id': effective_job_id, 'capability': capability, 'tier': tier, 'artifact_dir': str(directory), 'claim_state': 'candidate', 'integrity': False}


mcp = FastMCP("HexStrike Policy Gateway")


@mcp.tool()
def hexstrike_capability_catalog(
    mode: str = "src", include_unavailable: bool = True
) -> Dict[str, Any]:
    """List exposed HexStrike capabilities, tiers, and current binary readiness."""
    if mode not in ALLOWED_MODES:
        return {"success": False, "error": "invalid assessment mode"}
    allowed_tiers = {"A", "B", "C"} if mode in CONTRACTED_MODES else {"A", "B"}
    capabilities = []
    for capability in EXPOSED_CAPABILITIES:
        tier = CAPABILITY_TIER[capability]
        if tier not in allowed_tiers:
            continue
        binary = CAPABILITY_BINARIES.get(capability)
        path = _tool_path(capability)
        available = not binary or bool(path)
        if include_unavailable or available:
            capabilities.append(
                {
                    "name": capability,
                    "tier": tier,
                    "available": available,
                    "required_binary": binary,
                    "tool_path": path,
                }
            )
    return {
        "success": True,
        "mode": mode,
        "exposed_count": len(capabilities),
        "capabilities": capabilities,
        "blocked_count": len(POLICY["D"]),
    }


@mcp.tool()
def hexstrike_preflight() -> Dict[str, Any]:
    """Check the loopback REST service and summarize currently runnable tools."""
    health: Dict[str, Any]
    try:
        with urllib.request.urlopen(f"{HEXSTRIKE_API_URL}/health", timeout=30) as response:
            health = json.loads(response.read().decode("utf-8"))
    except Exception as exc:  # noqa: BLE001 - return structured preflight failure
        return {
            "success": False,
            "status": "unavailable",
            "api_url": HEXSTRIKE_API_URL,
            "error": str(exc),
        }

    available = [
        capability
        for capability in EXPOSED_CAPABILITIES
        if not CAPABILITY_BINARIES.get(capability) or _tool_path(capability)
    ]
    httpx_path = shutil.which("httpx", path=TOOL_SEARCH_PATH)
    httpx_is_projectdiscovery = bool(httpx_path and "/go/bin/" in httpx_path)
    return {
        "success": health.get("status") == "healthy" and httpx_is_projectdiscovery,
        "status": health.get("status"),
        "version": health.get("version"),
        "api_url": HEXSTRIKE_API_URL,
        "exposed_capabilities": len(EXPOSED_CAPABILITIES),
        "runnable_capabilities": len(available),
        "httpx_path": httpx_path,
        "httpx_projectdiscovery": httpx_is_projectdiscovery,
        "upstream_available_binaries": health.get("total_tools_available"),
        "upstream_checked_binaries": health.get("total_tools_count"),
    }


@mcp.tool()
def hexstrike_job_status(job_id: str) -> Dict[str, Any]:
    """Read durable job state and expose integrity only after terminal artifacts exist."""
    try:
        directory = _job_dir(job_id)
        request = _read_json(directory / 'request.json')
        state = _read_json(_state_path(directory))
        if not request or not state:
            return {'success': False, 'status': 'not_found', 'job_id': job_id, 'integrity': False}
        status = str(state.get('status', 'queued'))
        result_path = directory / 'result.json'
        if status not in TERMINAL_JOB_STATES and not result_path.exists():
            updated = state.get('updated_at', '')
            age = time.time() - (directory.stat().st_mtime if directory.exists() else time.time())
            if not _worker_is_alive(state.get('worker_pid')) and age >= WORKER_START_GRACE_SECONDS:
                _finalize_job(directory, request, {'success': False, 'status': 'aborted', 'error': 'worker exited before terminal artifact'}, 'aborted')
                state = _read_json(_state_path(directory))
                status = str(state.get('status', 'aborted'))
        if status not in TERMINAL_JOB_STATES or not result_path.exists() or not (directory / 'SHA256SUMS.json').exists():
            return {'success': False, 'status': status, 'job_id': job_id, 'capability': request.get('capability'), 'integrity': False, 'artifact_dir': str(directory)}
        result = _read_json(result_path)
        sums = _read_json(directory / 'SHA256SUMS.json')
        integrity = bool(sums) and all((directory / name).is_file() and _sha256(directory / name) == digest for name, digest in sums.items())
        completed = status == 'completed' and bool(result.get('execution', {}).get('success'))
        return {'success': completed and integrity, 'status': status, 'job_id': job_id, 'capability': result.get('capability', request.get('capability')), 'claim_state': result.get('claim_state', 'candidate'), 'integrity': integrity, 'artifact_dir': str(directory)}
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        return {'success': False, 'status': 'invalid', 'error': str(exc), 'integrity': False}


def _make_capability_tool(capability: str):
    tier = CAPABILITY_TIER[capability]

    def invoke(
        arguments_json: str = "{}",
        mode: str = "src",
        scope_roots: str = "",
        exact_targets: str = "",
        job_id: str = "",
    ) -> Dict[str, Any]:
        return execute_capability(
            capability,
            arguments_json=arguments_json,
            mode=mode,
            scope_roots=scope_roots,
            exact_targets=exact_targets,
            job_id=job_id,
        )

    invoke.__name__ = f"hexstrike_run_{capability}"
    invoke.__doc__ = (
        f"Run HexStrike capability {capability} through the policy gateway "
        f"(tier {tier}). Arguments must be a JSON object; scope is mandatory."
    )
    return invoke


for _capability in EXPOSED_CAPABILITIES:
    mcp.tool()(_make_capability_tool(_capability))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('--worker', default='')
    args, _unknown = parser.parse_known_args()
    JOB_ROOT.mkdir(parents=True, exist_ok=True)
    if args.worker:
        raise SystemExit(_run_job(args.worker))
    mcp.run()
