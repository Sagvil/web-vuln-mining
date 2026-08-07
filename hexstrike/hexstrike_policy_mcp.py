#!/usr/bin/env python3
"""Policy-controlled MCP faГ§ade for the upstream HexStrike MCP server."""

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
JOB_ROOT = Path(os.environ.get("HEXSTRIKE_JOB_ROOT", "/home/sagvil/жё—йЂЏ/hexstrike-jobs"))
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
        "/home/sagvil/жё—йЂЏ:/home/sagvil/hexstrike-policy",
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
        temp_nameЯ[h‘йм¶»§q«^tH\ЪX‹њЪLЌMЉ
B€Ъ]]›Ь[Љњ€ЉH\И[™N‚€›Ь€Ъ[љИ[€]\Љ[X™N€[™Kњ™XY
LЌ
€LЌ
K€€ЉN‚€YЩ\Эќ\]JЪ[љКB€™]\›€YЩ\Эљ^YЩ\Э

B‚‚™Y€Ь™XYЪњЫЫЉ]€]
HO€XЭЬЭ‹[ћWN‚€ћN‚€[YHHњЫЫ‹›ШYК]њ™XYЭ^
[ЫЩ[™ПIЭ]‹N	КJB€™]\›€[YHY€\Ъ[њЭ[ЩJ[YKXЭ
H[ЩHЯB€^Щ\
ФС\њ›Ь‹њЫЫ‹’”УУ‘XЫЩQ\њ›ЬЉN‚€™]\›€ЯB‚‚™Y€ЬЭ]WЬ]
\™XЭЬћN€]
HO€]‚€™]\›€\™XЭЬћHИ“Р—ФХUWС’SB‚‚™Y€ЭЬљ]WЬЭ]J\™XЭЬћN€]Э]\О€Э‹
Љ™љY[О€[ћJHO€XЭЬЭ‹[ћWN‚€Y€Э]\И›Э[€ЙЬ]Y]YY	Л	Ьќ[›љ[™ЙЛ
•T“RSђSТ“Р—ФХUTЯN‚€Z\ЩH[YQ\њ›ЬЉ‰Ъ[ќ[Y›Ш€Э]\О€ЬЭ]\ЯIКB€Э]HHЬ™XYЪњЫЫЉЬЭ]WЬ]
\™XЭЬћJJB€Э]Kќ\]JљY[КB€Э]VЙЬШЪ[XWЭ™\њЪ[Ы‰ЧHHB€Э]VЙЬЭ]\ЙЧHHЭ]\В€Э]VЙЭ\]YШ]	ЧHH[YKњЭ™ќ[YJ	ЙVKI[KIY	R‰SN‰TЦ‰Л[YK™Ы][YJ
JB€Ш]ЫZXЧЪњЫЫЉЬЭ]WЬ]
\™XЭЬћJKЭ]JB€™]\›€Э]B‚‚™Y€Э\Э™X[WШЫЫ[X[™
[Y[Э]€[ќ
HO€ЭЋ‚€€€’ЩY\H\Э™X[HЫY[ќ[™\ЭPФ[Y[Э]ќYЩ]ИY[ќXШ[€€€‚€™]\›€	И	Лљ›Ъ[ЉЪ^њ][ЭJ\ќ
H›Ь€\ќ[€
ЭЉVХ’RСWФUУЉKЭЉTХ‘PSWУPФ
K	ЛK\Щ\ќ™\‰ЛЭЉVХ’RСWРTWХT“
K	ЛK][Y[Э]	ЛЭЉ[Y[Э]
JJB‚‚™Y€ШШ[Э\Э™X[JШ\Xљ[]N€Э‹\™Э[Y[ќО€X\[™ЦЬЭ‹[ћWK[Y[Э]€[ќ
HO€XЭЬЭ‹[ћWN‚€ЫЫ[X[™HВ€ђTХPФР’S‹€	ШШ[	Л€	ЛKXЫЫ[X[™	Л€Э\Э™X[WШЫЫ[X[™
[Y[Э]
K€	ЛK]\™Щ]	Л€Ш\Xљ[]K€	ЛKZ[њ]ZњЫЫ‰Л€њЫЫ‹™[\К\™Э[Y[ќЛ[њЭ\™WШ\ШЪZOQ[ЩKЩ\\]ЬњПJ	Л	Л	О‰КJK€	ЛKZњЫЫ‰Л€	ЛK][Y[Э]	Л€ЭЉ[Y[Э]
K€B€Э\ќYH[YKќ[YJ
B€ЫЫ[X[™Щ[ќљ\›Ы›Y[ќHЬЛ™[ќљ\›Ы‹ЫЬJ
B€ЫЫ[X[™Щ[ќљ\›Ы›Y[ќЙФU	ЧHHУУФСPTђТФU€ћN‚€ЫЫ\]YHЭXњ›ШЩ\ЬЛњќ[ЉЫЫ[X[™Ш\\™WЫЭ]]UќYK^UќYK[Y[Э]][Y[Э]
ИЊЪXЪПQ[ЩK[ќЏXЫЫ[X[™Щ[ќљ\›Ы›Y[ќ
B€^Щ\ЭXњ›ШЩ\ЬЛ•[Y[Э]^\™Y\И^О‚€™]\›€ЙЬЭXШЩ\ЬЙО€[ЩK	ЬЭ]\ЙО€	Э[Y[Э]	Л	Щ\њ›Ь‰О€ЭЉ^КK	Щ^XЭ][Ы—Э[YIО€[YKќ[YJ
HHЭ\ќYB€\њЩY€[ћHH›Ы™B€Y€ЫЫ\]YњЭЭ]њЭљ\

N‚€ћN‚€\њЩYHњЫЫ‹›ШYКЫЫ\]YњЭЭ]
B€^Щ\њЫЫ‹’”УУ‘XЫЩQ\њ›ЬЋ‚€\њЩYH›Ы™B€™]\›€В€	ЬЭXШЩ\ЬЙО€ЫЫ\]Yњ™]\›ЫЩHOH[™\њЩY\И›Э›Ы™K€	ЬЭ]\ЙО€	ШЫЫ\]Y	ИY€ЫЫ\]Yњ™]\›ЫЩHOH[™\њЩY\И›Э›Ы™H[ЩH	ЩZ[Y	Л€	Ь™]\›ЫЩIО€ЫЫ\]Yњ™]\›ЫЩK€	Щ^XЭ][Ы—Э[YIО€[YKќ[YJ
HHЭ\ќY€	Ь™\Э[	О€\њЩY€	ЬЭЭ]	О€ЫЫ\]YњЭЭ]€	ЬЭ\њ‰О€ЫЫ\]YњЭ\њ‹€B‚‚™Y€Щљ[[^™WЪ›ШЉ\™XЭЬћN€]™\]Y\Э€X\[™ЦЬЭ‹[ћWK^XЭ][ЫЋ€X\[™ЦЬЭ‹[ћWKЭ]\О€ЭЉHO€XЭЬЭ‹[ћWN‚€€€•Ьљ]H\›Z[[\ќYXЭИ]ЫZXШ[H›Ь€]™\ћHXШЩ\Y›Ш‹€€€‚€љ[[ЬЭ]\ИHЭ]\ИY€Э]\И[€T“RSђSТ“Р—ФХUTИ[ЩH	ЩZ[Y	В€™\Э[Ь™XЫЬ™HВ€
Љ™XЭ
™\]Y\Э
K€	ШЫЫ\]YШ]	О€[YKњЭ™ќ[YJ	ЙVKI[KIY	R‰SN‰TЦ‰Л[YK™Ы][YJ
JK€	ЬЭ]\ЙО€љ[[ЬЭ]\Л€	Щ^XЭ][Ы‰О€XЭ
^XЭ][ЫЉK€	ШЫZ[WЬЭ]IО€	ШШ[™Y]IЛ€	Э™\љYљYY	О€[ЩK€B€™\Э[Ь]H\™XЭЬћHИ	Ь™\Э[љњЫЫ‰В€Ш]ЫZXЧЪњЫЫЉ™\Э[Ь]™\Э[Ь™XЫЬ™
B€™\]Y\ЭЬ]H\™XЭЬћHИ	Ь™\]Y\ЭљњЫЫ‰В€Э[\ИHЙЬ™\]Y\ЭљњЫЫ‰О€ЬЪLЌMЉ™\]Y\ЭЬ]
K	Ь™\Э[љњЫЫ‰О€ЬЪLЌMЉ™\Э[Ь]
_B€Ш]ЫZXЧЪњЫЫЉ\™XЭЬћHИ	ФТLЌM”ХSTЛљњЫЫ‰ЛЭ[\КB€ЭЬљ]WЬЭ]J\™XЭЬћKљ[[ЬЭ]\ЛЫЫ\]YШ]\™\Э[Ь™XЫЬ™ЙШЫЫ\]YШ]	ЧJB€™]\›€™\Э[Ь™XЫЬ™‚‚™Y€Ьќ[—Ъ›ШЉ›Ш—ЪY€ЭЉHO€[ќ‚€€€‘]XЪYЫЬљЩ\€[ќћ\Ъ[ќИ[Ш^\ИX]™\ИH\›Z[[™\Э[\ќYXЭ€€€‚€ћN‚€\™XЭЬћHHЪ›Ш—Щ\Љ›Ш—ЪY
B€™\]Y\ЭHЬ™XYЪњЫЫЉ\™XЭЬћHИ	Ь™\]Y\ЭљњЫЫ‰КB€Y€›Э™\]Y\Э‚€™]\›€‚€ЭЬљ]WЬЭ]J\™XЭЬћK	Ьќ[›љ[™ЙЛЭ\ќYШ]][YKњЭ™ќ[YJ	ЙVKI[KIY	R‰SN‰TЦ‰Л[YK™Ы][YJ
JKЫЬљЩ\—ЬY[ЬЛ™Щ]Y

JB€[Y[Э]HQT—ХSQSХUЛ™Щ]
ЭЉ™\]Y\Э™Щ]
	ЭY\‰КJKQT—ХSQSХUЦЙРIЧJB€^XЭ][Ы€HШШ[Э\Э™X[JЭЉ™\]Y\Э™Щ]
	ШШ\Xљ[]IКJK™\]Y\Э™Щ]
	Ш\™Э[Y[ќЙЛЯJK[Y[Э]
B€Э]\ИHЭЉ^XЭ][Ы‹™Щ]
	ЬЭ]\ЙЛ	ЩZ[Y	КJB€Щљ[[^™WЪ›ШЉ\™XЭЬћK™\]Y\Э^XЭ][Ы‹Э]\КB€™]\›€Y€Э]\ИOH	ШЫЫ\]Y	И[ЩHB€^Щ\\ЩQ^Щ\[Ы€\И^О€ИЫЬљЩ\€]\Э™\Щ\ќ™HH\›Z[[™XЫЬ™]™[€Yќ\€[€[ќ\›[\њ›Ь‹‚€ћN‚€\™XЭЬћHHЪ›Ш—Щ\Љ›Ш—ЪY
B€™\]Y\ЭHЬ™XYЪњЫЫЉ\™XЭЬћHИ	Ь™\]Y\ЭљњЫЫ‰КB€Y€™\]Y\Э‚€Щљ[[^™WЪ›ШЉ\™XЭЬћK™\]Y\ЭЙЬЭXШЩ\ЬЙО€[ЩK	ЬЭ]\ЙО€	ЩZ[Y	Л	Щ\њ›Ь‰О€™\Љ^К_K	ЩZ[Y	КB€^Щ\\ЩQ^Щ\[ЫЋ‚€\ЬВ€™]\›€B‚‚™Y€ЭЫЬљЩ\—Ъ\ЧШ[]™JY€[ћJHO€›ЫЫ‚€ћN‚€[YHH[ќ
Y
B€Y€[YHH‚€™]\›€[ЩB€ЬЛљЪ[
[YK
B€™]\›€ќYB€^Щ\
\Q\њ›Ь‹[YQ\њ›Ь‹›ШЩ\ЬУЫЪЭ\\њ›ЬЉN‚€™]\›€[ЩB€^Щ\\›Z\ЬЪ[Ы‘\њ›ЬЋ‚€™]\›€ќYB‚‚™Y€^XЭ]WШШ\Xљ[]J€Ш\Xљ[]N€Э‹€\™Э[Y[ќЧЪњЫЫЋ€Э€H	ЮЯIЛ€[ЩN€Э€H	ЬЬЙЛ€ШЫЬWЬ›ЫЭО€Э€H	ЙЛ€^XЭЭ\™Щ]О€Э€H	ЙЛ€›Ш—ЪY€Э€H	ЙЛЉHO€XЭЬЭ‹[ћWN‚€€€•[Y]K[њ]Y]YK[™\X›H™XЫЬ™Ы™HЬ[Ы[\Э™X[HШ\Xљ[]K€€€‚€Y\€HРTP’SUWХQT‹™Щ]
Ш\Xљ[]JB€Y€Y\€›Э[€ЙРIЛ	Р‰Л	РЙЯN‚€™]\›€ЙЬЭXШЩ\ЬЙО€[ЩK	ЬЭ]\ЙО€	Ш›ШЪЩY	Л	Щ\њ›Ь‰О€	ШШ\Xљ[]H\И›Э^ЬЩY	ЯB€Y€[ЩH›Э[€SХСQУSСTО‚€™]\›€ЙЬЭXШЩ\ЬЙО€[ЩK	ЬЭ]\ЙО€	Ш›ШЪЩY	Л	Щ\њ›Ь‰О€	Ъ[ќ[Y\ЬЩ\ЬЫY[ќ[ЩIЯB€Y€Y\€OH	РЙИ[™[ЩH›Э[€УУ•ђPХQУSСTО‚€™]\›€ЙЬЭXШЩ\ЬЙО€[ЩK	ЬЭ]\ЙО€	Ш›ШЪЩY	Л	Щ\њ›Ь‰О€	РЛ]Y\€Ш\Xљ[]H™\]Z\™\ИЫЫќXЭYX‹Ь€Э€[ЩIЯB€ћN‚€]ЧШ\™Э[Y[ќИHњЫЫ‹›ШYК\™Э[Y[ќЧЪњЫЫ€Ь€	ЮЯIКB€Y€›Э\Ъ[њЭ[ЩJ]ЧШ\™Э[Y[ќЛXЭ
N‚€Z\ЩH[YQ\њ›ЬЉ	Ш\™Э[Y[ќЧЪњЫЫ€]\ЭЫЫќZ[€H”УУ€Шљ™XЭ	КB€›ЫЭИHЬ\њЩWЫ\Э
ШЫЬWЬ›ЫЭКB€^XЭHЬ\њЩWЫ\Э
^XЭЭ\™Щ]КB€Y€›Э›ЫЭО‚€Z\ЩH[YQ\њ›ЬЉ	ЬШЫЬWЬ›ЫЭИ\И™\]Z\™Y	КB€\™Э[Y[ќИHЬ™\\™WШ\™Э[Y[ќКШ\Xљ[]K[ЩK]ЧШ\™Э[Y[ќКB€Y€Ш\Xљ[]H[€ЙЫ›X\ЬШШ[‰Л	Ы›X\ШY[ЩYЬШШ[‰ЯH[™›Э\™Э[Y[ќЛ™Щ]
	Э\™Щ]	КN‚€Y€[Љ^XЭ
HOHN‚€Z\ЩH[YQ\њ›ЬЉ	Ы›X\™\]Z\™\И^XЭHЫ™H^XЭ\™Щ]Ъ[€\™Э[Y[ќЧЪњЫЫ€ЫZ]И\™Щ]	КB€\™Щ]HЩ^XЭЪЬЭ
^XЭМJB€Y€›Э\™Щ]‚€Z\ЩH[YQ\њ›ЬЉ	Ы›X\^XЭ\™Щ]\И›И[YЬЭ	КB€\™Э[Y[ќЦЙЭ\™Щ]	ЧHH\™Щ]€Э[Y]WЬШЫЬJШ\Xљ[]KY\‹\™Э[Y[ќЛ›ЫЭЛ^XЭ
B€Y™™XЭ]™WЪ›Ш—ЪYH›Ш—ЪYЬ€Ы™]ЧЪ›Ш—ЪY
Ш\Xљ[]JB€\™XЭЬћHHЪ›Ш—Щ\ЉY™™XЭ]™WЪ›Ш—ЪY
B€^Щ\
[YQ\њ›Ь‹\Q\њ›Ь‹њЫЫ‹’”УУ‘XЫЩQ\њ›ЬЉH\И^О‚€™]\›€ЙЬЭXШЩ\ЬЙО€[ЩK	ЬЭ]\ЙО€	Ш›ШЪЩY	Л	Щ\њ›Ь‰О€ЭЉ^К_B€љ[\ћHHРTP’SUWР’SђT’QTЛ™Щ]
Ш\Xљ[]JB€ЫЫЬ]HЭЫЫЬ]
Ш\Xљ[]JB€Y€љ[\ћH[™›ЭЫЫЬ]‚€™]\›€ЙЬЭXШЩ\ЬЙО€[ЩK	ЬЭ]\ЙО€	Э[]Z[X›IЛ	ШШ\Xљ[]IО€Ш\Xљ[]K	Ь™\]Z\™YШљ[\ћIО€љ[\ћK	Щ\њ›Ь‰О€‰Ь™\]Z\™Yљ[\ћHШљ[\ћ_H\И›Э[њЭ[YЬ€›ЭЫ€U	ЯB€™\]Y\ЭЬ™XЫЬ™HВ€	ЬШЪ[XWЭ™\њЪ[Ы‰О€‹€	Ъ›Ш—ЪY	О€Y™™XЭ]™WЪ›Ш—ЪY€	ШШ\Xљ[]IО€Ш\Xљ[]K€	ЭY\‰О€Y\‹€	Ы[ЩIО€[ЩK€	ЬШЫЬWЬ›ЫЭЙО€›ЫЭЛ€	Щ^XЭЭ\™Щ]ЙО€^XЭ€	Ш\™Э[Y[ќЙО€\™Э[Y[ќЛ€	ЭЫЫЬ]	О€ЫЫЬ]€	ЬЭ\ќYШ]	О€[YKњЭ™ќ[YJ	ЙVKI[KIY	R‰SN‰TЦ‰Л[YK™Ы][YJ
JK€B€ћN‚€\™XЭЬћK›ZЩ\Љ\™[ќПUќYK^\ЭЫЪПQ[ЩJB€Ш]ЫZXЧЪњЫЫЉ\™XЭЬћHИ	Ь™\]Y\ЭљњЫЫ‰Л™\]Y\ЭЬ™XЫЬ™
B€ЭЬљ]WЬЭ]J\™XЭЬћK	Ь]Y]YY	ЛXШЩ\YШ]\™\]Y\ЭЬ™XЫЬ™ЙЬЭ\ќYШ]	ЧJB€ЫЬљЩ\—ЫЩИH\™XЭЬћHИ	ЭЫЬљЩ\‹›ЩЙВ€Ъ]ЫЬљЩ\—ЫЩЛ›Ь[Љ	ШIЛ[ЫЩ[™ПIЭ]‹N	КH\И[™N‚€›ШЩ\ЬИHЭXњ›ШЩ\ЬЛ”Ь[ЉЬЮ\Л™^XЭ]X›KЭЉ]
ЧЩљ[WЧКKњ™\ЫЫ™J
JK	ЛK]ЫЬљЩ\‰ЛY™™XЭ]™WЪ›Ш—ЪYKЭЭ]Z[™KЭ\њЏZ[™KЭ\ќЫ™]ЧЬЩ\ЬЪ[ЫЏUќYKЫЬЩWЩ™ПUќYJB€Э]HHЬ™XYЪњЫЫЉЬЭ]WЬ]
\™XЭЬћJJB€Y€ЭЉЭ]K™Щ]
	ЬЭ]\ЙКJH›Э[€T“RSђSТ“Р—ФХUTО‚€ЭЬљ]WЬЭ]J\™XЭЬћKЭЉЭ]K™Щ]
	ЬЭ]\ЙКHЬ€	Ь]Y]YY	КKЫЬљЩ\—ЬY\›ШЩ\ЬЛњY
B€^Щ\
ФС\њ›Ь‹[YQ\њ›ЬЉH\И^О‚€Y€\™XЭЬћK™^\ЭК
H[™
\™XЭЬћHИ	Ь™\]Y\ЭљњЫЫ‰КK™^\ЭК
N‚€Щљ[[^™WЪ›ШЉ\™XЭЬћK™\]Y\ЭЬ™XЫЬ™ЙЬЭXШЩ\ЬЙО€[ЩK	ЬЭ]\ЙО€	ЩZ[Y	Л	Щ\њ›Ь‰О€™\Љ^К_K	ЩZ[Y	КB€™]\›€ЙЬЭXШЩ\ЬЙО€[ЩK	ЬЭ]\ЙО€	ЩZ[Y	Л	Ъ›Ш—ЪY	О€Y™™XЭ]™WЪ›Ш—ЪY	Щ\њ›Ь‰О€ЭЉ^К_B€™]\›€ЙЬЭXШЩ\ЬЙО€ќYK	ЬЭ]\ЙО€	Ь]Y]YY	Л	Ъ›Ш—ЪY	О€Y™™XЭ]™WЪ›Ш—ЪY	ШШ\Xљ[]IО€Ш\Xљ[]K	ЭY\‰О€Y\‹	Ш\ќYXЭЩ\‰О€ЭЉ\™XЭЬћJK	ШЫZ[WЬЭ]IО€	ШШ[™Y]IЛ	Ъ[ќYЬљ]IО€[Щ_B‚‚›XЬH\ЭPФ
’^ЭљZЩHЫXЮHШ]]Ш^HЉB‚‚ђXЬќЫЫ

B™Y€^ЭљZЩWШШ\Xљ[]WШШ][ЩК€[ЩN€Э€HњЬИ‹[ЫYWЭ[]Z[X›N€›ЫЫHќYBЉHO€XЭЬЭ‹[ћWN‚€€€“\Э^ЬЩY^ЭљZЩHШ\Xљ[]Y\ЛY\њЛ[™Э\њ™[ќљ[\ћH™XY[™\ЬЛ€€€‚€Y€[ЩH›Э[€SХСQУSСTО‚€™]\›€ИњЭXШЩ\ЬИЋ€[ЩK™\њ›Ь€Ћ€љ[ќ[Y\ЬЩ\ЬЫY[ќ[ЩHџB€[ЭЩYЭY\њИHИђH‹ђ€‹ђИџHY€[ЩH[€УУ•ђPХQУSСTИ[ЩHИђH‹ђ€џB€Ш\Xљ[]Y\ИHЧB€›Ь€Ш\Xљ[]H[€VФСQРРTP’SUQTО‚€Y\€HРTP’SUWХQT–ШШ\Xљ[]WB€Y€Y\€›Э[€[ЭЩYЭY\њО‚€ЫЫќ[ќYB€љ[\ћHHРTP’SUWР’SђT’QTЛ™Щ]
Ш\Xљ[]JB€]HЭЫЫЬ]
Ш\Xљ[]JB€]Z[X›HH›Эљ[\ћHЬ€›ЫЫ
]
B€Y€[ЫYWЭ[]Z[X›HЬ€]Z[X›N‚€Ш\Xљ[]Y\Л\[™
€В€›[YHЋ€Ш\Xљ[]K€ќY\€Ћ€Y\‹€]Z[X›HЋ€]Z[X›K€њ™\]Z\™YШљ[\ћHЋ€љ[\ћK€ќЫЫЬ]Ћ€]€B€
B€™]\›€В€њЭXШЩ\ЬИЋ€ќYK€›[ЩHЋ€[ЩK€™^ЬЩYШЫЭ[ќЋ€[ЉШ\Xљ[]Y\КK€Ш\Xљ[]Y\ИЋ€Ш\Xљ[]Y\Л€›ШЪЩYШЫЭ[ќЋ€[ЉУPЦVИ‘—JK€B‚‚ђXЬќЫЫ

B™Y€^ЭљZЩWЬ™Y›YЪ

HO€XЭЬЭ‹[ћWN‚€€€ђЪXЪИHЫЬXЪИ‘TХЩ\ќљXЩH[™Э[[X\љ^™HЭ\њ™[ќHќ[›X›HЫЫЛ€€€‚€X[€XЭЬЭ‹[ћWB€ћN‚€Ъ]\›X‹њ™\]Y\Эќ\›Ь[Љ€ћТVХ’RСWРTWХT“KЪX[‹[Y[Э]LМ
H\И™\ЬЫњЩN‚€X[HњЫЫ‹›ШYК™\ЬЫњЩKњ™XY

K™XЫЩJќ]‹NЉJB€^Щ\^Щ\[Ы€\И^О€И›ЬXN€“LHH™]\›€ЭќXЭ\™Y™Y›YЪZ[\™B€™]\›€В€њЭXШЩ\ЬИЋ€[ЩK€њЭ]\ИЋ€ќ[]Z[X›H‹€\WЭ\›Ћ€VХ’RСWРTWХT“€™\њ›Ь€Ћ€ЭЉ^КK€B‚€]Z[X›HHВ€Ш\Xљ[]B€›Ь€Ш\Xљ[]H[€VФСQРРTP’SUQTВ€Y€›ЭРTP’SUWР’SђT’QTЛ™Щ]
Ш\Xљ[]JHЬ€ЭЫЫЬ]
Ш\Xљ[]JB€B€Ь]HЪ][ќЪXЪ
љ‹]UУУФСPTђТФU
B€Ъ\ЧЬ›Ъ™XЭ\ШЫЭ™\ћHH›ЫЫ
Ь][™‹ЩЫЛШљ[‹И€[€Ь]
B€™]\›€В€њЭXШЩ\ЬИЋ€X[™Щ]
њЭ]\ИЉHOHљX[H€[™Ъ\ЧЬ›Ъ™XЭ\ШЫЭ™\ћK€њЭ]\ИЋ€X[™Щ]
њЭ]\ИЉK€ќ™\њЪ[Ы€Ћ€X[™Щ]
ќ™\њЪ[Ы€ЉK€\WЭ\›Ћ€VХ’RСWРTWХT“€™^ЬЩYШШ\Xљ[]Y\ИЋ€[ЉVФСQРРTP’SUQTКK€њќ[›X›WШШ\Xљ[]Y\ИЋ€[Љ]Z[X›JK€љЬ]Ћ€Ь]€љЬ›Ъ™XЭ\ШЫЭ™\ћHЋ€Ъ\ЧЬ›Ъ™XЭ\ШЫЭ™\ћK€ќ\Э™X[WШ]Z[X›WШљ[\љY\ИЋ€X[™Щ]
ќЭ[ЭЫЫЧШ]Z[X›HЉK€ќ\Э™X[WШЪXЪЩYШљ[\љY\ИЋ€X[™Щ]
ќЭ[ЭЫЫЧШЫЭ[ќЉK€B‚‚ђXЬќЫЫ

B™Y€^ЭљZЩWЪ›Ш—ЬЭ]\К›Ш—ЪY€ЭЉHO€XЭЬЭ‹[ћWN‚€€€”™XY\X›H›Ш€Э]H[™^ЬЩH[ќYЬљ]HЫ›HYќ\€\›Z[[\ќYXЭИ^\Э€€€‚€ћN‚€\™XЭЬћHHЪ›Ш—Щ\Љ›Ш—ЪY
B€™\]Y\ЭHЬ™XYЪњЫЫЉ\™XЭЬћHИ	Ь™\]Y\ЭљњЫЫ‰КB€Э]HHЬ™XYЪњЫЫЉЬЭ]WЬ]
\™XЭЬћJJB€Y€›Э™\]Y\ЭЬ€›ЭЭ]N‚€™]\›€ЙЬЭXШЩ\ЬЙО€[ЩK	ЬЭ]\ЙО€	Ы›ЭЩ›Э[™	Л	Ъ›Ш—ЪY	О€›Ш—ЪY	Ъ[ќYЬљ]IО€[Щ_B€Э]\ИHЭЉЭ]K™Щ]
	ЬЭ]\ЙЛ	Ь]Y]YY	КJB€™\Э[Ь]H\™XЭЬћHИ	Ь™\Э[љњЫЫ‰В€Y€Э]\И›Э[€T“RSђSТ“Р—ФХUTИ[™›Э™\Э[Ь]™^\ЭК
N‚€\]YHЭ]K™Щ]
	Э\]YШ]	Л	ЙКB€YЩHH[YKќ[YJ
HH
\™XЭЬћKњЭ]

KњЭЫ][YHY€\™XЭЬћK™^\ЭК
H[ЩH[YKќ[YJ
JB€Y€›ЭЭЫЬљЩ\—Ъ\ЧШ[]™JЭ]K™Щ]
	ЭЫЬљЩ\—ЬY	КJH[™YЩHЏHУФ’СT—ФХT•СФђPСWФСPУУ‘О‚€Щљ[[^™WЪ›ШЉ\™XЭЬћK™\]Y\ЭЙЬЭXШЩ\ЬЙО€[ЩK	ЬЭ]\ЙО€	ШX›ЬќY	Л	Щ\њ›Ь‰О€	ЭЫЬљЩ\€^]Y™Y›Ь™H\›Z[[\ќYXЭ	ЯK	ШX›ЬќY	КB€Э]HHЬ™XYЪњЫЫЉЬЭ]WЬ]
\™XЭЬћJJB€Э]\ИHЭЉЭ]K™Щ]
	ЬЭ]\ЙЛ	ШX›ЬќY	КJB€Y€Э]\И›Э[€T“RSђSТ“Р—ФХUTИЬ€›Э™\Э[Ь]™^\ЭК
HЬ€›Э
\™XЭЬћHИ	ФТLЌM”ХSTЛљњЫЫ‰КK™^\ЭК
N‚€™]\›€ЙЬЭXШЩ\ЬЙО€[ЩK	ЬЭ]\ЙО€Э]\Л	Ъ›Ш—ЪY	О€›Ш—ЪY	ШШ\Xљ[]IО€™\]Y\Э™Щ]
	ШШ\Xљ[]IКK	Ъ[ќYЬљ]IО€[ЩK	Ш\ќYXЭЩ\‰О€ЭЉ\™XЭЬћJ_B€™\Э[HЬ™XYЪњЫЫЉ™\Э[Ь]
B€Э[\ИHЬ™XYЪњЫЫЉ\™XЭЬћHИ	ФТLЌM”ХSTЛљњЫЫ‰КB€[ќYЬљ]HH›ЫЫ
Э[\КH[™[

\™XЭЬћHИ[YJKљ\ЧЩљ[J
H[™ЬЪLЌMЉ\™XЭЬћHИ[YJHOHYЩ\Э›Ь€[YKYЩ\Э[€Э[\Лљ][\К
JB€ЫЫ\]YHЭ]\ИOH	ШЫЫ\]Y	И[™›ЫЫ
™\Э[™Щ]
	Щ^XЭ][Ы‰ЛЯJK™Щ]
	ЬЭXШЩ\ЬЙКJB€™]\›€ЙЬЭXШЩ\ЬЙО€ЫЫ\]Y[™[ќYЬљ]K	ЬЭ]\ЙО€Э]\Л	Ъ›Ш—ЪY	О€›Ш—ЪY	ШШ\Xљ[]IО€™\Э[™Щ]
	ШШ\Xљ[]IЛ™\]Y\Э™Щ]
	ШШ\Xљ[]IКJK	ШЫZ[WЬЭ]IО€™\Э[™Щ]
	ШЫZ[WЬЭ]IЛ	ШШ[™Y]IКK	Ъ[ќYЬљ]IО€[ќYЬљ]K	Ш\ќYXЭЩ\‰О€ЭЉ\™XЭЬћJ_B€^Щ\
[YQ\њ›Ь‹ФС\њ›Ь‹њЫЫ‹’”УУ‘XЫЩQ\њ›ЬЉH\И^О‚€™]\›€ЙЬЭXШЩ\ЬЙО€[ЩK	ЬЭ]\ЙО€	Ъ[ќ[Y	Л	Щ\њ›Ь‰О€ЭЉ^КK	Ъ[ќYЬљ]IО€[Щ_B‚‚™Y€ЫXZЩWШШ\Xљ[]WЭЫЫ
Ш\Xљ[]N€ЭЉN‚€Y\€HРTP’SUWХQT–ШШ\Xљ[]WB‚€Y€[ќ›ЪЩJ€\™Э[Y[ќЧЪњЫЫЋ€Э€HћЯH‹€[ЩN€Э€HњЬИ‹€ШЫЬWЬ›ЫЭО€Э€H€‹€^XЭЭ\™Щ]О€Э€H€‹€›Ш—ЪY€Э€H€‹€
HO€XЭЬЭ‹[ћWN‚€™]\›€^XЭ]WШШ\Xљ[]J€Ш\Xљ[]K€\™Э[Y[ќЧЪњЫЫЏX\™Э[Y[ќЧЪњЫЫ‹€[ЩO[[ЩK€ШЫЬWЬ›ЫЭП\ШЫЬWЬ›ЫЭЛ€^XЭЭ\™Щ]ПY^XЭЭ\™Щ]Л€›Ш—ЪYZ›Ш—ЪY€
B‚€[ќ›ЪЩK—ЧЫ[YWЧИH€љ^ЭљZЩWЬќ[—ЮШШ\Xљ[]_H‚€[ќ›ЪЩK—ЧЩШЧЧИH
€€”ќ[€^ЭљZЩHШ\Xљ[]HШШ\Xљ[]_H›ЭYЪHЫXЮHШ]]Ш^H‚€€ЉY\€ЭY\џJK€\™Э[Y[ќИ]\Э™HH”УУ€Шљ™XЭИШЫЬH\ИX[™]ЬћK€‚€
B€™]\›€[ќ›ЪЩB‚‚™›Ь€ШШ\Xљ[]H[€VФСQРРTP’SUQTО‚€XЬќЫЫ

JЫXZЩWШШ\Xљ[]WЭЫЫ
ШШ\Xљ[]JJB‚‚љY€ЧЫ[YWЧИOH—ЧЫXZ[—ЧИЋ‚€\њЩ\€H\™Ь\њЩKђ\™Э[Y[ќ\њЩ\ЉYЪ[Q[ЩJB€\њЩ\‹YШ\™Э[Y[ќ
	ЛK]ЫЬљЩ\‰ЛY][IЙКB€\™ЬЛЭ[љЫ›ЭЫ€H\њЩ\‹њ\њЩWЪЫ›ЭЫ—Ш\™ЬК
B€“Р—Ф“УХ›ZЩ\Љ\™[ќПUќYK^\ЭЫЪПUќYJB€Y€\™ЬЛќЫЬљЩ\Ћ‚€Z\ЩHЮ\Э[Q^]
Ьќ[—Ъ›ШЉ\™ЬЛќЫЬљЩ\ЉJB€XЬњќ[Љ
B