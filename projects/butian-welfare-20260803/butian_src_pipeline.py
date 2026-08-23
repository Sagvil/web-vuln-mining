#!/usr/bin/env python3
"""Butian public catalog, authenticated asset extraction, and low-impact URL prefilter.

The public Reward/pub endpoint intentionally exposes project metadata only. Official
assets are collected only from authenticated submit pages and are kept separate from
publicly inferred company websites.
"""
from __future__ import annotations

import argparse
import csv
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import ipaddress
import json
import os
import re
import shutil
import socket
import sqlite3
import stat
import subprocess
import sys
import threading
import time
from datetime import timedelta
from collections import Counter
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit
from xml.etree import ElementTree as ET

import requests

# ============================ Configuration zone ============================
# All defaults can also be overridden by the corresponding command-line option.
PROJECT_DIR = Path(__file__).resolve().parent
DEFAULT_RUN_DIR = PROJECT_DIR / "runs" / "butian-src"
DEFAULT_AUTH_HOME = Path.home() / ".local" / "share" / "butian-src-pipeline"
DEFAULT_AUTH_STATE = DEFAULT_AUTH_HOME / "storage-state.json"
# Browser executable; override with BUTIAN_BROWSER_PATH when Chromium is elsewhere.
DEFAULT_BROWSER_PATH = os.environ.get("BUTIAN_BROWSER_PATH", "/snap/bin/chromium")
# Snap Chromium may only persist profiles in its own writable data directory.
# Override with BUTIAN_BROWSER_PROFILE or --profile-dir for a custom dedicated profile.
DEFAULT_SNAP_BROWSER_PROFILE = (
    Path.home() / "snap" / "chromium" / "common" / "butian-src-pipeline-profile"
)
DEFAULT_STANDARD_BROWSER_PROFILE = DEFAULT_AUTH_HOME / "chromium-profile"
DEFAULT_BROWSER_PROFILE = Path(
    os.environ.get(
        "BUTIAN_BROWSER_PROFILE",
        str(
            DEFAULT_SNAP_BROWSER_PROFILE
            if DEFAULT_BROWSER_PATH.startswith("/snap/")
            else DEFAULT_STANDARD_BROWSER_PROFILE
        ),
    )
)
DEFAULT_VNC_DISPLAY = os.environ.get("BUTIAN_VNC_DISPLAY", ":1")
# X11 cookie file used by the headed VNC browser; override with BUTIAN_XAUTHORITY.
DEFAULT_XAUTHORITY = os.environ.get("BUTIAN_XAUTHORITY", str(Path.home() / ".Xauthority"))

BUTIAN_PUBLIC_API = "https://www.butian.net/Reward/pub"
BUTIAN_PLAN_URL = "https://www.butian.net/Reward/plan/1"
BUTIAN_SUBMIT_URL = "https://www.butian.net/Loo/submit?cid={project_id}"

REQUEST_TIMEOUT_SECONDS = 20
MAX_RETRIES = 3
RETRY_BACKOFF_SECONDS = 2.0
MIN_REQUEST_INTERVAL_SECONDS = 1.0
CATALOG_PAGE_HARD_LIMIT = 1000
MAX_REDIRECTS = 5
MAX_HTML_BYTES = 262_144
MAX_CAPTURED_JSON_BYTES = 262_144
MAX_SHALLOW_LINKS = 4
# Concurrent homepage/shallow-link probes.  DNS discovery and SQLite writes remain
# serialized so one run stays recoverable and rate-limited.
PREFILTER_WORKERS = 3
# Per-page request attempts for rough initial screening; override per run with
# --prefilter-http-attempts when speed or retry tolerance needs adjustment.
PREFILTER_HTTP_MAX_ATTEMPTS = 1
# Stage gates avoid expensive follow-up work for obvious static, unavailable, WAF,
# parking, external-redirect, or non-interactive root pages.
PREFILTER_SHALLOW_GATE_ENABLED = True
PREFILTER_SUBDOMAIN_GATE_ENABLED = True
BROWSER_SETTLE_MILLISECONDS = 1_200
# Batch defaults: begin with three public catalog pages and collect this many
# globally new `keep` URLs before advancing the persistent page cursor.
BATCH_TARGET_KEEP = 5
BATCH_PAGE_SPAN = 3
BATCH_CURSOR_NAME = "butian_public_src_prefilter"
BATCH_FILE_PREFIX = "batch"
# Wiki archive root; override with BUTIAN_WIKI_BATCH_DIR or --wiki-dir.
DEFAULT_WIKI_ROOT = Path(os.environ.get("BUTIAN_WIKI_ROOT", str(Path.home() / "wiki")))
DEFAULT_WIKI_BATCH_DIR = Path(
    os.environ.get(
        "BUTIAN_WIKI_BATCH_DIR",
        str(DEFAULT_WIKI_ROOT / "projects" / "butian-welfare-src-prefilter"),
    )
)
DEFAULT_WIKI_BATCH_HUB = DEFAULT_WIKI_BATCH_DIR.parent / "butian-welfare-src-prefilter.md"
DEFAULT_WIKI_INDEX = DEFAULT_WIKI_ROOT / "index.md"
# Per-target evidence folders created after an official URL passes initial screening.
DEFAULT_TARGET_ARCHIVE_DIR = DEFAULT_RUN_DIR / "targets"

# Subdomain discovery is DNS-only and is deduplicated by registrable root domain.
SUBDOMAIN_DISCOVERY_ENABLED = True
SUBDOMAIN_CACHE_DAYS = 30
SUBDOMAIN_NMAP_PATH = os.environ.get("BUTIAN_NMAP_PATH", "nmap")
SUBDOMAIN_WORDLIST = PROJECT_DIR / "wordlists" / "subdomains-10000.txt"
SUBDOMAIN_NMAP_THREADS = 5
SUBDOMAIN_NMAP_TIMEOUT_SECONDS = 900
SUBDOMAIN_DNS_QUERY_TIMEOUT_SECONDS = 5
SUBDOMAIN_PASSIVE_ENDPOINT = "https://crt.sh/"
SUBDOMAIN_PASSIVE_ENABLED = True
# Certificate-transparency is supplementary to DNS brute discovery; fail fast when
# crt.sh is degraded so one lookup does not stall the initial screen.
SUBDOMAIN_PASSIVE_TIMEOUT_SECONDS = 8
SUBDOMAIN_PASSIVE_MAX_ATTEMPTS = 1

# Middle screening uses the existing private DeepSeek key without copying it to runs.
DEEPSEEK_ENV_FILE = Path.home() / ".hermes" / ".env"
DEEPSEEK_API_KEY_ENV = "DEEPSEEK_API_KEY"
DEEPSEEK_CHAT_COMPLETIONS_URL = "https://api.deepseek.com/v1/chat/completions"
DEEPSEEK_MIDDLE_MODEL = "deepseek-v4-flash"
MIDDLE_AI_TIMEOUT_SECONDS = 45
MIDDLE_AI_MAX_RESPONSE_CHARS = 600
MIDDLE_AI_ENABLED_BY_DEFAULT = False

# Scores used by the rule-only URL prefilter. Login is valuable evidence, but it
# is deliberately not a mandatory condition by itself.
KEEP_FUNCTIONAL_SCORE = 5
DROP_STATIC_SCORE = 3
DROP_FUNCTIONAL_SCORE_MAX = 2
REVIEW_COMPLEXITY_SCORE = 5
AI_BOUNDARY_LOW = 3
AI_BOUNDARY_HIGH = 6

AI_ENDPOINT_ENV = "BUTIAN_AI_ENDPOINT"  # OpenAI-compatible /chat/completions URL.
AI_API_KEY_ENV = "BUTIAN_AI_API_KEY"  # Never write this value to files or logs.
AI_MODEL_ENV = "BUTIAN_AI_MODEL"
DEFAULT_AI_MODEL = "gpt-4o-mini"

USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36 ButianSrcPipeline/1.0"
)
PARKING_MARKERS = (
    "domain for sale",
    "premium domain",
    "buy this domain",
    "this domain is for sale",
    "域名出售",
    "域名转让",
    "正在出售",
    "停放页面",
    "sedo parking",
    "afternic",
)
WAF_MARKERS = ("access denied", "captcha", "安全验证", "人机验证", "waf", "challenge")
AUTH_MARKERS = ("login", "log in", "sign in", "登录", "注册", "会员登录", "账号登录")
BUSINESS_MARKERS = (
    "account",
    "profile",
    "order",
    "cart",
    "checkout",
    "dashboard",
    "admin",
    "search",
    "账户",
    "订单",
    "购物车",
    "后台",
    "管理",
    "查询",
    "预约",
    "提交",
    "个人中心",
)
SCOPE_MARKERS = (
    "资产范围",
    "测试范围",
    "漏洞范围",
    "提交范围",
    "scope",
    "asset",
    "domain",
    "target",
    "url",
    "域名",
    "目标",
)
# Visible labels accepted as official scope evidence.  Keep this stricter than
# SCOPE_MARKERS so page scripts, navigation, and unrelated fields cannot create assets.
TEXT_SCOPE_MARKERS = (
    "资产范围",
    "测试范围",
    "漏洞范围",
    "提交范围",
    "目标范围",
    "域名或ip",
)
EXCLUDE_MARKERS = ("排除", "exclude", "不包含", "禁止测试", "out of scope", "不可测试")
# Tags whose contents are not visible page text.  Scripts still count as a structural
# signal, but their source code must not create business, scope, or text-size evidence.
NON_VISIBLE_TEXT_TAGS = frozenset({"script", "style", "template", "noscript"})
# HTML scope extraction ignores executable/template content and only carries form-control
# values forward when an adjacent visible label or field hint identifies a scope field.
SCOPE_IGNORED_TAGS = NON_VISIBLE_TEXT_TAGS
SCOPE_BLOCK_TAGS = frozenset(
    {
        "article", "aside", "body", "br", "dd", "div", "dl", "dt", "fieldset",
        "figcaption", "figure", "footer", "form", "h1", "h2", "h3", "h4", "h5",
        "h6", "header", "li", "main", "ol", "p", "section", "table", "tbody",
        "td", "th", "thead", "tr", "ul",
    }
)
SCOPE_CONTROL_VALUE_ATTRS = ("value", "data-value", "data-url", "data-domain", "data-target")
SCOPE_FIELD_HINTS = ("scope", "range", "asset", "domain", "host", "target", "url", "域名", "范围", "资产", "目标")
SCOPE_VALUE_CONTEXT_CHARS = 480  # Maximum preceding visible label context for a form value.
SCOPE_TEXT_CONTEXT_CHARS = 700  # Maximum visible text inspected after one scope label.
STATIC_HOST_MARKERS = ("github pages", "netlify", "vercel", "cloudflare pages", "render static")
ASSET_EXTENSIONS = {
    ".7z",
    ".apk",
    ".avi",
    ".bmp",
    ".css",
    ".csv",
    ".doc",
    ".docx",
    ".gif",
    ".ico",
    ".jpeg",
    ".jpg",
    ".js",
    ".map",
    ".mp3",
    ".mp4",
    ".pdf",
    ".png",
    ".rar",
    ".svg",
    ".tar",
    ".tgz",
    ".txt",
    ".webp",
    ".woff",
    ".woff2",
    ".xls",
    ".xlsx",
    ".xml",
    ".zip",
}
SECOND_LEVEL_SUFFIXES = {
    "com.cn",
    "net.cn",
    "org.cn",
    "gov.cn",
    "edu.cn",
    "ac.cn",
    "co.uk",
    "org.uk",
    "com.au",
}
# ============================================================================


def utc_now() -> str:
    """Return an ISO-8601 timestamp in UTC."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def log(message: str) -> None:
    print(message, flush=True)


def json_compact(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def ensure_private_file(path: Path) -> None:
    """Set owner-only permissions where the operating system supports them."""
    try:
        path.chmod(stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass


def write_text_atomic(path: Path, content: str, private: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(content, encoding="utf-8")
    temporary.replace(path)
    if private:
        ensure_private_file(path)


def write_json_atomic(path: Path, value: Any, private: bool = False) -> None:
    write_text_atomic(path, json.dumps(value, ensure_ascii=False, indent=2) + "\n", private=private)


def write_jsonl_atomic(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    write_text_atomic(
        path,
        "".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in rows),
    )


def write_csv_atomic(
    path: Path, fieldnames: list[str], rows: Iterable[dict[str, Any]]
) -> None:
    """Atomically export a UTF-8 CSV table for human and script comparison."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    with temporary.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({name: row.get(name, "") for name in fieldnames})
    temporary.replace(path)


def path_from_argument(value: str | None, default: Path) -> Path:
    return Path(value).expanduser().resolve() if value else default.resolve()


def run_paths(args: argparse.Namespace) -> tuple[Path, Path]:
    run_dir = path_from_argument(getattr(args, "run_dir", None), DEFAULT_RUN_DIR)
    db_path = path_from_argument(getattr(args, "db", None), run_dir / "state.sqlite")
    return run_dir, db_path


def open_database(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    connection.executescript(
        """
        PRAGMA journal_mode=WAL;
        PRAGMA foreign_keys=ON;
        CREATE TABLE IF NOT EXISTS catalog_pages (
            page_number INTEGER PRIMARY KEY,
            page_count INTEGER NOT NULL,
            fingerprint TEXT NOT NULL,
            item_count INTEGER NOT NULL,
            status TEXT NOT NULL,
            fetched_at TEXT NOT NULL,
            error TEXT
        );
        CREATE TABLE IF NOT EXISTS catalog_projects (
            project_id TEXT PRIMARY KEY,
            company_name TEXT NOT NULL,
            avatar TEXT,
            source_json TEXT NOT NULL,
            first_seen_at TEXT NOT NULL,
            last_seen_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS extraction_results (
            project_id TEXT PRIMARY KEY,
            company_name TEXT NOT NULL,
            status TEXT NOT NULL,
            page_url TEXT NOT NULL,
            asset_count INTEGER NOT NULL DEFAULT 0,
            message TEXT,
            extracted_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS official_assets (
            project_id TEXT NOT NULL,
            normalized_url TEXT NOT NULL,
            raw_asset TEXT NOT NULL,
            asset_kind TEXT NOT NULL,
            scope TEXT NOT NULL,
            source TEXT NOT NULL,
            confidence TEXT NOT NULL,
            evidence TEXT NOT NULL,
            discovered_at TEXT NOT NULL,
            PRIMARY KEY (project_id, normalized_url, scope)
        );
        CREATE TABLE IF NOT EXISTS prefilter_results (
            normalized_url TEXT PRIMARY KEY,
            decision TEXT NOT NULL,
            functional_score INTEGER NOT NULL,
            static_score INTEGER NOT NULL,
            complexity_score INTEGER NOT NULL,
            reasons_json TEXT NOT NULL,
            result_json TEXT NOT NULL,
            analyzed_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS catalog_project_pages (
            page_number INTEGER NOT NULL,
            item_index INTEGER NOT NULL,
            project_id TEXT NOT NULL,
            page_fingerprint TEXT NOT NULL,
            observed_at TEXT NOT NULL,
            PRIMARY KEY (page_number, item_index)
        );
        CREATE INDEX IF NOT EXISTS catalog_project_pages_project_idx
            ON catalog_project_pages(project_id, page_number, item_index);
        CREATE TABLE IF NOT EXISTS batch_runs (
            batch_id TEXT PRIMARY KEY,
            page_start INTEGER NOT NULL,
            page_end INTEGER,
            target_keep INTEGER NOT NULL,
            keep_count INTEGER NOT NULL DEFAULT 0,
            candidate_count INTEGER NOT NULL DEFAULT 0,
            checked_count INTEGER NOT NULL DEFAULT 0,
            reused_count INTEGER NOT NULL DEFAULT 0,
            status TEXT NOT NULL,
            started_at TEXT NOT NULL,
            finished_at TEXT,
            configuration_json TEXT NOT NULL,
            wiki_directory TEXT NOT NULL,
            error TEXT
        );
        CREATE TABLE IF NOT EXISTS batch_project_records (
            batch_id TEXT NOT NULL,
            page_number INTEGER NOT NULL,
            item_index INTEGER NOT NULL,
            project_id TEXT NOT NULL,
            company_name TEXT NOT NULL,
            extraction_status TEXT NOT NULL,
            asset_count INTEGER NOT NULL DEFAULT 0,
            message TEXT,
            recorded_at TEXT NOT NULL,
            PRIMARY KEY (batch_id, page_number, item_index)
        );
        CREATE TABLE IF NOT EXISTS batch_url_records (
            batch_id TEXT NOT NULL,
            normalized_url TEXT NOT NULL,
            project_id TEXT NOT NULL,
            company_name TEXT NOT NULL,
            page_number INTEGER NOT NULL,
            item_index INTEGER NOT NULL,
            scope TEXT NOT NULL,
            source TEXT NOT NULL,
            confidence TEXT NOT NULL,
            decision TEXT NOT NULL,
            action TEXT NOT NULL,
            reasons_json TEXT NOT NULL,
            recorded_at TEXT NOT NULL,
            PRIMARY KEY (batch_id, normalized_url, project_id, page_number, item_index, scope)
        );
        CREATE TABLE IF NOT EXISTS url_registry (
            normalized_url TEXT PRIMARY KEY,
            first_batch_id TEXT NOT NULL,
            first_page_number INTEGER NOT NULL,
            first_project_id TEXT NOT NULL,
            first_company_name TEXT NOT NULL,
            first_seen_at TEXT NOT NULL,
            last_batch_id TEXT NOT NULL,
            last_page_number INTEGER NOT NULL,
            last_project_id TEXT NOT NULL,
            last_company_name TEXT NOT NULL,
            last_seen_at TEXT NOT NULL,
            decision TEXT NOT NULL,
            functional_score INTEGER NOT NULL,
            static_score INTEGER NOT NULL,
            complexity_score INTEGER NOT NULL,
            reasons_json TEXT NOT NULL,
            first_checked_at TEXT,
            last_checked_at TEXT,
            check_count INTEGER NOT NULL DEFAULT 0,
            reuse_count INTEGER NOT NULL DEFAULT 0,
            force_recheck_count INTEGER NOT NULL DEFAULT 0,
            source TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS pipeline_cursor (
            cursor_name TEXT PRIMARY KEY,
            next_page INTEGER,
            status TEXT NOT NULL,
            last_batch_id TEXT,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS subdomain_discovery_runs (
            root_domain TEXT PRIMARY KEY,
            status TEXT NOT NULL,
            discovered_at TEXT NOT NULL,
            expires_at TEXT,
            passive_count INTEGER NOT NULL DEFAULT 0,
            nmap_count INTEGER NOT NULL DEFAULT 0,
            nmap_xml_path TEXT,
            passive_json_path TEXT,
            error TEXT,
            configuration_json TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS subdomain_assets (
            root_domain TEXT NOT NULL,
            subdomain TEXT NOT NULL,
            sources_json TEXT NOT NULL,
            ips_json TEXT NOT NULL,
            cname TEXT NOT NULL DEFAULT '',
            asset_type TEXT NOT NULL,
            first_seen_at TEXT NOT NULL,
            last_seen_at TEXT NOT NULL,
            PRIMARY KEY (root_domain, subdomain)
        );
        CREATE INDEX IF NOT EXISTS subdomain_assets_root_idx
            ON subdomain_assets(root_domain, asset_type);
        CREATE TABLE IF NOT EXISTS middle_reviews (
            normalized_url TEXT PRIMARY KEY,
            initial_decision TEXT NOT NULL,
            initial_tier TEXT NOT NULL,
            subdomain_count INTEGER NOT NULL DEFAULT 0,
            subdomain_bonus INTEGER NOT NULL DEFAULT 0,
            ai_status TEXT NOT NULL,
            ai_decision TEXT,
            final_tier TEXT NOT NULL,
            confidence TEXT NOT NULL,
            scope_risk TEXT NOT NULL,
            reason TEXT NOT NULL,
            model TEXT,
            request_json TEXT NOT NULL,
            response_json TEXT NOT NULL,
            reviewed_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS target_artifacts (
            normalized_url TEXT NOT NULL,
            artifact_stage TEXT NOT NULL,
            artifact_path TEXT NOT NULL,
            sha256 TEXT NOT NULL,
            batch_id TEXT,
            generated_at TEXT NOT NULL,
            PRIMARY KEY (normalized_url, artifact_stage, artifact_path)
        );
        """
    )
    return connection


def make_http_session(max_redirects: int = MAX_REDIRECTS) -> requests.Session:
    session = requests.Session()
    session.headers.update(
        {
            "User-Agent": USER_AGENT,
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.6",
        }
    )
    session.max_redirects = max_redirects
    return session


class RateLimiter:
    """Thread-safe process-local delay between outbound GET requests."""

    def __init__(self, minimum_interval: float) -> None:
        self.minimum_interval = max(0.0, minimum_interval)
        self.last_request = 0.0
        self._lock = threading.Lock()

    def wait(self) -> None:
        # A single limiter is intentionally shared by workers, preserving the
        # configured global spacing while requests that are already in flight overlap.
        with self._lock:
            remaining = self.minimum_interval - (time.monotonic() - self.last_request)
            if remaining > 0:
                time.sleep(remaining)
            self.last_request = time.monotonic()


def request_with_retries(
    session: requests.Session,
    url: str,
    *,
    params: dict[str, Any] | None = None,
    timeout: float = REQUEST_TIMEOUT_SECONDS,
    limiter: RateLimiter | None = None,
    stream: bool = False,
    max_attempts: int = MAX_RETRIES,
) -> requests.Response:
    last_error: Exception | None = None
    attempt_count = max(1, int(max_attempts))
    for attempt in range(attempt_count):
        if limiter:
            limiter.wait()
        try:
            response = session.get(
                url,
                params=params,
                timeout=timeout,
                allow_redirects=True,
                stream=stream,
            )
            if response.status_code >= 500 and attempt < attempt_count - 1:
                response.close()
                time.sleep(RETRY_BACKOFF_SECONDS * (attempt + 1))
                continue
            return response
        except requests.RequestException as error:
            last_error = error
            if attempt < attempt_count - 1:
                time.sleep(RETRY_BACKOFF_SECONDS * (attempt + 1))
    raise RuntimeError(f"GET failed after {attempt_count} attempts: {last_error}") from last_error


def catalog_page_fingerprint(items: list[dict[str, Any]]) -> str:
    identifiers = [str(item.get("company_id", "")) for item in items]
    return hashlib.sha256("\n".join(identifiers).encode("utf-8")).hexdigest()


def parse_catalog_response(payload: Any) -> tuple[int, int, list[dict[str, Any]]]:
    if not isinstance(payload, dict):
        raise ValueError("catalog response is not a JSON object")
    data = payload.get("data")
    if not isinstance(data, dict):
        raise ValueError("catalog response has no data object")
    current = data.get("current")
    page_count = data.get("count")
    items = data.get("list")
    if not isinstance(current, int) or not isinstance(page_count, int) or not isinstance(items, list):
        raise ValueError("catalog response has an invalid current/count/list shape")
    valid_items = [
        item
        for item in items
        if isinstance(item, dict) and item.get("company_id") and item.get("company_name")
    ]
    return current, page_count, valid_items


def catalog_page_mapping_complete(
    connection: sqlite3.Connection, page_number: int, item_count: int
) -> bool:
    """A cached page can be resumed only after its ordered project mapping exists."""
    row = connection.execute(
        "SELECT COUNT(*) AS count FROM catalog_project_pages WHERE page_number=?",
        (page_number,),
    ).fetchone()
    return bool(row and int(row["count"]) == item_count)


def save_catalog_page_mappings(
    connection: sqlite3.Connection,
    page_number: int,
    fingerprint: str,
    items: list[dict[str, Any]],
    observed_at: str,
) -> None:
    """Replace one page's ordered item map, retaining duplicate project IDs if present."""
    connection.execute(
        "DELETE FROM catalog_project_pages WHERE page_number=?", (page_number,)
    )
    connection.executemany(
        """
        INSERT INTO catalog_project_pages(page_number, item_index, project_id, page_fingerprint, observed_at)
        VALUES (?, ?, ?, ?, ?)
        """,
        [
            (page_number, item_index, str(item["company_id"]), fingerprint, observed_at)
            for item_index, item in enumerate(items, 1)
        ],
    )


def catalog_declared_page_count(connection: sqlite3.Connection) -> int | None:
    row = connection.execute(
        "SELECT page_count FROM catalog_pages WHERE status='ok' ORDER BY fetched_at DESC LIMIT 1"
    ).fetchone()
    return int(row["page_count"]) if row else None


def catalog_projects_for_pages(
    connection: sqlite3.Connection, page_start: int, page_end: int
) -> list[sqlite3.Row]:
    """Return public projects in deterministic catalog-page and within-page order."""
    return list(
        connection.execute(
            """
            SELECT mapping.page_number, mapping.item_index, mapping.project_id,
                   projects.company_name
            FROM catalog_project_pages AS mapping
            JOIN catalog_projects AS projects ON projects.project_id=mapping.project_id
            WHERE mapping.page_number BETWEEN ? AND ?
            ORDER BY mapping.page_number, mapping.item_index
            """,
            (page_start, page_end),
        )
    )


def export_catalog(connection: sqlite3.Connection, path: Path) -> int:
    rows = []
    for row in connection.execute(
        "SELECT project_id, company_name, avatar, source_json "
        "FROM catalog_projects ORDER BY CAST(project_id AS INTEGER) DESC"
    ):
        source = json.loads(row["source_json"])
        rows.append(
            {
                "project_id": row["project_id"],
                "company_name": row["company_name"],
                "avatar": row["avatar"],
                "source": "butian_public_catalog",
                "raw": source,
            }
        )
    write_jsonl_atomic(path, rows)
    return len(rows)


def command_catalog(args: argparse.Namespace) -> int:
    run_dir, db_path = run_paths(args)
    if args.dry_run:
        log(f"DRY RUN catalog: GET {BUTIAN_PUBLIC_API}?name=&p=N -> {run_dir}")
        return 0
    connection = open_database(db_path)
    session = make_http_session()
    session.headers.update({"Referer": BUTIAN_PLAN_URL})
    limiter = RateLimiter(args.min_interval)
    requested_start = max(1, args.start_page)
    configured_limit = max(1, args.page_limit)
    known_row = connection.execute(
        "SELECT page_count FROM catalog_pages ORDER BY fetched_at DESC LIMIT 1"
    ).fetchone()
    page_count: int | None = int(known_row["page_count"]) if known_row else None
    upper_bound = min(page_count or CATALOG_PAGE_HARD_LIMIT, configured_limit)
    seen_fingerprints = {
        row["fingerprint"]: row["page_number"]
        for row in connection.execute(
            "SELECT page_number, fingerprint FROM catalog_pages WHERE status='ok'"
        )
    }

    page = requested_start
    while page <= upper_bound:
        existing = connection.execute(
            "SELECT status, page_count, item_count FROM catalog_pages WHERE page_number=?", (page,)
        ).fetchone()
        mapping_complete = bool(
            existing
            and catalog_page_mapping_complete(
                connection, page, int(existing["item_count"])
            )
        )
        if args.resume and existing and existing["status"] == "ok" and mapping_complete:
            page_count = page_count or int(existing["page_count"])
            upper_bound = min(page_count, configured_limit)
            log(f"catalog page {page}: resume skip")
            page += 1
            continue
        if args.resume and existing and existing["status"] == "ok":
            log(f"catalog page {page}: cached page lacks ordered mapping; refresh")
        try:
            response = request_with_retries(
                session,
                BUTIAN_PUBLIC_API,
                params={"name": "", "p": page},
                timeout=args.timeout,
                limiter=limiter,
            )
            content_type = response.headers.get("content-type", "")
            if response.status_code != 200 or "json" not in content_type.lower():
                raise ValueError(
                    f"unexpected catalog response HTTP {response.status_code} ({content_type})"
                )
            current, discovered_page_count, items = parse_catalog_response(response.json())
            response.close()
            if current != page:
                raise ValueError(f"expected page {page}, server returned page {current}")
            page_count = discovered_page_count
            upper_bound = min(page_count, configured_limit)
            fingerprint = catalog_page_fingerprint(items)
            previous_page = seen_fingerprints.get(fingerprint)
            if previous_page is not None and previous_page != page:
                connection.execute(
                    "INSERT OR REPLACE INTO catalog_pages VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        page,
                        page_count,
                        fingerprint,
                        len(items),
                        "repeated",
                        utc_now(),
                        f"same content as page {previous_page}",
                    ),
                )
                connection.commit()
                log(f"catalog page {page}: repeated page fingerprint from {previous_page}; stop")
                break
            seen_fingerprints[fingerprint] = page
            timestamp = utc_now()
            for item in items:
                project_id = str(item["company_id"])
                connection.execute(
                    """
                    INSERT INTO catalog_projects(project_id, company_name, avatar, source_json, first_seen_at, last_seen_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT(project_id) DO UPDATE SET
                      company_name=excluded.company_name,
                      avatar=excluded.avatar,
                      source_json=excluded.source_json,
                      last_seen_at=excluded.last_seen_at
                    """,
                    (
                        project_id,
                        str(item["company_name"]),
                        item.get("avatar"),
                        json_compact(item),
                        timestamp,
                        timestamp,
                    ),
                )
            save_catalog_page_mappings(
                connection, page, fingerprint, items, timestamp
            )
            connection.execute(
                "INSERT OR REPLACE INTO catalog_pages VALUES (?, ?, ?, ?, ?, ?, NULL)",
                (page, page_count, fingerprint, len(items), "ok", timestamp),
            )
            connection.commit()
            log(f"catalog page {page}/{page_count}: {len(items)} projects")
            if not items:
                break
            page += 1
        except Exception as error:
            connection.execute(
                "INSERT OR REPLACE INTO catalog_pages VALUES (?, ?, ?, ?, ?, ?, ?)",
                (page, page_count or 0, "", 0, "failed", utc_now(), str(error)[:500]),
            )
            connection.commit()
            log(f"catalog page {page}: failed: {error}")
            connection.close()
            return 2

    output_path = run_dir / "catalog.jsonl"
    count = export_catalog(connection, output_path)
    write_json_atomic(
        run_dir / "catalog-manifest.json",
        {
            "generated_at": utc_now(),
            "source": BUTIAN_PUBLIC_API,
            "project_count": count,
            "declared_page_count": page_count,
            "note": "Public catalog records do not contain official asset URLs.",
        },
    )
    connection.close()
    log(f"catalog export: {count} projects -> {output_path}")
    return 0


def normalise_host(host: str) -> str | None:
    host = host.strip().strip(".").lower()
    if not host:
        return None
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    if any(character.isspace() for character in host) or "/" in host:
        return None
    return host


def normalize_target_url(value: str) -> str | None:
    raw = str(value or "").strip().strip("'\"，。；;()（）[]{}")
    if not raw:
        return None
    if raw.startswith("//"):
        raw = "https:" + raw
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw):
        raw = "https://" + raw
    parts = urlsplit(raw)
    if (
        parts.scheme.lower() not in {"http", "https"}
        or not parts.hostname
        or parts.username
        or parts.password
    ):
        return None
    host = normalise_host(parts.hostname)
    if not host:
        return None
    try:
        port_number = parts.port
    except ValueError:
        return None
    port = f":{port_number}" if port_number else ""
    netloc = host + port
    filtered_query = [
        (key, item)
        for key, item in parse_qsl(parts.query, keep_blank_values=True)
        if not key.lower().startswith("utm_")
    ]
    path = parts.path or "/"
    return urlunsplit(
        (parts.scheme.lower(), netloc, path, urlencode(filtered_query, doseq=True), "")
    )


def is_public_target(url: str) -> bool:
    host = urlsplit(url).hostname or ""
    if host in {"localhost", "localhost.localdomain"} or host.endswith(".local"):
        return False
    try:
        return ipaddress.ip_address(host).is_global
    except ValueError:
        return True


def registered_domain(host: str) -> str:
    parts = host.lower().split(".")
    if len(parts) < 2:
        return host.lower()
    tail = ".".join(parts[-2:])
    if tail in SECOND_LEVEL_SUFFIXES and len(parts) >= 3:
        return ".".join(parts[-3:])
    return tail


def is_same_site(left: str, right: str) -> bool:
    left_host = urlsplit(left).hostname or ""
    right_host = urlsplit(right).hostname or ""
    return bool(
        left_host
        and right_host
        and registered_domain(left_host) == registered_domain(right_host)
    )


def is_asset_link(url: str) -> bool:
    path = urlsplit(url).path.lower()
    return any(path.endswith(extension) for extension in ASSET_EXTENSIONS)


def strip_text(value: str, limit: int = 320) -> str:
    return re.sub(r"\s+", " ", value).strip()[:limit]


class ScopeTextParser(HTMLParser):
    """Collect visible scope sections while discarding executable and link attributes."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._fallback_parts: list[str] = []
        self._frames: list[dict[str, Any]] = []
        self._stack: list[dict[str, Any]] = []
        self._ignored_depth = 0
        self._sequence = 0

    def _append(self, value: str) -> None:
        if not value:
            return
        self._fallback_parts.append(value)
        for frame in self._stack:
            frame["parts"].append(value)

    def _recent_visible_text(self) -> str:
        return "".join(self._fallback_parts)[-SCOPE_VALUE_CONTEXT_CHARS:]

    @staticmethod
    def _has_scope_label(value: str) -> bool:
        lowered = value.lower()
        return any(marker.lower() in lowered for marker in TEXT_SCOPE_MARKERS)

    @staticmethod
    def _has_exclude_label(value: str) -> bool:
        lowered = value.lower()
        return any(marker in lowered for marker in EXCLUDE_MARKERS)

    @staticmethod
    def _has_field_hint(attributes: dict[str, str]) -> bool:
        hint = " ".join(
            attributes.get(name, "")
            for name in ("id", "name", "class", "placeholder", "aria-label", "title")
        ).lower()
        return any(marker.lower() in hint for marker in SCOPE_FIELD_HINTS)

    def handle_starttag(
        self, tag: str, attributes: list[tuple[str, str | None]]
    ) -> None:
        tag = tag.lower()
        if tag in SCOPE_IGNORED_TAGS:
            self._ignored_depth += 1
            return
        if self._ignored_depth:
            return
        if tag in SCOPE_BLOCK_TAGS:
            self._sequence += 1
            self._stack.append(
                {"tag": tag, "start": self._sequence, "parts": []}
            )
        if tag not in {"input", "textarea"}:
            return
        attrs = {key.lower(): (value or "") for key, value in attributes}
        has_scope_evidence = self._has_scope_label(
            self._recent_visible_text()
        ) or self._has_field_hint(attrs)
        if not has_scope_evidence:
            return
        for name in SCOPE_CONTROL_VALUE_ATTRS:
            value = attrs.get(name, "").strip()
            if value:
                self._append(f" {value} ")

    def handle_startendtag(
        self, tag: str, attributes: list[tuple[str, str | None]]
    ) -> None:
        self.handle_starttag(tag, attributes)
        self.handle_endtag(tag)

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag in SCOPE_IGNORED_TAGS:
            if self._ignored_depth:
                self._ignored_depth -= 1
            return
        if self._ignored_depth or tag not in SCOPE_BLOCK_TAGS:
            return
        for index in range(len(self._stack) - 1, -1, -1):
            if self._stack[index]["tag"] != tag:
                continue
            self._sequence += 1
            frame = self._stack.pop(index)
            frame["end"] = self._sequence
            self._frames.append(frame)
            break

    def handle_data(self, data: str) -> None:
        if not self._ignored_depth:
            self._append(data)

    def scope_contexts(self) -> list[str]:
        """Return the smallest scope-labelled visible containers with URL-like text."""
        labelled: list[dict[str, Any]] = []
        for frame in self._frames:
            content = "".join(frame["parts"])
            if not (
                self._has_scope_label(content) or self._has_exclude_label(content)
            ):
                continue
            if extract_urls_from_text(content):
                frame["content"] = content
                labelled.append(frame)
        if not labelled:
            fallback = "".join(self._fallback_parts)
            return [fallback] if (
                self._has_scope_label(fallback) or self._has_exclude_label(fallback)
            ) else []
        smallest = [
            frame
            for frame in labelled
            if not any(
                frame["start"] < child["start"]
                and child["end"] < frame["end"]
                for child in labelled
            )
        ]
        return [
            str(frame["content"])
            for frame in sorted(smallest, key=lambda item: int(item["start"]))
        ]


class SiteFeatureParser(HTMLParser):
    """Collect only lightweight structural signals and explicitly linked URLs."""

    def __init__(self, base_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.anchors: list[str] = []
        self.form_count = 0
        self.password_inputs = 0
        self.non_search_forms = 0
        self.script_count = 0
        self.api_hints = 0
        self.text_chunks: list[str] = []
        self.title_chunks: list[str] = []
        self._in_title = False
        self._form_is_search = False
        self._ignored_text_depth = 0

    def handle_starttag(self, tag: str, attributes: list[tuple[str, str | None]]) -> None:
        attrs = {key.lower(): (value or "") for key, value in attributes}
        tag = tag.lower()
        if tag in NON_VISIBLE_TEXT_TAGS:
            if tag == "script":
                self.script_count += 1
                source = attrs.get("src", "").lower()
                if any(marker in source for marker in ("api", "ajax", "graphql", "axios")):
                    self.api_hints += 1
            self._ignored_text_depth += 1
            return
        if tag == "a":
            href = attrs.get("href", "")
            if href:
                self.anchors.append(href)
        elif tag == "form":
            self.form_count += 1
            combined = " ".join(
                [
                    attrs.get("action", ""),
                    attrs.get("id", ""),
                    attrs.get("class", ""),
                    attrs.get("role", ""),
                ]
            ).lower()
            self._form_is_search = "search" in combined or "搜索" in combined
        elif tag == "input":
            input_type = attrs.get("type", "").lower()
            if input_type == "password":
                self.password_inputs += 1
            combined = " ".join(attrs.values()).lower()
            if any(marker in combined for marker in ("api", "ajax", "endpoint", "接口")):
                self.api_hints += 1
        elif tag == "title":
            self._in_title = True

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag in NON_VISIBLE_TEXT_TAGS:
            if self._ignored_text_depth:
                self._ignored_text_depth -= 1
            return
        if tag == "form" and not self._form_is_search:
            self.non_search_forms += 1
        if tag == "form":
            self._form_is_search = False
        if tag == "title":
            self._in_title = False

    def handle_startendtag(
        self, tag: str, attributes: list[tuple[str, str | None]]
    ) -> None:
        self.handle_starttag(tag, attributes)
        self.handle_endtag(tag)

    def handle_data(self, data: str) -> None:
        if self._ignored_text_depth:
            return
        compact = strip_text(data, 512)
        if compact:
            self.text_chunks.append(compact)
            if self._in_title:
                self.title_chunks.append(compact)
            lowered = compact.lower()
            if any(marker in lowered for marker in ("api", "ajax", "graphql", "接口")):
                self.api_hints += 1

    def metrics(self) -> dict[str, Any]:
        text = " ".join(self.text_chunks)
        lowered = text.lower()
        links: list[str] = []
        for href in self.anchors:
            absolute = normalize_target_url(urljoin(self.base_url, href))
            if absolute:
                links.append(absolute)
        internal_links = [link for link in links if is_same_site(self.base_url, link)]
        auth_hits = sum(marker in lowered for marker in AUTH_MARKERS) + self.password_inputs
        business_hits = sum(marker in lowered for marker in BUSINESS_MARKERS)
        return {
            "title": strip_text(" ".join(self.title_chunks), 160),
            "text_excerpt": strip_text(text, 800),
            "text_chars": len(text),
            "anchor_count": len(links),
            "internal_link_count": len(set(internal_links)),
            "form_count": self.form_count,
            "non_search_form_count": self.non_search_forms,
            "password_inputs": self.password_inputs,
            "script_count": self.script_count,
            "api_hints": self.api_hints,
            "auth_hits": auth_hits,
            "business_hits": business_hits,
            "links": list(dict.fromkeys(internal_links)),
        }


def analyse_html(base_url: str, html_text: str) -> dict[str, Any]:
    parser = SiteFeatureParser(base_url)
    try:
        parser.feed(html_text)
        parser.close()
    except Exception:
        pass
    metrics = parser.metrics()
    lowered = html_text.lower()
    metrics["parking"] = any(marker in lowered for marker in PARKING_MARKERS)
    metrics["waf"] = any(marker in lowered for marker in WAF_MARKERS)
    return metrics


def extract_shallow_links(base_url: str, html_text: str, maximum: int) -> list[str]:
    metrics = analyse_html(base_url, html_text)
    selected: list[str] = []
    for link in metrics["links"]:
        if link == base_url or is_asset_link(link):
            continue
        path = urlsplit(link).path.lower()
        if any(token in path for token in ("logout", "signout", "delete", "remove")):
            continue
        selected.append(link)
        if len(selected) >= maximum:
            break
    return selected


def consume_response_body(response: requests.Response, maximum_bytes: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    for chunk in response.iter_content(chunk_size=8192):
        if not chunk:
            continue
        remaining = maximum_bytes - total
        if remaining <= 0:
            break
        chunks.append(chunk[:remaining])
        total += len(chunks[-1])
        if total >= maximum_bytes:
            break
    return b"".join(chunks)


def fetch_html_probe(
    session: requests.Session,
    url: str,
    *,
    timeout: float,
    limiter: RateLimiter,
    max_attempts: int = MAX_RETRIES,
) -> dict[str, Any]:
    try:
        response = request_with_retries(
            session, url, timeout=timeout, limiter=limiter, stream=True,
            max_attempts=max_attempts,
        )
        body = consume_response_body(response, MAX_HTML_BYTES)
        encoding = response.encoding or "utf-8"
        text = body.decode(encoding, errors="replace")
        result = {
            "requested_url": url,
            "final_url": normalize_target_url(response.url) or response.url,
            "status_code": response.status_code,
            "content_type": response.headers.get("content-type", ""),
            "server": response.headers.get("server", ""),
            "set_cookie": bool(response.headers.get("set-cookie")),
            "redirect_chain": [item.url for item in response.history] + [response.url],
            "body": text,
            "body_bytes": len(body),
            "error": None,
        }
        response.close()
        return result
    except Exception as error:
        return {
            "requested_url": url,
            "final_url": url,
            "status_code": None,
            "content_type": "",
            "server": "",
            "set_cookie": False,
            "redirect_chain": [],
            "body": "",
            "body_bytes": 0,
            "error": str(error)[:500],
        }


def classify_prefilter(
    root_probe: dict[str, Any],
    page_metrics: list[dict[str, Any]],
    pages_followed: int,
) -> dict[str, Any]:
    """Produce a conservative, evidence-led initial classification."""
    reasons: list[str] = []
    status_code = root_probe["status_code"]
    if root_probe["error"]:
        return {
            "decision": "review",
            "functional_score": 0,
            "static_score": 0,
            "complexity_score": 0,
            "reasons": ["unreachable", root_probe["error"]],
        }
    if status_code in {401, 403, 429} or (status_code and status_code >= 500):
        return {
            "decision": "review",
            "functional_score": 0,
            "static_score": 0,
            "complexity_score": 0,
            "reasons": [f"blocked_or_unavailable_http_{status_code}"],
        }
    content_type = root_probe["content_type"].lower()
    if "html" not in content_type and "xhtml" not in content_type:
        return {
            "decision": "drop",
            "functional_score": 0,
            "static_score": 4,
            "complexity_score": 0,
            "reasons": ["root_response_is_not_html", content_type or "missing_content_type"],
        }
    if not is_same_site(root_probe["requested_url"], root_probe["final_url"]):
        return {
            "decision": "review",
            "functional_score": 0,
            "static_score": 0,
            "complexity_score": 0,
            "reasons": ["redirected_to_external_site", root_probe["final_url"]],
        }

    aggregate = Counter()
    parking = False
    waf = False
    for metrics in page_metrics:
        for key in (
            "text_chars",
            "anchor_count",
            "internal_link_count",
            "form_count",
            "non_search_form_count",
            "password_inputs",
            "script_count",
            "api_hints",
            "auth_hits",
            "business_hits",
        ):
            aggregate[key] += int(metrics.get(key, 0))
        parking = parking or bool(metrics.get("parking"))
        waf = waf or bool(metrics.get("waf"))

    if parking:
        return {
            "decision": "drop",
            "functional_score": 0,
            "static_score": 5,
            "complexity_score": 0,
            "reasons": ["parking_or_domain_sale_marker"],
        }
    if waf:
        return {
            "decision": "review",
            "functional_score": 0,
            "static_score": 0,
            "complexity_score": 0,
            "reasons": ["waf_or_challenge_marker"],
        }

    functional_score = 0
    if aggregate["password_inputs"] or aggregate["auth_hits"]:
        functional_score += 3
        reasons.append("authentication_signal")
    if aggregate["non_search_form_count"]:
        functional_score += 2
        reasons.append("business_form_signal")
    if root_probe["set_cookie"]:
        functional_score += 1
        reasons.append("session_cookie_signal")
    if aggregate["script_count"] >= 2 or aggregate["api_hints"]:
        functional_score += 1
        reasons.append("script_or_api_signal")
    if aggregate["internal_link_count"] >= 5:
        functional_score += 1
        reasons.append("internal_navigation_signal")
    if aggregate["business_hits"]:
        functional_score += 1
        reasons.append("business_function_signal")

    static_score = 0
    server_banner = (root_probe["server"] or "").lower()
    if any(marker in server_banner for marker in STATIC_HOST_MARKERS):
        static_score += 1
        reasons.append("static_hosting_hint")
    if aggregate["text_chars"] < 250:
        static_score += 1
        reasons.append("low_visible_text")
    if aggregate["anchor_count"] <= 2:
        static_score += 1
        reasons.append("minimal_navigation")
    if aggregate["form_count"] == 0 and aggregate["script_count"] <= 1:
        static_score += 1
        reasons.append("no_form_or_dynamic_script")

    complexity_score = 0
    if aggregate["internal_link_count"] >= 30:
        complexity_score += 2
    if aggregate["script_count"] >= 10:
        complexity_score += 2
    if pages_followed >= MAX_SHALLOW_LINKS and aggregate["internal_link_count"] >= 15:
        complexity_score += 1

    if static_score >= DROP_STATIC_SCORE and functional_score <= DROP_FUNCTIONAL_SCORE_MAX:
        decision = "drop"
        reasons.append("low_interaction_static_site")
    elif complexity_score >= REVIEW_COMPLEXITY_SCORE:
        decision = "review"
        reasons.append("high_complexity_needs_manual_scope_review")
    elif functional_score >= KEEP_FUNCTIONAL_SCORE:
        decision = "keep"
        reasons.append("sufficient_dynamic_or_functional_signals")
    else:
        decision = "review"
        reasons.append("ambiguous_or_insufficient_signals")

    return {
        "decision": decision,
        "functional_score": functional_score,
        "static_score": static_score,
        "complexity_score": complexity_score,
        "reasons": list(dict.fromkeys(reasons)),
    }


def ai_recheck(args: argparse.Namespace, result: dict[str, Any]) -> dict[str, Any] | None:
    """Optionally classify only review records near the rule threshold."""
    if not getattr(args, "ai", False) or result.get("decision") != "review":
        return None
    score = int(result.get("functional_score", 0))
    if not AI_BOUNDARY_LOW <= score <= AI_BOUNDARY_HIGH:
        return None
    endpoint = os.environ.get(AI_ENDPOINT_ENV, "").strip()
    api_key = os.environ.get(AI_API_KEY_ENV, "").strip()
    model = os.environ.get(AI_MODEL_ENV, DEFAULT_AI_MODEL).strip() or DEFAULT_AI_MODEL
    if not endpoint or not api_key:
        return {
            "status": "skipped",
            "reason": f"set {AI_ENDPOINT_ENV} and {AI_API_KEY_ENV} to enable AI",
        }
    summary = {
        "url": result["url"],
        "rule_scores": {
            "functional": result["functional_score"],
            "static": result["static_score"],
            "complexity": result["complexity_score"],
        },
        "rule_reasons": result["reasons"],
        "root_status": result["root_status"],
        "page_summary": result["page_summary"],
    }
    messages = [
        {
            "role": "system",
            "content": (
                "Classify a website only from supplied structural metadata. "
                "Return JSON with decision keep/review/drop and a concise reason."
            ),
        },
        {"role": "user", "content": json.dumps(summary, ensure_ascii=False)},
    ]
    try:
        response = requests.post(
            endpoint,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            json={
                "model": model,
                "messages": messages,
                "temperature": 0,
                "response_format": {"type": "json_object"},
            },
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        content = response.json()["choices"][0]["message"]["content"]
        parsed = json.loads(content)
        decision = str(parsed.get("decision", "")).lower()
        if decision not in {"keep", "review", "drop"}:
            raise ValueError("AI response lacks a valid decision")
        return {
            "status": "ok",
            "decision": decision,
            "reason": strip_text(str(parsed.get("reason", "")), 240),
            "model": model,
        }
    except Exception as error:
        return {"status": "failed", "reason": str(error)[:300], "model": model}



# ======================== Subdomain and middle-screen helpers ========================
def target_id_for_url(url: str) -> str:
    """Return a stable, filesystem-safe identifier for one normalized URL."""
    host = urlsplit(url).hostname or "target"
    slug = re.sub(r"[^a-z0-9]+", "-", host.lower()).strip("-") or "target"
    return f"{slug}-{hashlib.sha256(url.encode('utf-8')).hexdigest()[:12]}"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def subdomain_bonus_for_count(count: int) -> int:
    """Map observed DNS names to the user-approved initial-screening bonus."""
    if count >= 20:
        return 3
    if count >= 15:
        return 2
    if count >= 6:
        return 1
    return 0


def subdomain_footprint_label(count: int) -> str:
    if count >= 20:
        return "large_footprint"
    if count >= 15:
        return "broad_footprint"
    if count >= 6:
        return "medium_footprint"
    return "small_footprint"


def is_child_of_root(host: str, root_domain: str) -> bool:
    return host != root_domain and host.endswith("." + root_domain)


def classify_subdomain_type(subdomain: str, root_domain: str, cname: str = "") -> str:
    """Classify only public DNS labels; no HTTP or service probing is performed."""
    prefix = subdomain[: -(len(root_domain) + 1)] if is_child_of_root(subdomain, root_domain) else subdomain
    tokens = [item for item in re.split(r"[._-]+", prefix.lower()) if item]
    lowered = " ".join(tokens + [cname.lower()])
    groups = (
        ("dev_test", ("dev", "test", "testing", "stage", "staging", "uat", "beta", "demo")),
        ("admin", ("admin", "manage", "console", "panel")),
        ("auth", ("auth", "login", "sso", "account", "oauth", "passport")),
        ("api", ("api", "openapi", "gateway", "graphql")),
        ("business", ("order", "shop", "mall", "pay", "payment", "crm", "erp", "oa", "booking")),
        ("mail_vpn", ("mail", "smtp", "imap", "pop", "vpn", "remote", "webmail")),
        ("monitoring", ("monitor", "grafana", "status", "metrics", "prometheus")),
        ("delivery", ("cdn", "static", "img", "image", "media", "download", "assets", "oss")),
        ("web", ("www", "web", "m", "mobile", "portal", "home")),
    )
    for asset_type, markers in groups:
        if any(marker in tokens or marker in lowered for marker in markers):
            return asset_type
    return "unknown"


def extract_discovered_hosts(value: str, root_domain: str) -> set[str]:
    expression = re.compile(
        rf"(?<![A-Za-z0-9_.-])(?:[A-Za-z0-9-]+\.)+{re.escape(root_domain)}(?=$|[^A-Za-z0-9.-])",
        re.IGNORECASE,
    )
    hosts: set[str] = set()
    for match in expression.findall(value or ""):
        host = normalise_host(match.lstrip("*."))
        if host and is_child_of_root(host, root_domain):
            hosts.add(host)
    return hosts


def parse_nmap_dns_xml(xml_text: str, root_domain: str) -> set[str]:
    """Parse Nmap XML defensively; a regex fallback handles partial script output."""
    hosts = extract_discovered_hosts(xml_text, root_domain)
    try:
        document = ET.fromstring(xml_text)
    except Exception:
        return hosts
    for element in document.iter():
        for value in (element.text, *element.attrib.values()):
            if value:
                hosts.update(extract_discovered_hosts(str(value), root_domain))
    return hosts


def _resolve_subdomain_dns(host: str) -> tuple[list[str], str]:
    """Collect DNS addresses and an optional CNAME without contacting web services."""
    addresses: set[str] = set()
    try:
        for item in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM):
            address = item[4][0]
            try:
                if ipaddress.ip_address(address).is_global:
                    addresses.add(address)
            except ValueError:
                pass
    except OSError:
        pass
    cname = ""
    dig = shutil.which("dig")
    if dig:
        try:
            completed = subprocess.run(
                [dig, "+time=2", "+tries=1", "+short", "CNAME", host],
                capture_output=True, text=True, timeout=SUBDOMAIN_DNS_QUERY_TIMEOUT_SECONDS, check=False,
            )
            for line in completed.stdout.splitlines():
                candidate = normalise_host(line)
                if candidate:
                    cname = candidate
                    break
        except (OSError, subprocess.TimeoutExpired):
            pass
    return sorted(addresses), cname


def _cached_subdomain_rows(connection: sqlite3.Connection, root_domain: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for row in connection.execute(
        "SELECT * FROM subdomain_assets WHERE root_domain=? ORDER BY subdomain", (root_domain,)
    ):
        item = dict(row)
        item["sources"] = json.loads(item.pop("sources_json") or "[]")
        item["ips"] = json.loads(item.pop("ips_json") or "[]")
        rows.append(item)
    return rows


def summarise_subdomains(
    connection: sqlite3.Connection, root_domain: str, run_row: sqlite3.Row | None = None
) -> dict[str, Any]:
    rows = _cached_subdomain_rows(connection, root_domain)
    type_counts = Counter(str(row["asset_type"]) for row in rows)
    source_counts: Counter[str] = Counter()
    for row in rows:
        source_counts.update(str(source) for source in row["sources"])
    return {
        "root_domain": root_domain,
        "subdomain_count": len(rows),
        "subdomain_bonus": subdomain_bonus_for_count(len(rows)),
        "footprint": subdomain_footprint_label(len(rows)),
        "type_counts": dict(sorted(type_counts.items())),
        "source_counts": dict(sorted(source_counts.items())),
        "subdomains": rows,
        "status": str(run_row["status"]) if run_row else "not_run",
        "discovered_at": str(run_row["discovered_at"]) if run_row else "",
        "expires_at": str(run_row["expires_at"] or "") if run_row else "",
        "nmap_xml_path": str(run_row["nmap_xml_path"] or "") if run_row else "",
        "passive_json_path": str(run_row["passive_json_path"] or "") if run_row else "",
        "error": str(run_row["error"] or "") if run_row else "",
    }


def _subdomain_cache_is_fresh(row: sqlite3.Row | None) -> bool:
    if row is None or row["status"] not in {"ok", "partial"} or not row["expires_at"]:
        return False
    try:
        return datetime.fromisoformat(str(row["expires_at"])) > datetime.now(timezone.utc)
    except ValueError:
        return False


def fetch_passive_subdomains(
    root_domain: str, session: requests.Session, limiter: RateLimiter, timeout: float
) -> tuple[set[str], list[Any], str]:
    """Read public certificate-transparency names without accessing those names."""
    if not SUBDOMAIN_PASSIVE_ENABLED:
        return set(), [], "disabled"
    response: requests.Response | None = None
    try:
        response = request_with_retries(
            session,
            SUBDOMAIN_PASSIVE_ENDPOINT,
            params={"q": f"%.{root_domain}", "output": "json"},
            timeout=min(timeout, SUBDOMAIN_PASSIVE_TIMEOUT_SECONDS),
            limiter=limiter,
            max_attempts=SUBDOMAIN_PASSIVE_MAX_ATTEMPTS,
        )
        if response.status_code != 200:
            return set(), [], f"passive_http_{response.status_code}"
        payload = response.json()
        if not isinstance(payload, list):
            return set(), [], "passive_invalid_json"
        hosts: set[str] = set()
        for item in payload:
            if not isinstance(item, dict):
                continue
            for field in ("name_value", "common_name"):
                for raw in str(item.get(field, "")).splitlines():
                    host = normalise_host(raw.strip().lstrip("*."))
                    if host and is_child_of_root(host, root_domain):
                        hosts.add(host)
        return hosts, payload, "ok"
    except Exception as error:
        return set(), [], f"passive_error:{str(error)[:240]}"
    finally:
        if response is not None:
            response.close()


def run_nmap_dns_brute(root_domain: str, args: argparse.Namespace) -> tuple[set[str], str, str]:
    """Run only Nmap dns-brute with host/port discovery disabled."""
    nmap_path = str(getattr(args, "nmap_path", SUBDOMAIN_NMAP_PATH) or SUBDOMAIN_NMAP_PATH)
    executable = shutil.which(nmap_path) if not Path(nmap_path).is_file() else nmap_path
    wordlist = Path(str(getattr(args, "subdomain_wordlist", SUBDOMAIN_WORDLIST))).expanduser()
    if not executable:
        return set(), "", "nmap_unavailable"
    if not wordlist.is_file():
        return set(), "", f"wordlist_missing:{wordlist}"
    script_args = (
        f"dns-brute.domain={root_domain},dns-brute.hostlist={wordlist},"
        f"dns-brute.threads={int(getattr(args, 'subdomain_nmap_threads', SUBDOMAIN_NMAP_THREADS))}"
    )
    command = [
        executable, "-sn", "-n", "-Pn", "--script", "dns-brute",
        "--script-args", script_args, "-oX", "-", root_domain,
    ]
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=int(getattr(args, "subdomain_nmap_timeout", SUBDOMAIN_NMAP_TIMEOUT_SECONDS)),
            check=False,
        )
    except subprocess.TimeoutExpired:
        return set(), "", "nmap_timeout"
    except OSError as error:
        return set(), "", f"nmap_error:{str(error)[:240]}"
    xml_text = completed.stdout or ""
    hosts = parse_nmap_dns_xml(xml_text, root_domain)
    if completed.returncode != 0:
        detail = strip_text(completed.stderr or "nmap_nonzero_exit", 240)
        return hosts, xml_text, f"nmap_exit_{completed.returncode}:{detail}"
    return hosts, xml_text, "ok"


def discover_subdomains(
    connection: sqlite3.Connection,
    run_dir: Path,
    root_domain: str,
    args: argparse.Namespace,
    session: requests.Session,
    limiter: RateLimiter,
) -> dict[str, Any]:
    """Return cached or newly observed DNS-only subdomain evidence for one root."""
    enabled = bool(getattr(args, "subdomain_discovery", SUBDOMAIN_DISCOVERY_ENABLED))
    if not enabled:
        return {
            "root_domain": root_domain, "subdomain_count": 0, "subdomain_bonus": 0,
            "footprint": "small_footprint", "type_counts": {}, "source_counts": {},
            "subdomains": [], "status": "disabled", "discovered_at": "", "expires_at": "",
            "nmap_xml_path": "", "passive_json_path": "", "error": "",
        }
    existing = connection.execute(
        "SELECT * FROM subdomain_discovery_runs WHERE root_domain=?", (root_domain,)
    ).fetchone()
    if _subdomain_cache_is_fresh(existing) and not bool(getattr(args, "force_subdomain_refresh", False)):
        summary = summarise_subdomains(connection, root_domain, existing)
        summary["cache_action"] = "reused"
        return summary

    passive_hosts, passive_payload, passive_status = fetch_passive_subdomains(
        root_domain, session, limiter, float(getattr(args, "timeout", REQUEST_TIMEOUT_SECONDS))
    )
    nmap_hosts, nmap_xml, nmap_status = run_nmap_dns_brute(root_domain, args)
    archive_dir = run_dir / "subdomains" / re.sub(r"[^a-z0-9.-]+", "-", root_domain)
    passive_path = archive_dir / "passive-results.json"
    nmap_path = archive_dir / "nmap-dns.xml"
    write_json_atomic(passive_path, {"root_domain": root_domain, "status": passive_status, "results": passive_payload})
    write_text_atomic(nmap_path, nmap_xml or "<nmaprun/>\n")

    discovered: dict[str, set[str]] = {}
    for host in passive_hosts:
        discovered.setdefault(host, set()).add("certificate_transparency")
    for host in nmap_hosts:
        discovered.setdefault(host, set()).add("nmap_dns_brute")
    timestamp = utc_now()
    for host, sources in discovered.items():
        current = connection.execute(
            "SELECT sources_json, ips_json, cname, first_seen_at FROM subdomain_assets WHERE root_domain=? AND subdomain=?",
            (root_domain, host),
        ).fetchone()
        prior_sources = set(json.loads(current["sources_json"])) if current else set()
        prior_ips = set(json.loads(current["ips_json"])) if current else set()
        resolved_ips, resolved_cname = _resolve_subdomain_dns(host)
        ips = sorted(prior_ips | set(resolved_ips))
        cname = resolved_cname or (str(current["cname"]) if current else "")
        connection.execute(
            """
            INSERT INTO subdomain_assets(root_domain, subdomain, sources_json, ips_json, cname, asset_type, first_seen_at, last_seen_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(root_domain, subdomain) DO UPDATE SET
              sources_json=excluded.sources_json, ips_json=excluded.ips_json,
              asset_type=excluded.asset_type, last_seen_at=excluded.last_seen_at
            """,
            (
                root_domain, host, json_compact(sorted(prior_sources | sources)), json_compact(ips),
                cname, classify_subdomain_type(host, root_domain, cname),
                str(current["first_seen_at"]) if current else timestamp, timestamp,
            ),
        )
    failures = [status for status in (passive_status, nmap_status) if status != "ok"]
    status = "ok" if not failures else ("partial" if discovered else "failed")
    expires = (datetime.now(timezone.utc) + timedelta(days=SUBDOMAIN_CACHE_DAYS)).replace(microsecond=0).isoformat()
    config = {
        "passive_enabled": SUBDOMAIN_PASSIVE_ENABLED,
        "nmap_path": str(getattr(args, "nmap_path", SUBDOMAIN_NMAP_PATH)),
        "wordlist": str(getattr(args, "subdomain_wordlist", SUBDOMAIN_WORDLIST)),
        "threads": int(getattr(args, "subdomain_nmap_threads", SUBDOMAIN_NMAP_THREADS)),
    }
    connection.execute(
        """
        INSERT INTO subdomain_discovery_runs(root_domain, status, discovered_at, expires_at, passive_count, nmap_count, nmap_xml_path, passive_json_path, error, configuration_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(root_domain) DO UPDATE SET
          status=excluded.status, discovered_at=excluded.discovered_at, expires_at=excluded.expires_at,
          passive_count=excluded.passive_count, nmap_count=excluded.nmap_count,
          nmap_xml_path=excluded.nmap_xml_path, passive_json_path=excluded.passive_json_path,
          error=excluded.error, configuration_json=excluded.configuration_json
        """,
        (
            root_domain, status, timestamp, expires, len(passive_hosts), len(nmap_hosts),
            str(nmap_path), str(passive_path), "; ".join(failures)[:500], json_compact(config),
        ),
    )
    connection.commit()
    run_row = connection.execute(
        "SELECT * FROM subdomain_discovery_runs WHERE root_domain=?", (root_domain,)
    ).fetchone()
    summary = summarise_subdomains(connection, root_domain, run_row)
    summary["cache_action"] = "checked"
    return summary


def attach_subdomain_weight(result: dict[str, Any], summary: dict[str, Any]) -> dict[str, Any]:
    """Keep original rule scores intact and add an auditable DNS-footprint bonus."""
    reasons = list(result.get("reasons", []))
    base_decision = str(result.get("decision", "review"))
    functional = int(result.get("functional_score", 0))
    bonus = int(summary.get("subdomain_bonus", 0))
    hard_reason_prefixes = (
        "unreachable", "blocked_or_unavailable", "root_response_is_not_html",
        "redirected_to_external", "parking", "waf", "invalid_http_url", "non_public",
    )
    hard_failure = base_decision == "drop" or any(
        str(reason).startswith(hard_reason_prefixes) for reason in reasons
    )
    interaction = any(
        marker in reasons
        for marker in ("authentication_signal", "business_form_signal", "business_function_signal")
    )
    combined = functional + bonus
    initial_tier = "review"
    initial_passed = False
    if hard_failure:
        initial_tier = "drop" if base_decision == "drop" else "review"
    elif base_decision == "keep":
        strong = "business_form_signal" in reasons or (
            "authentication_signal" in reasons and "business_function_signal" in reasons
        )
        initial_tier = "priority_candidate" if strong else "conditional_candidate"
        initial_passed = True
    elif (
        base_decision == "review"
        and "high_complexity_needs_manual_scope_review" not in reasons
        and interaction
        and combined >= KEEP_FUNCTIONAL_SCORE
    ):
        result["decision"] = "keep"
        reasons.append("subdomain_footprint_assisted_pass")
        initial_tier = "conditional_candidate"
        initial_passed = True
    result["reasons"] = list(dict.fromkeys(reasons))
    result["base_decision"] = base_decision
    result["combined_functional_score"] = combined
    result["subdomain_root"] = str(summary.get("root_domain", ""))
    result["subdomain_count"] = int(summary.get("subdomain_count", 0))
    result["subdomain_bonus"] = bonus
    result["subdomain_footprint"] = str(summary.get("footprint", "small_footprint"))
    result["subdomain_type_counts"] = dict(summary.get("type_counts", {}))
    result["subdomain_source_counts"] = dict(summary.get("source_counts", {}))
    result["subdomain_status"] = str(summary.get("status", "not_run"))
    result["initial_tier"] = initial_tier
    result["initial_passed"] = initial_passed
    return result


def subdomain_enrichment_required(result: dict[str, Any]) -> bool:
    """Run DNS discovery only when it can legitimately affect a keep candidate."""
    if not PREFILTER_SUBDOMAIN_GATE_ENABLED:
        return True
    reasons = [str(reason) for reason in result.get("reasons", [])]
    hard_prefixes = (
        "unreachable", "blocked_or_unavailable", "root_response_is_not_html",
        "redirected_to_external", "parking", "waf", "low_interaction_static_site",
        "invalid_http_url", "non_public",
    )
    if str(result.get("decision", "review")) == "drop" or any(
        reason.startswith(hard_prefixes) for reason in reasons
    ):
        return False
    return any(
        marker in reasons
        for marker in ("authentication_signal", "business_form_signal", "business_function_signal")
    )


def enrich_prefilter_result(
    connection: sqlite3.Connection,
    run_dir: Path,
    args: argparse.Namespace,
    result: dict[str, Any],
    session: requests.Session,
    limiter: RateLimiter,
) -> tuple[dict[str, Any], dict[str, Any]]:
    normalized = str(result.get("normalized_url") or "")
    host = urlsplit(normalized).hostname or ""
    summary: dict[str, Any]
    if host and subdomain_enrichment_required(result):
        summary = discover_subdomains(
            connection, run_dir, registered_domain(host), args, session, limiter
        )
    else:
        summary = {
            "root_domain": registered_domain(host) if host else "",
            "subdomain_count": 0, "subdomain_bonus": 0,
            "footprint": "small_footprint", "type_counts": {}, "source_counts": {},
            "subdomains": [], "status": "skipped_not_eligible",
            "discovered_at": "", "expires_at": "", "nmap_xml_path": "",
            "passive_json_path": "", "error": "",
        }
    return attach_subdomain_weight(result, summary), summary


def _archive_manifest(
    connection: sqlite3.Connection, target_dir: Path, url: str, batch_id: str | None
) -> None:
    entries = []
    for path in sorted(target_dir.rglob("*")):
        if not path.is_file() or path.name == "manifest.json":
            continue
        relative = path.relative_to(target_dir)
        digest = sha256_file(path)
        entries.append({"path": str(relative), "sha256": digest, "bytes": path.stat().st_size})
        connection.execute(
            """
            INSERT OR REPLACE INTO target_artifacts(normalized_url, artifact_stage, artifact_path, sha256, batch_id, generated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (url, str(relative.parts[0]), str(path), digest, batch_id, utc_now()),
        )
    write_json_atomic(target_dir / "manifest.json", {"normalized_url": url, "generated_at": utc_now(), "files": entries})


def archive_initial_target(
    connection: sqlite3.Connection,
    run_dir: Path,
    result: dict[str, Any],
    occurrence: dict[str, Any] | None = None,
    batch_id: str | None = None,
) -> Path | None:
    """Create self-contained, sanitized evidence files for each initial-pass URL."""
    if not result.get("initial_passed"):
        return None
    url = str(result.get("normalized_url") or "")
    if not url:
        return None
    target_dir = run_dir / "targets" / target_id_for_url(url)
    initial_dir = target_dir / "initial"
    subdomain_dir = target_dir / "subdomains"
    occurrence = occurrence or {}
    project_id = str(occurrence.get("project_id") or result.get("project_id") or "")
    company_name = str(occurrence.get("company_name") or "")
    if project_id and not company_name:
        row = connection.execute(
            "SELECT company_name FROM catalog_projects WHERE project_id=?", (project_id,)
        ).fetchone()
        company_name = str(row["company_name"]) if row else ""
    root_domain = str(result.get("subdomain_root") or registered_domain(urlsplit(url).hostname or ""))
    run_row = connection.execute(
        "SELECT * FROM subdomain_discovery_runs WHERE root_domain=?", (root_domain,)
    ).fetchone()
    summary = summarise_subdomains(connection, root_domain, run_row) if root_domain else {"subdomains": [], "type_counts": {}}
    target_meta = {
        "target_id": target_dir.name, "normalized_url": url, "project_id": project_id,
        "company_name": company_name, "source": occurrence.get("source", result.get("source", "official_submit_page")),
        "scope": occurrence.get("scope", "include"), "created_at": utc_now(),
    }
    write_json_atomic(target_dir / "target.json", target_meta)
    write_json_atomic(initial_dir / "initial-result.json", result)
    write_json_atomic(initial_dir / "root-probe-summary.json", {
        key: result.get(key) for key in (
            "normalized_url", "root_status", "root_final_url", "root_content_type", "redirect_chain", "analyzed_at"
        )
    })
    write_json_atomic(initial_dir / "page-metrics.json", {
        "page_summary": result.get("page_summary", {}), "page_metrics": result.get("page_metrics", [])
    })
    write_json_atomic(initial_dir / "shallow-links.json", {"pages_followed": result.get("pages_followed", [])})
    initial_report = "\n".join([
        f"# 初筛报告：{url}", "", "| 字段 | 值 |", "|---|---|",
        f"| 初筛结论 | {result.get('decision', 'review')} |",
        f"| 初筛层级 | {result.get('initial_tier', 'review')} |",
        f"| 原功能分 | {result.get('functional_score', 0)} |",
        f"| 子域加分 | {result.get('subdomain_bonus', 0)} |",
        f"| 合计功能分 | {result.get('combined_functional_score', result.get('functional_score', 0))} |",
        f"| 子域数量 | {result.get('subdomain_count', 0)} |",
        f"| 子域足迹 | {result.get('subdomain_footprint', '')} |",
        f"| 命中规则 | {'; '.join(result.get('reasons', []))} |", "",
        "本目录不保存 Cookie、会话、密码、表单内容或浏览器 Profile。", "",
    ])
    write_text_atomic(initial_dir / "initial-report.md", initial_report)
    write_json_atomic(subdomain_dir / "summary.json", {key: value for key, value in summary.items() if key != "subdomains"})
    write_json_atomic(subdomain_dir / "type-summary.json", summary.get("type_counts", {}))
    fields = ["subdomain", "asset_type", "sources", "ips", "cname", "first_seen_at", "last_seen_at"]
    rows = [
        {**item, "sources": ";".join(item.get("sources", [])), "ips": ";".join(item.get("ips", []))}
        for item in summary.get("subdomains", [])
    ]
    write_csv_atomic(subdomain_dir / "subdomains.csv", fields, rows)
    passive_source = Path(str(summary.get("passive_json_path", "")))
    nmap_source = Path(str(summary.get("nmap_xml_path", "")))
    if passive_source.is_file():
        shutil.copyfile(passive_source, subdomain_dir / "passive-results.json")
    else:
        write_json_atomic(subdomain_dir / "passive-results.json", {"status": summary.get("status", "not_run"), "results": []})
    if nmap_source.is_file():
        shutil.copyfile(nmap_source, subdomain_dir / "nmap-dns.xml")
    else:
        write_text_atomic(subdomain_dir / "nmap-dns.xml", "<nmaprun/>\n")
    _archive_manifest(connection, target_dir, url, batch_id)
    connection.commit()
    return target_dir

def prefilter_one_url(
    args: argparse.Namespace,
    url: str,
    session: requests.Session,
    limiter: RateLimiter,
) -> dict[str, Any]:
    normalized = normalize_target_url(url)
    timestamp = utc_now()
    if not normalized:
        return {
            "url": url,
            "normalized_url": None,
            "decision": "drop",
            "functional_score": 0,
            "static_score": 0,
            "complexity_score": 0,
            "reasons": ["invalid_http_url"],
            "analyzed_at": timestamp,
        }
    if not is_public_target(normalized):
        return {
            "url": url,
            "normalized_url": normalized,
            "decision": "drop",
            "functional_score": 0,
            "static_score": 0,
            "complexity_score": 0,
            "reasons": ["non_public_or_local_target"],
            "analyzed_at": timestamp,
        }
    root_url = urlunsplit(
        (urlsplit(normalized).scheme, urlsplit(normalized).netloc, "/", "", "")
    )
    root_probe = fetch_html_probe(
        session, root_url, timeout=args.timeout, limiter=limiter,
        max_attempts=prefilter_http_attempt_count(args),
    )
    root_metrics = (
        analyse_html(root_probe["final_url"], root_probe["body"])
        if root_probe["body"]
        else {}
    )
    page_metrics = [root_metrics] if root_metrics else []
    followed_links: list[str] = []
    quick_classification = classify_prefilter(root_probe, page_metrics, 0)
    quick_reasons = [str(reason) for reason in quick_classification.get("reasons", [])]
    shallow_skip_prefixes = (
        "unreachable", "blocked_or_unavailable", "root_response_is_not_html",
        "redirected_to_external", "parking", "waf", "low_interaction_static_site",
    )
    shallow_required = not any(
        reason.startswith(shallow_skip_prefixes) for reason in quick_reasons
    )
    if (
        root_probe["body"]
        and not root_probe["error"]
        and root_probe["status_code"]
        and "html" in root_probe["content_type"].lower()
        and (not PREFILTER_SHALLOW_GATE_ENABLED or shallow_required)
    ):
        for link in extract_shallow_links(
            root_probe["final_url"], root_probe["body"], args.max_shallow_links
        ):
            child_probe = fetch_html_probe(
                session, link, timeout=args.timeout, limiter=limiter,
                max_attempts=prefilter_http_attempt_count(args),
            )
            if (
                child_probe["body"]
                and not child_probe["error"]
                and "html" in child_probe["content_type"].lower()
            ):
                page_metrics.append(
                    analyse_html(child_probe["final_url"], child_probe["body"])
                )
                followed_links.append(child_probe["final_url"])
    classification = (
        quick_classification
        if PREFILTER_SHALLOW_GATE_ENABLED and not shallow_required
        else classify_prefilter(root_probe, page_metrics, len(followed_links))
    )
    classification["quick_stage_decision"] = quick_classification.get("decision", "review")
    classification["quick_stage_reasons"] = quick_reasons
    classification["shallow_scan_performed"] = bool(followed_links)
    result: dict[str, Any] = {
        "url": url,
        "normalized_url": normalized,
        **classification,
        "root_status": root_probe["status_code"],
        "root_final_url": root_probe["final_url"],
        "redirect_chain": root_probe["redirect_chain"],
        "root_content_type": root_probe["content_type"],
        "pages_followed": followed_links,
        "page_metrics": [
            {
                key: item.get(key)
                for key in (
                    "title", "text_excerpt", "text_chars", "anchor_count", "internal_link_count",
                    "form_count", "non_search_form_count", "password_inputs",
                    "script_count", "api_hints", "auth_hits", "business_hits", "links",
                )
            }
            for item in page_metrics
        ],
        "page_summary": {
            "pages_observed": len(page_metrics),
            "text_chars": sum(int(item.get("text_chars", 0)) for item in page_metrics),
            "anchors": sum(int(item.get("anchor_count", 0)) for item in page_metrics),
            "internal_links": sum(
                int(item.get("internal_link_count", 0)) for item in page_metrics
            ),
            "forms": sum(int(item.get("form_count", 0)) for item in page_metrics),
            "password_inputs": sum(
                int(item.get("password_inputs", 0)) for item in page_metrics
            ),
            "scripts": sum(int(item.get("script_count", 0)) for item in page_metrics),
        },
        "analyzed_at": timestamp,
    }
    ai_result = ai_recheck(args, result)
    if ai_result:
        result["ai_review"] = ai_result
        if ai_result.get("status") == "ok":
            result["decision"] = ai_result["decision"]
            result["reasons"].append("ai_boundary_review")
    return result


def save_prefilter_result(
    connection: sqlite3.Connection, result: dict[str, Any]
) -> None:
    normalized = result.get("normalized_url")
    if not normalized:
        return
    connection.execute(
        """
        INSERT INTO prefilter_results(normalized_url, decision, functional_score, static_score, complexity_score, reasons_json, result_json, analyzed_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(normalized_url) DO UPDATE SET
          decision=excluded.decision,
          functional_score=excluded.functional_score,
          static_score=excluded.static_score,
          complexity_score=excluded.complexity_score,
          reasons_json=excluded.reasons_json,
          result_json=excluded.result_json,
          analyzed_at=excluded.analyzed_at
        """,
        (
            normalized,
            result["decision"],
            int(result["functional_score"]),
            int(result["static_score"]),
            int(result["complexity_score"]),
            json_compact(result["reasons"]),
            json_compact(result),
            result["analyzed_at"],
        ),
    )


def export_prefilter(
    connection: sqlite3.Connection, run_dir: Path
) -> dict[str, int]:
    rows = [
        json.loads(row["result_json"])
        for row in connection.execute(
            "SELECT result_json FROM prefilter_results ORDER BY normalized_url"
        )
    ]
    write_jsonl_atomic(run_dir / "prefilter.jsonl", rows)
    kept = [
        row["normalized_url"]
        for row in rows
        if row.get("decision") == "keep" and row.get("normalized_url")
    ]
    write_text_atomic(run_dir / "kept_urls.txt", "".join(url + "\n" for url in kept))
    reviews = [row for row in rows if row.get("decision") == "review"]
    review_path = run_dir / "review.csv"
    review_path.parent.mkdir(parents=True, exist_ok=True)
    with review_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "normalized_url",
                "root_status",
                "functional_score",
                "static_score",
                "complexity_score",
                "reasons",
            ],
        )
        writer.writeheader()
        for row in reviews:
            writer.writerow(
                {
                    "normalized_url": row.get("normalized_url", ""),
                    "root_status": row.get("root_status", ""),
                    "functional_score": row.get("functional_score", 0),
                    "static_score": row.get("static_score", 0),
                    "complexity_score": row.get("complexity_score", 0),
                    "reasons": ";".join(row.get("reasons", [])),
                }
            )
    return dict(Counter(str(row.get("decision")) for row in rows))


def records_from_input(
    path: Path, asserted_source: str | None
) -> list[dict[str, Any]]:
    suffix = path.suffix.lower()
    if suffix == ".txt":
        if asserted_source != "official_submit_page":
            raise ValueError(
                "plain URL input requires --input-source official_submit_page"
            )
        return [
            {"url": line.strip(), "source": asserted_source, "scope": "include"}
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
    content = path.read_text(encoding="utf-8")
    if suffix == ".jsonl":
        rows = [json.loads(line) for line in content.splitlines() if line.strip()]
    else:
        payload = json.loads(content)
        if isinstance(payload, dict):
            rows = (
                payload.get("results")
                or payload.get("assets")
                or payload.get("items")
                or []
            )
        else:
            rows = payload
    if not isinstance(rows, list):
        raise ValueError("input must contain a JSON/JSONL list of asset records")
    return [row for row in rows if isinstance(row, dict)]


def load_official_asset_records(
    connection: sqlite3.Connection,
    input_path: Path | None,
    asserted_source: str | None,
) -> list[dict[str, Any]]:
    if input_path:
        records = records_from_input(input_path, asserted_source)
    else:
        records = [
            dict(row)
            for row in connection.execute(
                "SELECT * FROM official_assets WHERE scope='include' "
                "ORDER BY project_id, normalized_url"
            )
        ]
    accepted: list[dict[str, Any]] = []
    rejected = 0
    for record in records:
        source = record.get("source") or asserted_source
        scope = str(record.get("scope", "include")).lower()
        candidate = (
            record.get("normalized_url")
            or record.get("url")
            or record.get("asset")
            or record.get("raw_asset")
        )
        normalized = normalize_target_url(str(candidate or ""))
        if source != "official_submit_page" or scope == "exclude" or not normalized:
            rejected += 1
            continue
        accepted.append(
            {
                "url": normalized,
                "source": source,
                "project_id": record.get("project_id"),
            }
        )
    if rejected:
        log(
            f"prefilter input: rejected {rejected} records without confirmed official include scope"
        )
    deduplicated: dict[str, dict[str, Any]] = {}
    for record in accepted:
        deduplicated.setdefault(record["url"], record)
    return list(deduplicated.values())


def prefilter_worker_count(args: argparse.Namespace) -> int:
    """Return a bounded count for concurrent HTTP-only initial probes."""
    return max(1, min(8, int(getattr(args, "prefilter_workers", PREFILTER_WORKERS))))


def prefilter_http_attempt_count(args: argparse.Namespace) -> int:
    """Return a bounded request-attempt count for one initial-screening page."""
    return max(1, min(MAX_RETRIES, int(getattr(
        args, "prefilter_http_attempts", PREFILTER_HTTP_MAX_ATTEMPTS
    ))))


def prefilter_worker_error(url: str, error: Exception) -> dict[str, Any]:
    """Convert an unexpected worker exception into an auditable review record."""
    normalized = normalize_target_url(url)
    return {
        "url": url,
        "normalized_url": normalized,
        "decision": "review" if normalized else "drop",
        "functional_score": 0,
        "static_score": 0,
        "complexity_score": 0,
        "reasons": ["prefilter_worker_error"],
        "error_class": type(error).__name__,
        "error": strip_text(str(error), 240),
        "analyzed_at": utc_now(),
    }


def iter_prefilter_network_results(
    args: argparse.Namespace,
    records: list[dict[str, Any]],
    limiter: RateLimiter,
) -> Iterable[tuple[dict[str, Any], dict[str, Any]]]:
    """Probe pages concurrently; retain one main-thread writer for SQLite/artifacts."""
    if not records:
        return

    def probe(record: dict[str, Any]) -> dict[str, Any]:
        session = make_http_session()
        try:
            return prefilter_one_url(args, str(record["url"]), session, limiter)
        except Exception as error:  # Keep a single broken target from halting the run.
            return prefilter_worker_error(str(record["url"]), error)
        finally:
            session.close()

    workers = prefilter_worker_count(args)
    if workers == 1:
        for record in records:
            yield record, probe(record)
        return

    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="prefilter") as executor:
        pending: dict[Any, dict[str, Any]] = {}
        records_iter = iter(records)
        for _ in range(min(workers, len(records))):
            record = next(records_iter)
            pending[executor.submit(probe, record)] = record
        while pending:
            future = next(as_completed(pending))
            record = pending.pop(future)
            try:
                result = future.result()
            except Exception as error:  # Defensive guard for executor-level failures.
                result = prefilter_worker_error(str(record["url"]), error)
            try:
                next_record = next(records_iter)
            except StopIteration:
                next_record = None
            if next_record is not None:
                pending[executor.submit(probe, next_record)] = next_record
            yield record, result


def command_prefilter(args: argparse.Namespace) -> int:
    run_dir, db_path = run_paths(args)
    if args.dry_run:
        log(f"DRY RUN prefilter: official assets -> {run_dir}/prefilter.jsonl")
        return 0
    connection = open_database(db_path)
    input_path = Path(args.input).expanduser().resolve() if args.input else None
    try:
        records = load_official_asset_records(
            connection, input_path, args.input_source
        )
    except Exception as error:
        log(f"prefilter input error: {error}")
        connection.close()
        return 2
    if args.limit:
        records = records[: args.limit]
    if not records:
        log("prefilter: no confirmed official include-scope URLs available")
        connection.close()
        return 0

    pending_records: list[dict[str, Any]] = []
    for record in records:
        existing = connection.execute(
            "SELECT 1 FROM prefilter_results WHERE normalized_url=?", (record["url"],)
        ).fetchone()
        if args.resume and existing:
            log(f"prefilter resume skip: {record['url']}")
            continue
        pending_records.append(record)

    session = make_http_session()
    limiter = RateLimiter(args.min_interval)
    processed = 0
    kept_count = 0
    stop_after_keeps = max(0, int(getattr(args, "stop_after_keeps", 0)))
    stopped_after_keep_target = False
    try:
        for record, result in iter_prefilter_network_results(args, pending_records, limiter):
            result["source"] = record["source"]
            result["project_id"] = record.get("project_id")
            result, _summary = enrich_prefilter_result(
                connection, run_dir, args, result, session, limiter
            )
            save_prefilter_result(connection, result)
            archive_initial_target(connection, run_dir, result, record)
            connection.commit()
            processed += 1
            if result.get("decision") == "keep":
                kept_count += 1
            log(
                f"prefilter {processed}/{len(records)}: {result['decision'].upper()} {record['url']}"
            )
            if stop_after_keeps and kept_count >= stop_after_keeps:
                stopped_after_keep_target = True
                log(
                    f"prefilter: initial keep target reached ({kept_count}/{stop_after_keeps}); stopping"
                )
                break
        counts = export_prefilter(connection, run_dir)
        write_json_atomic(
            run_dir / "run_manifest.json",
            {
                "generated_at": utc_now(),
                "stage": "prefilter",
                "input_record_count": len(records),
                "processed_count": processed,
                "counts": counts,
                "configuration": {
                    "max_shallow_links": args.max_shallow_links,
                    "min_request_interval": args.min_interval,
                    "prefilter_workers": prefilter_worker_count(args),
                    "prefilter_http_attempts": prefilter_http_attempt_count(args),
                    "stop_after_keeps": stop_after_keeps,
                    "kept_count": kept_count,
                    "stopped_after_keep_target": stopped_after_keep_target,
                    "ai_enabled": bool(args.ai),
                    "subdomain_discovery": bool(getattr(args, "subdomain_discovery", False)),
                    "subdomain_wordlist": str(getattr(args, "subdomain_wordlist", SUBDOMAIN_WORDLIST)),
                },
            },
        )
    finally:
        session.close()
        connection.close()
    log(f"prefilter export: {counts} -> {run_dir}")
    return 0


def extract_urls_from_text(text: str) -> list[str]:
    url_pattern = re.compile(
        r"(?:(?:https?:)?//[A-Za-z0-9._~%:-]+(?:/[A-Za-z0-9._~%/?#=&+\-]*)?)"
    )
    host_pattern = re.compile(
        r"(?<![@\w.-])(?:[A-Za-z0-9-]+\.)+(?:com|cn|net|org|gov\.cn|edu\.cn|com\.cn)"
        r"(?:/[A-Za-z0-9._~%/?#=&+\-]*)?"
    )
    return url_pattern.findall(text) + host_pattern.findall(text)


def context_scope(context: str) -> tuple[str, str]:
    lowered = context.lower()
    if any(marker in lowered for marker in EXCLUDE_MARKERS):
        return "exclude", "high"
    if any(marker in lowered for marker in SCOPE_MARKERS):
        return "include", "high"
    return "include", "medium"


def extract_scoped_text_candidates(
    text: str, source_label: str
) -> list[dict[str, Any]]:
    """Extract only assets adjacent to visible, explicit scope labels.

    Raw submit-page HTML includes navigation links and large JavaScript bundles.  Those
    are deliberately excluded before URL recognition so they cannot be recorded as
    official targets.  URL-like values in a scope-labelled input are retained.
    """
    parser = ScopeTextParser()
    parser.feed(text)
    parser.close()
    candidates: list[dict[str, Any]] = []
    scope_expression = "|".join(
        re.escape(marker) for marker in (*TEXT_SCOPE_MARKERS, *EXCLUDE_MARKERS)
    )
    for visible_text in parser.scope_contexts():
        matches = list(re.finditer(scope_expression, visible_text, flags=re.IGNORECASE))
        for index, match in enumerate(matches):
            # Stop at the next scope label so adjacent include/exclude sections do not
            # cross-classify each other's URLs.
            start = match.start()
            next_start = (
                matches[index + 1].start()
                if index + 1 < len(matches)
                else len(visible_text)
            )
            end = min(next_start, match.end() + SCOPE_TEXT_CONTEXT_CHARS)
            context = strip_text(visible_text[start:end], 900)
            scope, confidence = context_scope(match.group(0))
            for raw in extract_urls_from_text(context):
                normalized = normalize_target_url(raw)
                if normalized and not is_butian_internal(normalized):
                    candidates.append(
                        {
                            "normalized_url": normalized,
                            "raw_asset": raw,
                            "asset_kind": "url_or_domain",
                            "scope": scope,
                            "source": "official_submit_page",
                            "confidence": confidence,
                            "evidence": f"{source_label}: {context}",
                        }
                    )
    return candidates


def is_butian_internal(url: str) -> bool:
    host = urlsplit(url).hostname or ""
    return (
        host == "butian.net"
        or host.endswith(".butian.net")
        or host == "qianxin.com"
        or host.endswith(".qianxin.com")
    )


def extract_scoped_json_candidates(
    value: Any,
    context: str = "root",
    declared_scope: str | None = None,
) -> list[dict[str, Any]]:
    """Extract JSON assets only when the JSON itself declares their scope."""
    candidates: list[dict[str, Any]] = []
    if isinstance(value, dict):
        scope_value = " ".join(
            str(value.get(key, ""))
            for key in ("scope", "scope_type", "asset_scope", "range_type")
        ).strip().lower()
        if any(marker in scope_value for marker in EXCLUDE_MARKERS):
            local_scope = "exclude"
        elif any(marker in scope_value for marker in SCOPE_MARKERS) or scope_value in {
            "include",
            "in_scope",
        }:
            local_scope = "include"
        else:
            local_scope = declared_scope
        for key, item in value.items():
            child_context = f"{context}.{key}".lower()
            candidates.extend(
                extract_scoped_json_candidates(item, child_context, local_scope)
            )
    elif isinstance(value, list):
        for item in value:
            candidates.extend(
                extract_scoped_json_candidates(item, context, declared_scope)
            )
    elif isinstance(value, str) and declared_scope:
        for raw in extract_urls_from_text(value):
            normalized = normalize_target_url(raw)
            if normalized and not is_butian_internal(normalized):
                candidates.append(
                    {
                        "normalized_url": normalized,
                        "raw_asset": raw,
                        "asset_kind": "json_asset",
                        "scope": declared_scope,
                        "source": "official_submit_page",
                        "confidence": "high",
                        "evidence": f"json field: {context}",
                    }
                )
    return candidates


def deduplicate_assets(
    candidates: Iterable[dict[str, Any]]
) -> list[dict[str, Any]]:
    values: dict[tuple[str, str], dict[str, Any]] = {}
    for candidate in candidates:
        key = (candidate["normalized_url"], candidate["scope"])
        current = values.get(key)
        if current is None or (
            candidate["confidence"] == "high" and current["confidence"] != "high"
        ):
            values[key] = candidate
    return list(values.values())


def import_playwright() -> Any:
    try:
        from playwright.sync_api import sync_playwright
    except ImportError as error:
        raise RuntimeError(
            "Playwright is required for login/extract. Install: pip install -r requirements-butian.txt"
        ) from error
    return sync_playwright


def vnc_browser_environment(
    display: str, xauthority_value: str, *, require_xauthority: bool
) -> dict[str, str]:
    """Build the X11 environment for a headed Chromium process on the VNC desktop."""
    xauthority = Path(xauthority_value).expanduser()
    if require_xauthority and not xauthority.is_file():
        raise RuntimeError(
            f"Xauthority file not found: {xauthority}; pass --xauthority PATH "
            "or set BUTIAN_XAUTHORITY"
        )
    environment = {**os.environ, "DISPLAY": display}
    if xauthority.is_file():
        # Snap changes HOME inside its sandbox, so pass the VNC X11 cookie explicitly.
        environment["XAUTHORITY"] = str(xauthority)
    return environment


def command_login(args: argparse.Namespace) -> int:
    auth_state = path_from_argument(args.auth_state, DEFAULT_AUTH_STATE)
    profile_dir = path_from_argument(args.profile_dir, DEFAULT_BROWSER_PROFILE)
    xauthority = Path(args.xauthority).expanduser()
    if args.dry_run:
        log(
            "DRY RUN login: "
            f"Chromium profile {profile_dir}, state {auth_state}, "
            f"DISPLAY={args.display}, XAUTHORITY={xauthority}"
        )
        return 0
    sync_playwright = import_playwright()
    auth_state.parent.mkdir(parents=True, exist_ok=True)
    profile_dir.mkdir(parents=True, exist_ok=True)
    # The persistent profile stores session material too; keep it private.
    profile_dir.chmod(0o700)
    browser_path = args.browser_path
    environment = vnc_browser_environment(
        args.display, str(xauthority), require_xauthority=True
    )
    with sync_playwright() as playwright:
        context = playwright.chromium.launch_persistent_context(
            user_data_dir=str(profile_dir),
            executable_path=browser_path if Path(browser_path).exists() else None,
            headless=False,
            viewport={"width": 1280, "height": 800},
            env=environment,
        )
        page = context.pages[0] if context.pages else context.new_page()
        page.goto(
            BUTIAN_SUBMIT_URL.format(project_id=args.verify_project_id),
            wait_until="domcontentloaded",
            timeout=args.browser_timeout * 1000,
        )
        log("Complete Butian SSO in the dedicated VNC browser, then return here and press Enter.")
        input()
        page.goto(
            BUTIAN_SUBMIT_URL.format(project_id=args.verify_project_id),
            wait_until="domcontentloaded",
            timeout=args.browser_timeout * 1000,
        )
        if (
            "Login" in page.url
            or "skyeye.qianxin.com" in page.url
            or "login" in page.url.lower()
        ):
            context.close()
            log("login verification failed: submit page still redirects to SSO")
            return 2
        context.storage_state(path=str(auth_state))
        context.close()
    ensure_private_file(auth_state)
    log(f"authenticated state saved: {auth_state}")
    return 0


def selected_projects(
    connection: sqlite3.Connection,
    project_ids: list[str] | None,
    limit: int | None,
) -> list[sqlite3.Row]:
    if project_ids:
        placeholders = ",".join("?" for _ in project_ids)
        query = (
            "SELECT project_id, company_name FROM catalog_projects "
            f"WHERE project_id IN ({placeholders})"
        )
        rows = list(connection.execute(query, project_ids))
        requested_order = {
            project_id: index for index, project_id in enumerate(dict.fromkeys(project_ids))
        }
        rows.sort(key=lambda row: requested_order.get(str(row["project_id"]), len(requested_order)))
    else:
        rows = list(
            connection.execute(
                "SELECT project_id, company_name FROM catalog_projects "
                "ORDER BY CAST(project_id AS INTEGER) DESC"
            )
        )
    return rows[:limit] if limit else rows


def command_extract(args: argparse.Namespace) -> int:
    run_dir, db_path = run_paths(args)
    auth_state = path_from_argument(args.auth_state, DEFAULT_AUTH_STATE)
    if args.dry_run:
        log(
            f"DRY RUN extract: authenticated submit pages -> {run_dir}/official_assets.jsonl"
        )
        return 0
    if not auth_state.is_file():
        log(
            f"login_required: no authenticated state at {auth_state}; run the login command first"
        )
        return 3
    connection = open_database(db_path)
    projects = selected_projects(connection, args.project_id, args.limit)
    if not projects:
        log("extract: catalog is empty; run catalog first")
        connection.close()
        return 2
    sync_playwright = import_playwright()
    login_required_seen = False
    browser_environment = vnc_browser_environment(
        args.display, args.xauthority, require_xauthority=args.headful
    )
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(
            headless=not args.headful,
            executable_path=args.browser_path if Path(args.browser_path).exists() else None,
            env=browser_environment,
        )
        context = browser.new_context(storage_state=str(auth_state), user_agent=USER_AGENT)
        for index, project in enumerate(projects, 1):
            project_id, company_name = (
                str(project["project_id"]),
                str(project["company_name"]),
            )
            existing = connection.execute(
                "SELECT status FROM extraction_results WHERE project_id=?", (project_id,)
            ).fetchone()
            if args.resume and existing and existing["status"] in {"ok", "no_assets_found"}:
                log(f"extract resume skip {project_id}")
                continue
            page = context.new_page()
            captured_json: list[Any] = []

            def on_response(response: Any) -> None:
                content_type = response.headers.get("content-type", "").lower()
                if "json" not in content_type or len(captured_json) >= 12:
                    return
                try:
                    body = response.body()
                    if len(body) <= MAX_CAPTURED_JSON_BYTES:
                        captured_json.append(
                            json.loads(body.decode("utf-8", errors="replace"))
                        )
                except Exception:
                    pass

            page.on("response", on_response)
            page_url = BUTIAN_SUBMIT_URL.format(project_id=project_id)
            try:
                page.goto(
                    page_url,
                    wait_until="domcontentloaded",
                    timeout=args.browser_timeout * 1000,
                )
                page.wait_for_timeout(BROWSER_SETTLE_MILLISECONDS)
                current_url = page.url
                if (
                    "Login" in current_url
                    or "skyeye.qianxin.com" in current_url
                    or "login" in current_url.lower()
                ):
                    status, message, candidates = (
                        "login_required",
                        "authenticated session expired",
                        [],
                    )
                    login_required_seen = True
                else:
                    html_text = page.content()
                    candidates = extract_scoped_text_candidates(html_text, "submit page")
                    for payload in captured_json:
                        candidates.extend(extract_scoped_json_candidates(payload))
                    candidates = deduplicate_assets(candidates)
                    status = "ok" if candidates else "no_assets_found"
                    message = ""
            except Exception as error:
                current_url, status, message, candidates = (
                    page_url,
                    "failed",
                    str(error)[:500],
                    [],
                )
            finally:
                page.close()
            now = utc_now()
            connection.execute(
                "INSERT OR REPLACE INTO extraction_results VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    project_id,
                    company_name,
                    status,
                    current_url,
                    len(candidates),
                    message,
                    now,
                ),
            )
            for candidate in candidates:
                record = {
                    "project_id": project_id,
                    "company_name": company_name,
                    **candidate,
                    "discovered_at": now,
                }
                connection.execute(
                    """
                    INSERT OR REPLACE INTO official_assets(project_id, normalized_url, raw_asset, asset_kind, scope, source, confidence, evidence, discovered_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        record["project_id"],
                        record["normalized_url"],
                        record["raw_asset"],
                        record["asset_kind"],
                        record["scope"],
                        record["source"],
                        record["confidence"],
                        record["evidence"],
                        record["discovered_at"],
                    ),
                )
            connection.commit()
            log(
                f"extract {index}/{len(projects)}: {project_id} {status} assets={len(candidates)}"
            )
            time.sleep(args.min_interval)
        context.close()
        browser.close()

    assets = [
        dict(row)
        for row in connection.execute(
            "SELECT * FROM official_assets ORDER BY project_id, normalized_url"
        )
    ]
    project_names = {
        row["project_id"]: row["company_name"]
        for row in connection.execute(
            "SELECT project_id, company_name FROM catalog_projects"
        )
    }
    for row in assets:
        row["company_name"] = project_names.get(row["project_id"], "")
    write_jsonl_atomic(run_dir / "official_assets.jsonl", assets)
    extraction_counts = dict(
        Counter(
            row["status"]
            for row in connection.execute("SELECT status FROM extraction_results")
        )
    )
    write_json_atomic(
        run_dir / "extraction-manifest.json",
        {
            "generated_at": utc_now(),
            "project_count": len(projects),
            "asset_count": len(assets),
            "statuses": extraction_counts,
            "source": "official_submit_page",
            "note": "Only authenticated submit-page evidence is marked as official scope.",
        },
    )
    connection.close()
    log(
        f"extract export: {len(assets)} official asset records -> {run_dir / 'official_assets.jsonl'}"
    )
    return 3 if login_required_seen else 0



# ============================== DeepSeek middle screening ==============================
def load_deepseek_api_key() -> str:
    """Read one private key without exporting, logging, or archiving its value."""
    value = os.environ.get(DEEPSEEK_API_KEY_ENV, "").strip()
    if value:
        return value
    try:
        for raw_line in DEEPSEEK_ENV_FILE.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if line.startswith("export "):
                line = line[7:].lstrip()
            if not line.startswith(DEEPSEEK_API_KEY_ENV + "="):
                continue
            candidate = line.split("=", 1)[1].strip()
            if len(candidate) >= 2 and candidate[0] == candidate[-1] and candidate[0] in {"'", '"'}:
                candidate = candidate[1:-1]
            return candidate.strip()
    except OSError:
        pass
    return ""


def parse_json_object(value: str) -> dict[str, Any]:
    text = str(value or "").strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text, flags=re.IGNORECASE | re.DOTALL).strip()
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", text, flags=re.DOTALL)
        if not match:
            raise
        parsed = json.loads(match.group(0))
    if not isinstance(parsed, dict):
        raise ValueError("AI response is not a JSON object")
    return parsed


def _official_context_for_url(connection: sqlite3.Connection, url: str) -> dict[str, Any]:
    row = connection.execute(
        """
        SELECT assets.project_id, projects.company_name, assets.scope, assets.source,
               assets.confidence, assets.evidence
        FROM official_assets AS assets
        LEFT JOIN catalog_projects AS projects ON projects.project_id=assets.project_id
        WHERE assets.normalized_url=? AND assets.scope='include' AND assets.source='official_submit_page'
        ORDER BY assets.confidence DESC, assets.project_id LIMIT 1
        """,
        (url,),
    ).fetchone()
    return dict(row) if row else {
        "project_id": "", "company_name": "", "scope": "include",
        "source": "official_submit_page", "confidence": "", "evidence": "",
    }


def _initial_fields_from_result(
    connection: sqlite3.Connection, result: dict[str, Any]
) -> dict[str, Any]:
    """Enrich legacy cached results without issuing new HTTP, DNS, or browser requests."""
    if "initial_passed" in result and "initial_tier" in result:
        return result
    url = str(result.get("normalized_url") or "")
    host = urlsplit(url).hostname or ""
    root = registered_domain(host) if host else ""
    run_row = connection.execute(
        "SELECT * FROM subdomain_discovery_runs WHERE root_domain=?", (root,)
    ).fetchone() if root else None
    summary = summarise_subdomains(connection, root, run_row) if root else {
        "root_domain": "", "subdomain_count": 0, "subdomain_bonus": 0,
        "footprint": "small_footprint", "type_counts": {}, "source_counts": {}, "status": "not_run",
    }
    return attach_subdomain_weight(result, summary)


def build_middle_request_summary(
    connection: sqlite3.Connection, result: dict[str, Any]
) -> dict[str, Any]:
    url = str(result.get("normalized_url") or "")
    context = _official_context_for_url(connection, url)
    root = str(result.get("subdomain_root") or registered_domain(urlsplit(url).hostname or ""))
    run_row = connection.execute(
        "SELECT * FROM subdomain_discovery_runs WHERE root_domain=?", (root,)
    ).fetchone() if root else None
    summary = summarise_subdomains(connection, root, run_row) if root else {"subdomains": [], "type_counts": {}, "source_counts": {}}
    representatives = [
        {"name": item["subdomain"], "type": item["asset_type"], "sources": item["sources"]}
        for item in summary.get("subdomains", [])[:20]
    ]
    return {
        "url": url,
        "official_context": {
            "project_id": context.get("project_id", ""),
            "company_name": context.get("company_name", ""),
            "scope": context.get("scope", "include"),
            "source": context.get("source", "official_submit_page"),
            "confidence": context.get("confidence", ""),
        },
        "rule": {
            "decision": result.get("decision", "review"),
            "initial_tier": result.get("initial_tier", "review"),
            "functional_score": result.get("functional_score", 0),
            "static_score": result.get("static_score", 0),
            "complexity_score": result.get("complexity_score", 0),
            "subdomain_bonus": result.get("subdomain_bonus", 0),
            "combined_functional_score": result.get("combined_functional_score", result.get("functional_score", 0)),
            "reasons": result.get("reasons", []),
        },
        "http": {
            "root_status": result.get("root_status"),
            "root_final_url": result.get("root_final_url", ""),
            "redirect_chain": result.get("redirect_chain", []),
            "root_content_type": result.get("root_content_type", ""),
            "page_summary": result.get("page_summary", {}),
            "page_metrics": [
                {key: metric.get(key) for key in ("title", "text_excerpt", "form_count", "password_inputs", "links")}
                for metric in result.get("page_metrics", [])[:5]
            ],
            "pages_followed": result.get("pages_followed", [])[:4],
        },
        "subdomains": {
            "root_domain": root,
            "count": len(summary.get("subdomains", [])),
            "footprint": subdomain_footprint_label(len(summary.get("subdomains", []))),
            "type_counts": summary.get("type_counts", {}),
            "source_counts": summary.get("source_counts", {}),
            "representatives": representatives,
            "status": summary.get("status", "not_run"),
        },
    }


def call_deepseek_middle(request_summary: dict[str, Any], *, ai_enabled: bool) -> dict[str, Any]:
    """Call DeepSeek V4 Flash and return only validated, non-secret response data."""
    if not ai_enabled:
        return {"status": "skipped", "reason": "middle_ai_not_enabled", "model": DEEPSEEK_MIDDLE_MODEL}
    api_key = load_deepseek_api_key()
    if not api_key:
        return {"status": "failed", "reason": "deepseek_api_key_missing", "model": DEEPSEEK_MIDDLE_MODEL}
    system_prompt = (
        "You classify a website from supplied public structural metadata only. "
        "Return JSON exactly with decision(priority_keep|conditional_keep|review|drop), "
        "confidence(high|medium|low), subdomain_assessment(small|medium|broad|high_risk_scope), "
        "business_evidence(array), scope_risk(low|medium|high), contradicting_evidence(array), and reason. "
        "Do not invent endpoints or claim testing was performed."
    )
    try:
        response = requests.post(
            DEEPSEEK_CHAT_COMPLETIONS_URL,
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json={
                "model": DEEPSEEK_MIDDLE_MODEL,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": json.dumps(request_summary, ensure_ascii=False)},
                ],
                "temperature": 0,
                "thinking": {"type": "disabled"},
                "max_tokens": MIDDLE_AI_MAX_RESPONSE_CHARS,
                "response_format": {"type": "json_object"},
            },
            timeout=MIDDLE_AI_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        content = response.json()["choices"][0]["message"]["content"]
        parsed = parse_json_object(str(content))
        decision = str(parsed.get("decision", "")).lower().strip()
        # Accept legacy keep/conditional labels while persisting the strict final-tier schema.
        decision = {"keep": "priority_keep", "conditional": "conditional_keep", "pass": "conditional_keep"}.get(decision, decision)
        if decision not in {"priority_keep", "conditional_keep", "review", "drop"}:
            raise ValueError("AI decision is invalid")
        confidence = str(parsed.get("confidence", "medium")).lower()
        scope_risk = str(parsed.get("scope_risk", "medium")).lower()
        assessment = str(parsed.get("subdomain_assessment", "medium")).lower()
        return {
            "status": "ok", "decision": decision,
            "confidence": confidence if confidence in {"high", "medium", "low"} else "medium",
            "scope_risk": scope_risk if scope_risk in {"low", "medium", "high"} else "medium",
            "subdomain_assessment": assessment if assessment in {"small", "medium", "broad", "high_risk_scope"} else "medium",
            "business_evidence": [strip_text(str(item), 160) for item in parsed.get("business_evidence", []) if str(item).strip()][:12],
            "contradicting_evidence": [strip_text(str(item), 160) for item in parsed.get("contradicting_evidence", []) if str(item).strip()][:12],
            "reason": strip_text(str(parsed.get("reason", "")), 400),
            "model": DEEPSEEK_MIDDLE_MODEL,
        }
    except Exception as error:
        return {"status": "failed", "reason": strip_text(str(error), 300), "model": DEEPSEEK_MIDDLE_MODEL}


def save_middle_review(connection: sqlite3.Connection, review: dict[str, Any]) -> None:
    connection.execute(
        """
        INSERT INTO middle_reviews(normalized_url, initial_decision, initial_tier, subdomain_count, subdomain_bonus,
          ai_status, ai_decision, final_tier, confidence, scope_risk, reason, model, request_json, response_json, reviewed_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(normalized_url) DO UPDATE SET
          initial_decision=excluded.initial_decision, initial_tier=excluded.initial_tier,
          subdomain_count=excluded.subdomain_count, subdomain_bonus=excluded.subdomain_bonus,
          ai_status=excluded.ai_status, ai_decision=excluded.ai_decision, final_tier=excluded.final_tier,
          confidence=excluded.confidence, scope_risk=excluded.scope_risk, reason=excluded.reason,
          model=excluded.model, request_json=excluded.request_json, response_json=excluded.response_json,
          reviewed_at=excluded.reviewed_at
        """,
        (
            review["normalized_url"], review["initial_decision"], review["initial_tier"],
            int(review["subdomain_count"]), int(review["subdomain_bonus"]), review["ai_status"],
            review.get("ai_decision"), review["final_tier"], review["confidence"], review["scope_risk"],
            review["reason"], review.get("model", ""), json_compact(review["request_summary"]),
            json_compact(review["ai_result"]), review["reviewed_at"],
        ),
    )


def write_middle_target_artifacts(
    connection: sqlite3.Connection,
    run_dir: Path,
    result: dict[str, Any],
    review: dict[str, Any],
    context: dict[str, Any],
    batch_id: str | None,
) -> Path:
    url = str(result["normalized_url"])
    target_dir = archive_initial_target(connection, run_dir, result, context, batch_id)
    if target_dir is None:
        target_dir = run_dir / "targets" / target_id_for_url(url)
        target_dir.mkdir(parents=True, exist_ok=True)
    middle_dir = target_dir / "middle"
    write_json_atomic(middle_dir / "ai-request-summary.json", review["request_summary"])
    write_json_atomic(middle_dir / "ai-result.json", review["ai_result"])
    report = "\n".join([
        f"# 中筛报告：{url}", "", "| 字段 | 值 |", "|---|---|",
        f"| 项目 | {context.get('company_name', '')} ({context.get('project_id', '')}) |",
        f"| 初筛结论 | {review['initial_decision']} / {review['initial_tier']} |",
        f"| 子域数量 / 加分 | {review['subdomain_count']} / {review['subdomain_bonus']} |",
        f"| AI 状态 | {review['ai_status']} |",
        f"| AI 模型 | {review.get('model', '')} |",
        f"| 最终层级 | {review['final_tier']} |",
        f"| 置信度 | {review['confidence']} |",
        f"| 范围风险 | {review['scope_risk']} |",
        f"| 原因 | {review['reason']} |", "",
        "## 子域类型", "", "| 类型 | 数量 |", "|---|---:|",
        *(( [f"| {kind} | {count} |" for kind, count in sorted(review["request_summary"].get("subdomains", {}).get("type_counts", {}).items())] ) or ["| — | 0 |"]),
        "", "## AI 业务证据", "", *(([f"- {item}" for item in review["ai_result"].get("business_evidence", [])]) or ["- 未返回。"]),
        "", "## 冲突信号", "", *(([f"- {item}" for item in review["ai_result"].get("contradicting_evidence", [])]) or ["- 未返回。"]), "",
    ])
    write_text_atomic(middle_dir / "middle-report.md", report)
    _archive_manifest(connection, target_dir, url, batch_id)
    connection.commit()
    return target_dir


def middle_review_one(
    connection: sqlite3.Connection,
    run_dir: Path,
    url: str,
    args: argparse.Namespace,
    *,
    batch_id: str | None = None,
    force: bool = False,
) -> dict[str, Any]:
    row = connection.execute(
        "SELECT result_json FROM prefilter_results WHERE normalized_url=?", (url,)
    ).fetchone()
    if row is None:
        raise ValueError(f"middle: no prefilter result for {url}")
    result = _initial_fields_from_result(connection, json.loads(row["result_json"]))
    context = _official_context_for_url(connection, url)
    if not result.get("initial_passed"):
        return {
            "normalized_url": url, "initial_decision": str(result.get("decision", "review")),
            "initial_tier": str(result.get("initial_tier", "review")), "subdomain_count": int(result.get("subdomain_count", 0)),
            "subdomain_bonus": int(result.get("subdomain_bonus", 0)), "ai_status": "skipped",
            "ai_decision": None, "final_tier": "review", "confidence": "low", "scope_risk": "medium",
            "reason": "initial_screen_not_passed", "model": DEEPSEEK_MIDDLE_MODEL,
            "request_summary": {}, "ai_result": {"status": "skipped", "reason": "initial_screen_not_passed"},
            "reviewed_at": utc_now(),
        }
    previous = connection.execute(
        "SELECT * FROM middle_reviews WHERE normalized_url=?", (url,)
    ).fetchone()
    if previous is not None and not force:
        review = dict(previous)
        review["request_summary"] = json.loads(review.pop("request_json") or "{}")
        review["ai_result"] = json.loads(review.pop("response_json") or "{}")
        review["reused"] = True
        write_middle_target_artifacts(connection, run_dir, result, review, context, batch_id)
        return review
    request_summary = build_middle_request_summary(connection, result)
    ai_result = call_deepseek_middle(request_summary, ai_enabled=bool(getattr(args, "ai", False)))
    if ai_result.get("status") == "ok":
        final_tier = str(ai_result["decision"])
        confidence = str(ai_result["confidence"])
        scope_risk = str(ai_result["scope_risk"])
        reason = str(ai_result["reason"])
        ai_decision: str | None = final_tier
    else:
        final_tier = "review"
        confidence = "low"
        scope_risk = "medium"
        reason = str(ai_result.get("reason", "deepseek_unavailable"))
        ai_decision = None
    review = {
        "normalized_url": url, "initial_decision": str(result.get("decision", "review")),
        "initial_tier": str(result.get("initial_tier", "review")),
        "subdomain_count": int(result.get("subdomain_count", 0)),
        "subdomain_bonus": int(result.get("subdomain_bonus", 0)), "ai_status": str(ai_result.get("status", "failed")),
        "ai_decision": ai_decision, "final_tier": final_tier, "confidence": confidence,
        "scope_risk": scope_risk, "reason": reason, "model": str(ai_result.get("model", DEEPSEEK_MIDDLE_MODEL)),
        "request_summary": request_summary, "ai_result": ai_result, "reviewed_at": utc_now(),
    }
    save_middle_review(connection, review)
    write_middle_target_artifacts(connection, run_dir, result, review, context, batch_id)
    connection.commit()
    return review


def middle_candidate_urls(connection: sqlite3.Connection, batch_id: str | None) -> list[str]:
    if batch_id:
        candidate_rows = connection.execute(
            "SELECT DISTINCT normalized_url FROM batch_url_records WHERE batch_id=? ORDER BY normalized_url", (batch_id,)
        )
    else:
        candidate_rows = connection.execute("SELECT normalized_url FROM prefilter_results ORDER BY normalized_url")
    selected: list[str] = []
    for row in candidate_rows:
        url = str(row["normalized_url"])
        result_row = connection.execute(
            "SELECT result_json FROM prefilter_results WHERE normalized_url=?", (url,)
        ).fetchone()
        if result_row is None:
            continue
        result = _initial_fields_from_result(connection, json.loads(result_row["result_json"]))
        if result.get("initial_passed"):
            selected.append(url)
    return selected


def export_middle_wiki_artifacts(
    connection: sqlite3.Connection, batch_id: str, wiki_dir: Path, run_dir: Path
) -> dict[str, Path]:
    urls = set(middle_candidate_urls(connection, batch_id))
    rows: list[dict[str, Any]] = []
    for row in connection.execute("SELECT * FROM middle_reviews ORDER BY normalized_url"):
        data = dict(row)
        if data["normalized_url"] not in urls:
            continue
        data.pop("request_json", None)
        data.pop("response_json", None)
        rows.append(data)
    wiki_dir.mkdir(parents=True, exist_ok=True)
    csv_path = wiki_dir / f"{batch_id}-middle-results.csv"
    fields = [
        "normalized_url", "initial_decision", "initial_tier", "subdomain_count", "subdomain_bonus",
        "ai_status", "ai_decision", "final_tier", "confidence", "scope_risk", "reason", "model", "reviewed_at",
    ]
    write_csv_atomic(csv_path, fields, rows)
    target_wiki_dir = wiki_dir / "targets"
    for review in rows:
        target_id = target_id_for_url(str(review["normalized_url"]))
        target_dir = run_dir / "targets" / target_id
        target_page = target_wiki_dir / f"{target_id}.md"
        write_text_atomic(target_page, "\n".join([
            f"# {review['normalized_url']}", "", "| 字段 | 值 |", "|---|---|",
            f"| 最终层级 | {review['final_tier']} |",
            f"| AI 状态 | {review['ai_status']} |",
            f"| 子域数量 | {review['subdomain_count']} |",
            f"| 置信度 | {review['confidence']} |", "",
            f"- 初筛档案：`{target_dir / 'initial' / 'initial-report.md'}`", 
            f"- 中筛报告：`{target_dir / 'middle' / 'middle-report.md'}`", 
            f"- 子域数据：`{target_dir / 'subdomains' / 'subdomains.csv'}`", "",
        ]))
    priority = [str(row["normalized_url"]) for row in rows if row["final_tier"] == "priority_keep"]
    conditional = [str(row["normalized_url"]) for row in rows if row["final_tier"] == "conditional_keep"]
    priority_path = wiki_dir / "priority_keep_urls.txt"
    conditional_path = wiki_dir / "conditional_keep_urls.txt"
    write_text_atomic(priority_path, "".join(item + "\n" for item in priority))
    write_text_atomic(conditional_path, "".join(item + "\n" for item in conditional))
    counts = Counter(str(row["final_tier"]) for row in rows)
    report_path = wiki_dir / f"{batch_id}-middle.md"
    report = "\n".join([
        f"# 补天公益 SRC 中筛 {batch_id}", "", "| priority_keep | conditional_keep | review | drop |", "|---:|---:|---:|---:|",
        f"| {counts.get('priority_keep', 0)} | {counts.get('conditional_keep', 0)} | {counts.get('review', 0)} | {counts.get('drop', 0)} |", "",
        f"- `{csv_path.name}`：本批次初筛通过网址的 DeepSeek 中筛结果。",
        "- `targets/`：逐网址 Wiki 索引页。",
        f"- `{priority_path.name}`：计入批次目标的高优先级网址。",
        f"- `{conditional_path.name}`：不计入目标的条件保留网址。", "",
    ])
    write_text_atomic(report_path, report)
    return {"report": report_path, "results_csv": csv_path, "priority": priority_path, "conditional": conditional_path}


def command_middle(args: argparse.Namespace) -> int:
    run_dir, db_path = run_paths(args)
    wiki_dir = path_from_argument(args.wiki_dir, DEFAULT_WIKI_BATCH_DIR)
    if args.dry_run:
        log(f"DRY RUN middle: batch={args.batch_id} -> {wiki_dir}")
        return 0
    connection = open_database(db_path)
    batch = connection.execute("SELECT 1 FROM batch_runs WHERE batch_id=?", (args.batch_id,)).fetchone()
    if batch is None:
        log(f"middle: unknown batch {args.batch_id}")
        connection.close()
        return 2
    urls = middle_candidate_urls(connection, args.batch_id)
    if args.limit:
        urls = urls[:args.limit]
    processed = reused = 0
    for index, url in enumerate(urls, 1):
        previous = connection.execute("SELECT 1 FROM middle_reviews WHERE normalized_url=?", (url,)).fetchone()
        review = middle_review_one(
            connection, run_dir, url, args, batch_id=args.batch_id,
            force=bool(getattr(args, "force_middle_recheck", False)),
        )
        if previous and not bool(getattr(args, "force_middle_recheck", False)):
            reused += 1
        else:
            processed += 1
        log(f"middle {index}/{len(urls)}: {review['final_tier'].upper()} {url}")
    paths = export_middle_wiki_artifacts(connection, args.batch_id, wiki_dir, run_dir)
    connection.close()
    log(f"middle export: processed={processed} reused={reused} -> {paths['report']}")
    return 0

def command_run(args: argparse.Namespace) -> int:
    catalog_code = command_catalog(args)
    if catalog_code:
        return catalog_code
    auth_state = path_from_argument(args.auth_state, DEFAULT_AUTH_STATE)
    if not auth_state.is_file():
        log("run finished public catalog only: login_required for official target extraction")
        return 3
    extract_code = command_extract(args)
    if extract_code:
        return extract_code
    return command_prefilter(args)


def next_batch_id(connection: sqlite3.Connection) -> str:
    """Allocate a stable, readable batch identifier for output file names."""
    numbers: list[int] = []
    for row in connection.execute("SELECT batch_id FROM batch_runs"):
        match = re.fullmatch(rf"{re.escape(BATCH_FILE_PREFIX)}-(\d+)", row["batch_id"])
        if match:
            numbers.append(int(match.group(1)))
    return f"{BATCH_FILE_PREFIX}-{max(numbers, default=0) + 1:04d}"


def read_batch_cursor(connection: sqlite3.Connection) -> tuple[int | None, str]:
    row = connection.execute(
        "SELECT next_page, status FROM pipeline_cursor WHERE cursor_name=?",
        (BATCH_CURSOR_NAME,),
    ).fetchone()
    if not row:
        return 1, "active"
    if row["status"] == "exhausted":
        return None, "exhausted"
    return int(row["next_page"] or 1), str(row["status"])


def save_batch_cursor(
    connection: sqlite3.Connection,
    next_page: int | None,
    status: str,
    batch_id: str,
) -> None:
    connection.execute(
        """
        INSERT INTO pipeline_cursor(cursor_name, next_page, status, last_batch_id, updated_at)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(cursor_name) DO UPDATE SET
          next_page=excluded.next_page,
          status=excluded.status,
          last_batch_id=excluded.last_batch_id,
          updated_at=excluded.updated_at
        """,
        (BATCH_CURSOR_NAME, next_page, status, batch_id, utc_now()),
    )


def update_batch_run(
    connection: sqlite3.Connection,
    batch_id: str,
    *,
    page_end: int | None,
    keep_count: int,
    candidate_count: int,
    checked_count: int,
    reused_count: int,
    status: str,
    error: str = "",
    finished: bool = False,
) -> None:
    connection.execute(
        """
        UPDATE batch_runs
        SET page_end=?, keep_count=?, candidate_count=?, checked_count=?, reused_count=?,
            status=?, error=?, finished_at=?
        WHERE batch_id=?
        """,
        (
            page_end,
            keep_count,
            candidate_count,
            checked_count,
            reused_count,
            status,
            error[:500] or None,
            utc_now() if finished else None,
            batch_id,
        ),
    )


def save_batch_project_records(
    connection: sqlite3.Connection,
    batch_id: str,
    projects: list[sqlite3.Row],
    extraction_rows: dict[str, sqlite3.Row],
) -> None:
    timestamp = utc_now()
    for project in projects:
        result = extraction_rows.get(str(project["project_id"]))
        connection.execute(
            """
            INSERT OR REPLACE INTO batch_project_records(
              batch_id, page_number, item_index, project_id, company_name,
              extraction_status, asset_count, message, recorded_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                batch_id,
                int(project["page_number"]),
                int(project["item_index"]),
                str(project["project_id"]),
                str(project["company_name"]),
                str(result["status"]) if result else "not_attempted",
                int(result["asset_count"]) if result else 0,
                str(result["message"] or "") if result else "missing extraction result",
                timestamp,
            ),
        )


def save_batch_url_record(
    connection: sqlite3.Connection,
    batch_id: str,
    occurrence: dict[str, Any],
    result: dict[str, Any],
    action: str,
) -> None:
    connection.execute(
        """
        INSERT OR REPLACE INTO batch_url_records(
          batch_id, normalized_url, project_id, company_name, page_number, item_index,
          scope, source, confidence, decision, action, reasons_json, recorded_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            batch_id,
            occurrence["normalized_url"],
            occurrence["project_id"],
            occurrence["company_name"],
            occurrence["page_number"],
            occurrence["item_index"],
            occurrence["scope"],
            occurrence["source"],
            occurrence["confidence"],
            str(result.get("decision", "review")),
            action,
            json_compact(result.get("reasons", [])),
            utc_now(),
        ),
    )


def upsert_url_registry(
    connection: sqlite3.Connection,
    batch_id: str,
    occurrence: dict[str, Any],
    result: dict[str, Any],
    action: str,
    had_prefilter_result: bool,
) -> None:
    """Maintain a single comparison row per URL without retaining session material."""
    url = occurrence["normalized_url"]
    current = connection.execute(
        "SELECT * FROM url_registry WHERE normalized_url=?", (url,)
    ).fetchone()
    checked_now = action in {"checked", "force_recheck"}
    analyzed_at = str(result.get("analyzed_at") or utc_now())
    reasons = json_compact(result.get("reasons", []))
    values = {
        "decision": str(result.get("decision", "review")),
        "functional_score": int(result.get("functional_score", 0)),
        "static_score": int(result.get("static_score", 0)),
        "complexity_score": int(result.get("complexity_score", 0)),
    }
    if current is None:
        inferred_previous_check = had_prefilter_result and not checked_now
        connection.execute(
            """
            INSERT INTO url_registry(
              normalized_url, first_batch_id, first_page_number, first_project_id,
              first_company_name, first_seen_at, last_batch_id, last_page_number,
              last_project_id, last_company_name, last_seen_at, decision,
              functional_score, static_score, complexity_score, reasons_json,
              first_checked_at, last_checked_at, check_count, reuse_count,
              force_recheck_count, source
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                url,
                batch_id,
                occurrence["page_number"],
                occurrence["project_id"],
                occurrence["company_name"],
                utc_now(),
                batch_id,
                occurrence["page_number"],
                occurrence["project_id"],
                occurrence["company_name"],
                utc_now(),
                values["decision"],
                values["functional_score"],
                values["static_score"],
                values["complexity_score"],
                reasons,
                analyzed_at if (checked_now or inferred_previous_check) else None,
                analyzed_at if (checked_now or inferred_previous_check) else None,
                1 if (checked_now or inferred_previous_check) else 0,
                1 if action == "reused" else 0,
                1 if action == "force_recheck" else 0,
                occurrence["source"],
            ),
        )
        return
    connection.execute(
        """
        UPDATE url_registry
        SET last_batch_id=?, last_page_number=?, last_project_id=?,
            last_company_name=?, last_seen_at=?, decision=?, functional_score=?,
            static_score=?, complexity_score=?, reasons_json=?,
            last_checked_at=CASE WHEN ? THEN ? ELSE last_checked_at END,
            check_count=check_count + ?, reuse_count=reuse_count + ?,
            force_recheck_count=force_recheck_count + ?, source=?
        WHERE normalized_url=?
        """,
        (
            batch_id,
            occurrence["page_number"],
            occurrence["project_id"],
            occurrence["company_name"],
            utc_now(),
            values["decision"],
            values["functional_score"],
            values["static_score"],
            values["complexity_score"],
            reasons,
            1 if checked_now else 0,
            analyzed_at,
            1 if checked_now else 0,
            1 if action == "reused" else 0,
            1 if action == "force_recheck" else 0,
            occurrence["source"],
            url,
        ),
    )


def batch_asset_occurrences(
    connection: sqlite3.Connection, projects: list[sqlite3.Row]
) -> tuple[dict[str, list[dict[str, Any]]], list[dict[str, Any]]]:
    """Return in-scope candidate occurrences and separately recorded exclusions."""
    first_mapping: dict[str, sqlite3.Row] = {}
    for project in projects:
        first_mapping.setdefault(str(project["project_id"]), project)
    project_ids = list(first_mapping)
    if not project_ids:
        return {}, []
    placeholders = ",".join("?" for _ in project_ids)
    assets = list(
        connection.execute(
            "SELECT * FROM official_assets WHERE project_id IN (" + placeholders + ") "
            "ORDER BY project_id, normalized_url, scope",
            project_ids,
        )
    )
    candidates: dict[str, list[dict[str, Any]]] = {}
    exclusions: list[dict[str, Any]] = []
    for asset in assets:
        mapping = first_mapping.get(str(asset["project_id"]))
        if mapping is None:
            continue
        occurrence = {
            "normalized_url": str(asset["normalized_url"]),
            "project_id": str(asset["project_id"]),
            "company_name": str(mapping["company_name"]),
            "page_number": int(mapping["page_number"]),
            "item_index": int(mapping["item_index"]),
            "scope": str(asset["scope"]),
            "source": str(asset["source"]),
            "confidence": str(asset["confidence"]),
        }
        if occurrence["scope"] == "include" and occurrence["source"] == "official_submit_page":
            candidates.setdefault(occurrence["normalized_url"], []).append(occurrence)
        else:
            exclusions.append(occurrence)
    ordered = dict(
        sorted(
            candidates.items(),
            key=lambda item: (
                item[1][0]["page_number"],
                item[1][0]["item_index"],
                item[0],
            ),
        )
    )
    return ordered, exclusions


def batch_result_rows(connection: sqlite3.Connection, batch_id: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for row in connection.execute(
        """
        SELECT * FROM batch_url_records WHERE batch_id=?
        ORDER BY page_number, item_index, normalized_url, scope
        """,
        (batch_id,),
    ):
        data = dict(row)
        data["reasons"] = ";".join(json.loads(data.pop("reasons_json") or "[]"))
        rows.append(data)
    return rows


def export_batch_wiki_artifacts(
    connection: sqlite3.Connection,
    batch_id: str,
    wiki_dir: Path,
    run_dir: Path,
) -> dict[str, Path]:
    """Write batch tables and a concise Obsidian report without authentication data."""
    batch = connection.execute(
        "SELECT * FROM batch_runs WHERE batch_id=?", (batch_id,)
    ).fetchone()
    if batch is None:
        raise ValueError(f"unknown batch: {batch_id}")
    batch_data = dict(batch)
    result_rows = batch_result_rows(connection, batch_id)
    for data in result_rows:
        prefilter = connection.execute(
            "SELECT result_json FROM prefilter_results WHERE normalized_url=?", (data["normalized_url"],)
        ).fetchone()
        if prefilter:
            details = _initial_fields_from_result(connection, json.loads(prefilter["result_json"]))
            data.update({
                "initial_tier": details.get("initial_tier", ""),
                "subdomain_count": details.get("subdomain_count", 0),
                "subdomain_bonus": details.get("subdomain_bonus", 0),
                "subdomain_footprint": details.get("subdomain_footprint", ""),
            })
        middle = connection.execute(
            "SELECT ai_status, final_tier, confidence, scope_risk FROM middle_reviews WHERE normalized_url=?",
            (data["normalized_url"],),
        ).fetchone()
        if middle:
            data.update(dict(middle))
        else:
            data.update({"ai_status": "", "final_tier": "", "confidence": "", "scope_risk": ""})
    project_rows = [
        dict(row)
        for row in connection.execute(
            """
            SELECT * FROM batch_project_records WHERE batch_id=?
            ORDER BY page_number, item_index
            """,
            (batch_id,),
        )
    ]
    registry_rows = []
    for row in connection.execute("SELECT * FROM url_registry ORDER BY normalized_url"):
        data = dict(row)
        data["reasons"] = ";".join(json.loads(data.pop("reasons_json") or "[]"))
        prefilter = connection.execute(
            "SELECT result_json FROM prefilter_results WHERE normalized_url=?", (data["normalized_url"],)
        ).fetchone()
        if prefilter:
            details = _initial_fields_from_result(connection, json.loads(prefilter["result_json"]))
            data.update({
                "initial_tier": details.get("initial_tier", ""),
                "subdomain_count": details.get("subdomain_count", 0),
                "subdomain_bonus": details.get("subdomain_bonus", 0),
                "subdomain_footprint": details.get("subdomain_footprint", ""),
            })
        middle = connection.execute(
            "SELECT ai_status, final_tier, confidence, scope_risk FROM middle_reviews WHERE normalized_url=?",
            (data["normalized_url"],),
        ).fetchone()
        data.update(dict(middle) if middle else {"ai_status": "", "final_tier": "", "confidence": "", "scope_risk": ""})
        registry_rows.append(data)

    wiki_dir.mkdir(parents=True, exist_ok=True)
    result_csv = wiki_dir / f"{batch_id}-results.csv"
    project_csv = wiki_dir / f"{batch_id}-projects.csv"
    registry_csv = wiki_dir / "url-registry.csv"
    result_fields = [
        "batch_id", "page_number", "item_index", "project_id", "company_name",
        "normalized_url", "scope", "source", "confidence", "decision", "action",
        "initial_tier", "subdomain_count", "subdomain_bonus", "subdomain_footprint",
        "ai_status", "final_tier", "confidence", "scope_risk", "reasons", "recorded_at",
    ]
    project_fields = [
        "batch_id", "page_number", "item_index", "project_id", "company_name",
        "extraction_status", "asset_count", "message", "recorded_at",
    ]
    registry_fields = [
        "normalized_url", "first_batch_id", "first_page_number", "first_project_id",
        "first_company_name", "first_seen_at", "last_batch_id", "last_page_number",
        "last_project_id", "last_company_name", "last_seen_at", "decision",
        "functional_score", "static_score", "complexity_score", "initial_tier",
        "subdomain_count", "subdomain_bonus", "subdomain_footprint", "ai_status",
        "final_tier", "confidence", "scope_risk", "reasons", "first_checked_at",
        "last_checked_at", "check_count", "reuse_count", "force_recheck_count", "source",
    ]
    write_csv_atomic(result_csv, result_fields, result_rows)
    write_csv_atomic(project_csv, project_fields, project_rows)
    write_csv_atomic(registry_csv, registry_fields, registry_rows)

    decision_counts = Counter(str(row["decision"]) for row in result_rows)
    kept = [row for row in result_rows if row["decision"] in {"keep", "priority_keep"}]
    short_rows = kept[:100]
    keep_table = ["| URL | 项目 | 页码 | 结论 |", "|---|---|---:|---|"]
    for row in short_rows:
        keep_table.append(
            f"| {row['normalized_url']} | {row['company_name']} | {row['page_number']} | {row['decision']} |"
        )
    if not short_rows:
        keep_table.append("| — | — | — | 本批次无 keep URL |")
    report_path = wiki_dir / f"{batch_id}.md"
    report = "\n".join(
        [
            f"# 补天公益 SRC 初筛 {batch_id}",
            "",
            "## 批次范围",
            "",
            "| 字段 | 值 |",
            "|---|---|",
            f"| 状态 | {batch_data['status']} |",
            f"| 目录页 | {batch_data['page_start']}–{batch_data['page_end'] or '未完成'} |",
            f"| keep 目标 / 实际 | {batch_data['target_keep']} / {batch_data['keep_count']} |",
            f"| 新检测 / 历史复用 | {batch_data['checked_count']} / {batch_data['reused_count']} |",
            f"| 候选 URL | {batch_data['candidate_count']} |",
            f"| 运行时间 | {batch_data['started_at']} – {batch_data['finished_at'] or '进行中'} |",
            "",
            "## 初筛结论",
            "",
            "| priority_keep | conditional_keep | keep | review | drop | 排除范围 |",
            "|---:|---:|---:|---:|---:|---:|",
            f"| {decision_counts.get('priority_keep', 0)} | {decision_counts.get('conditional_keep', 0)} | {decision_counts.get('keep', 0)} | {decision_counts.get('review', 0)} | {decision_counts.get('drop', 0)} | {decision_counts.get('excluded_scope', 0)} |",
            "",
            "## 保留网址",
            "",
            *keep_table,
            "",
            "## 数据文件",
            "",
            f"- `{result_csv.name}`：本批次所有 URL（含 keep/review/drop/reused/excluded）。",
            f"- `{project_csv.name}`：全部目录项目的资产提取状态。",
            "- `url-registry.csv`：跨批次 URL 历史比对表；已判定 URL 后续默认复用。",
            f"- `{batch_id}-middle.md`：DeepSeek 中筛及逐网址报告索引（启用中筛时生成）。",
            f"- 运行 manifest：`{run_dir / 'batches' / (batch_id + '-manifest.json')}`。",
            "",
        ]
    )
    write_text_atomic(report_path, report)

    cursor = connection.execute(
        "SELECT next_page, status FROM pipeline_cursor WHERE cursor_name=?",
        (BATCH_CURSOR_NAME,),
    ).fetchone()
    history = [
        dict(row)
        for row in connection.execute(
            "SELECT batch_id, page_start, page_end, keep_count, status, finished_at FROM batch_runs ORDER BY started_at DESC LIMIT 50"
        )
    ]
    hub_path = wiki_dir.parent / "butian-welfare-src-prefilter.md"
    history_lines = ["| 批次 | 目录页 | keep | 状态 | 完成时间 |", "|---|---|---:|---|---|"]
    for row in history:
        history_lines.append(
            f"| [[projects/butian-welfare-src-prefilter/{row['batch_id']}|{row['batch_id']}]] | "
            f"{row['page_start']}–{row['page_end'] or '未完成'} | {row['keep_count']} | "
            f"{row['status']} | {row['finished_at'] or ''} |"
        )
    next_page = cursor["next_page"] if cursor and cursor["status"] != "exhausted" else "目录已结束"
    hub = "\n".join(
        [
            "# 补天公益 SRC 批量初筛", "",
            "## 当前进度", "",
            "| 项目 | 值 |", "|---|---|",
            f"| 下一目录页 | {next_page} |",
            f"| 游标状态 | {cursor['status'] if cursor else '未初始化'} |",
            f"| 全局 URL 记录数 | {len(registry_rows)} |",
            "", "## 批次历史", "", *history_lines, "",
            "`url-registry.csv` 是跨批次的快速比对表；review、drop 和排除范围均保留，默认不重复联网检测。", "",
        ]
    )
    write_text_atomic(hub_path, hub)
    wiki_index = wiki_dir.parent.parent / "index.md"
    if wiki_index.is_file():
        index = wiki_index.read_text(encoding="utf-8")
        link = "[[projects/butian-welfare-src-prefilter|补天公益 SRC 批量初筛]]"
        if link not in index:
            write_text_atomic(
                wiki_index,
                index.rstrip() + "\n\n## 自动生成项目\n\n"
                + f"| {link} | 连续目录页初筛、URL 历史登记与批次归档 | src, butian, prefilter |\n",
            )
    manifest_path = run_dir / "batches" / f"{batch_id}-manifest.json"
    write_json_atomic(
        manifest_path,
        {
            "batch": batch_data,
            "result_counts": dict(decision_counts),
            "project_count": len(project_rows),
            "result_count": len(result_rows),
            "wiki": {
                "directory": str(wiki_dir),
                "report": str(report_path),
                "results_csv": str(result_csv),
                "projects_csv": str(project_csv),
                "registry_csv": str(registry_csv),
                "hub": str(hub_path),
            },
        },
    )
    return {
        "report": report_path,
        "results_csv": result_csv,
        "projects_csv": project_csv,
        "registry_csv": registry_csv,
        "manifest": manifest_path,
    }


def make_batch_catalog_args(
    args: argparse.Namespace, run_dir: Path, db_path: Path, page_start: int, page_end: int
) -> argparse.Namespace:
    return argparse.Namespace(
        run_dir=str(run_dir), db=str(db_path), timeout=args.timeout,
        min_interval=args.min_interval, resume=True, dry_run=False,
        start_page=page_start, page_limit=page_end,
    )


def make_batch_extract_args(
    args: argparse.Namespace, run_dir: Path, db_path: Path, project_ids: list[str]
) -> argparse.Namespace:
    return argparse.Namespace(
        run_dir=str(run_dir), db=str(db_path), timeout=args.timeout,
        min_interval=args.min_interval, resume=True, dry_run=False,
        auth_state=args.auth_state, browser_path=args.browser_path,
        browser_timeout=args.browser_timeout, xauthority=args.xauthority,
        project_id=project_ids, limit=None, headful=args.headful, display=args.display,
    )


def command_batch(args: argparse.Namespace) -> int:
    """Process sequential catalog-page blocks until the new keep-URL target is met."""
    run_dir, db_path = run_paths(args)
    wiki_dir = path_from_argument(args.wiki_dir, DEFAULT_WIKI_BATCH_DIR)
    target_keep = max(1, int(args.target_kept))
    page_span = max(1, int(args.page_span))
    if args.dry_run:
        log(
            "DRY RUN batch: public pages -> authenticated official assets -> prefilter "
            f"until {target_keep} keep URLs; page span={page_span}; wiki={wiki_dir}"
        )
        return 0
    auth_state = path_from_argument(args.auth_state, DEFAULT_AUTH_STATE)
    if not auth_state.is_file():
        log(f"login_required: no authenticated state at {auth_state}; run login first")
        return 3

    connection: sqlite3.Connection | None = open_database(db_path)
    cursor_page, cursor_status = read_batch_cursor(connection)
    if args.start_page is not None:
        page = max(1, int(args.start_page))
    elif cursor_status == "exhausted" or cursor_page is None:
        log("batch: catalog cursor is exhausted; pass --start-page N to explicitly revisit pages")
        connection.close()
        return 0
    else:
        page = cursor_page
    # --resume-batch continues an interrupted partial page block without repeating
    # completed checks; target_keep may be lowered for the active batch.
    resumed_batch = str(getattr(args, "resume_batch", "") or "").strip()
    configuration = {
        "target_keep": target_keep,
        "page_span": page_span,
        "max_shallow_links": args.max_shallow_links,
        "prefilter_workers": prefilter_worker_count(args),
        "min_request_interval": args.min_interval,
        "ai_enabled": bool(args.ai),
        "force_recheck": bool(args.force_recheck),
        "subdomain_discovery": bool(getattr(args, "subdomain_discovery", False)),
        "subdomain_wordlist": str(getattr(args, "subdomain_wordlist", SUBDOMAIN_WORDLIST)),
        "middle_ai": bool(getattr(args, "middle_ai", False)),
        "force_middle_recheck": bool(getattr(args, "force_middle_recheck", False)),
    }
    if resumed_batch:
        active = connection.execute("SELECT * FROM batch_runs WHERE batch_id=?", (resumed_batch,)).fetchone()
        if active is None:
            log(f"batch: unknown resume batch: {resumed_batch}")
            connection.close()
            return 2
        batch_id = resumed_batch
        page = int(active["page_end"] or active["page_start"] or page) + 1
        connection.execute("UPDATE batch_runs SET target_keep=?, status='running', finished_at=NULL, error='', configuration_json=? WHERE batch_id=?", (target_keep, json_compact(configuration), batch_id))
        counted_decision = "priority_keep" if bool(getattr(args, "middle_ai", False)) else "keep"
        keep_count = int(connection.execute("SELECT COUNT(DISTINCT normalized_url) FROM batch_url_records WHERE batch_id=? AND decision=?", (batch_id, counted_decision)).fetchone()[0])
        candidate_count = int(connection.execute("SELECT COUNT(DISTINCT normalized_url) FROM batch_url_records WHERE batch_id=? AND action!='excluded'", (batch_id,)).fetchone()[0])
        checked_count = int(connection.execute("SELECT COUNT(DISTINCT normalized_url) FROM batch_url_records WHERE batch_id=? AND action IN ('checked','force_recheck')", (batch_id,)).fetchone()[0])
        reused_count = int(connection.execute("SELECT COUNT(DISTINCT normalized_url) FROM batch_url_records WHERE batch_id=? AND action='reused'", (batch_id,)).fetchone()[0])
    else:
        batch_id = next_batch_id(connection)
        connection.execute("""INSERT INTO batch_runs(batch_id, page_start, page_end, target_keep, status, started_at, configuration_json, wiki_directory) VALUES (?, ?, NULL, ?, 'running', ?, ?, ?)""", (batch_id, page, target_keep, utc_now(), json_compact(configuration), str(wiki_dir)))
        keep_count = candidate_count = checked_count = reused_count = 0
    connection.commit()

    last_completed_page = page - 1
    terminal_status = "completed"
    error_message = ""
    exit_code = 0
    try:
        while True:
            known_page_count = catalog_declared_page_count(connection)
            if known_page_count is not None and page > known_page_count:
                terminal_status = "exhausted"
                break
            chunk_end = page + page_span - 1
            if known_page_count is not None:
                chunk_end = min(chunk_end, known_page_count)
            connection.close()
            connection = None
            catalog_code = command_catalog(
                make_batch_catalog_args(args, run_dir, db_path, page, chunk_end)
            )
            connection = open_database(db_path)
            if catalog_code:
                terminal_status, error_message, exit_code = (
                    "interrupted", "catalog page acquisition failed", catalog_code
                )
                break
            page_count = catalog_declared_page_count(connection)
            if page_count is None:
                terminal_status, error_message, exit_code = (
                    "interrupted", "catalog did not report a page count", 2
                )
                break
            if page > page_count:
                terminal_status = "exhausted"
                break
            chunk_end = min(chunk_end, page_count)
            projects = catalog_projects_for_pages(connection, page, chunk_end)
            page_rows = list(
                connection.execute(
                    "SELECT page_number, item_count, status FROM catalog_pages "
                    "WHERE page_number BETWEEN ? AND ? ORDER BY page_number",
                    (page, chunk_end),
                )
            )
            expected_page_count = chunk_end - page + 1
            mappings_complete = (
                len(page_rows) == expected_page_count
                and all(
                    row["status"] == "ok"
                    and catalog_page_mapping_complete(
                        connection, int(row["page_number"]), int(row["item_count"])
                    )
                    for row in page_rows
                )
            )
            expected_items = sum(int(row["item_count"]) for row in page_rows)
            if not mappings_complete or len(projects) != expected_items:
                terminal_status, error_message, exit_code = (
                    "interrupted", "catalog page mapping is incomplete", 2
                )
                break
            project_ids = list(dict.fromkeys(str(row["project_id"]) for row in projects))
            connection.close()
            connection = None
            extract_code = command_extract(
                make_batch_extract_args(args, run_dir, db_path, project_ids)
            )
            connection = open_database(db_path)
            result_rows = {
                str(row["project_id"]): row
                for row in connection.execute(
                    "SELECT * FROM extraction_results WHERE project_id IN ("
                    + ",".join("?" for _ in project_ids) + ")",
                    project_ids,
                )
            } if project_ids else {}
            save_batch_project_records(connection, batch_id, projects, result_rows)
            invalid_statuses: dict[str, str] = {}
            for project in projects:
                project_id = str(project["project_id"])
                result = result_rows.get(project_id)
                status = str(result["status"]) if result else "not_attempted"
                if status in {"failed", "login_required", "not_attempted"}:
                    invalid_statuses[project_id] = status
            connection.commit()
            if extract_code or invalid_statuses:
                status_text = ", ".join(
                    f"{project_id}:{status}" for project_id, status in list(invalid_statuses.items())[:8]
                )
                terminal_status = "interrupted"
                error_message = status_text or "authenticated extraction failed"
                exit_code = 3 if extract_code == 3 or "login_required" in status_text else 2
                break

            candidates, exclusions = batch_asset_occurrences(connection, projects)
            for occurrence in exclusions:
                save_batch_url_record(
                    connection,
                    batch_id,
                    occurrence,
                    {"decision": "excluded_scope", "reasons": ["official_scope_excluded"]},
                    "excluded",
                )
            session = make_http_session()
            limiter = RateLimiter(args.min_interval)
            # Queue only URLs that require a new homepage/shallow-link probe.  The
            # results are committed below by one main thread, preserving SQLite and
            # per-target artifact consistency while slow websites overlap.
            probe_records: list[dict[str, Any]] = []
            for url, occurrences in candidates.items():
                previous = connection.execute(
                    "SELECT 1 FROM prefilter_results WHERE normalized_url=?", (url,)
                ).fetchone()
                if previous is None or args.force_recheck:
                    first = occurrences[0]
                    probe_records.append(
                        {"url": url, "source": first["source"], "project_id": first["project_id"]}
                    )
            checked_results: dict[str, dict[str, Any]] = {}
            for probe_index, (probe_record, probe_result) in enumerate(
                iter_prefilter_network_results(args, probe_records, limiter), 1
            ):
                checked_results[str(probe_record["url"])] = probe_result
                log(
                    f"batch {batch_id}: prepared web probe {probe_index}/{len(probe_records)} "
                    f"{probe_record['url']}"
                )
            for url, occurrences in candidates.items():
                first = occurrences[0]
                previous = connection.execute(
                    "SELECT result_json FROM prefilter_results WHERE normalized_url=?", (url,)
                ).fetchone()
                had_previous = previous is not None
                if previous is not None and not args.force_recheck:
                    result = json.loads(previous["result_json"])
                    action = "reused"
                    reused_count += 1
                else:
                    result = checked_results.pop(url)
                    action = "force_recheck" if previous is not None else "checked"
                    checked_count += 1
                result["source"] = first["source"]
                result["project_id"] = first["project_id"]
                result, _summary = enrich_prefilter_result(
                    connection, run_dir, args, result, session, limiter
                )
                save_prefilter_result(connection, result)
                archive_initial_target(connection, run_dir, result, first, batch_id)
                candidate_count += 1
                batch_result = result
                if bool(getattr(args, "middle_ai", False)) and result.get("initial_passed"):
                    had_middle = connection.execute(
                        "SELECT 1 FROM middle_reviews WHERE normalized_url=?", (url,)
                    ).fetchone() is not None
                    middle_args = argparse.Namespace(**vars(args))
                    middle_args.ai = True
                    middle = middle_review_one(
                        connection, run_dir, url, middle_args, batch_id=batch_id,
                        force=bool(getattr(args, "force_middle_recheck", False)),
                    )
                    batch_result = dict(result)
                    batch_result["decision"] = middle["final_tier"]
                    batch_result["reasons"] = list(result.get("reasons", [])) + [
                        f"middle_{middle['final_tier']}", f"middle_ai_{middle['ai_status']}"
                    ]
                    if middle["final_tier"] == "priority_keep" and not had_middle:
                        keep_count += 1
                elif result.get("decision") == "keep" and not had_previous:
                    keep_count += 1
                upsert_url_registry(
                    connection, batch_id, first, result, action, had_previous
                )
                for occurrence_index, occurrence in enumerate(occurrences):
                    save_batch_url_record(
                        connection,
                        batch_id,
                        occurrence,
                        batch_result,
                        action if occurrence_index == 0 else "duplicate_in_batch",
                    )
                connection.commit()
                if resumed_batch and keep_count >= target_keep:
                    # A manually resumed run may stop inside its partial page block.
                    terminal_status = "completed"
                    break
            if resumed_batch and terminal_status == "completed":
                break
            last_completed_page = chunk_end
            update_batch_run(
                connection, batch_id, page_end=last_completed_page,
                keep_count=keep_count, candidate_count=candidate_count,
                checked_count=checked_count, reused_count=reused_count, status="running",
            )
            connection.commit()
            page = chunk_end + 1
            if keep_count >= target_keep:
                terminal_status = "completed"
                break
            if page > page_count:
                terminal_status = "exhausted"
                break
    except Exception as error:
        terminal_status, error_message, exit_code = "interrupted", str(error), 2
    finally:
        if connection is None:
            connection = open_database(db_path)
        if connection:
            if terminal_status in {"completed", "exhausted"}:
                declared_count = catalog_declared_page_count(connection)
                cursor_state = "exhausted" if (
                    terminal_status == "exhausted" or (declared_count is not None and page > declared_count)
                ) else "active"
                save_batch_cursor(
                    connection, None if cursor_state == "exhausted" else page,
                    cursor_state, batch_id,
                )
            update_batch_run(
                connection, batch_id, page_end=last_completed_page if last_completed_page >= int(args.start_page or cursor_page or 1) else None,
                keep_count=keep_count, candidate_count=candidate_count,
                checked_count=checked_count, reused_count=reused_count, status=terminal_status,
                error=error_message, finished=True,
            )
            connection.commit()
            paths = export_batch_wiki_artifacts(connection, batch_id, wiki_dir, run_dir)
            if bool(getattr(args, "middle_ai", False)):
                export_middle_wiki_artifacts(connection, batch_id, wiki_dir, run_dir)
            connection.close()
            log(
                f"batch {batch_id}: {terminal_status}; pages={int(args.start_page or cursor_page or 1)}-"
                f"{last_completed_page if last_completed_page >= int(args.start_page or cursor_page or 1) else 'none'}; "
                f"new_keep={keep_count}; wiki={paths['report']}"
            )
    return exit_code


def add_common_runtime_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--run-dir",
        help=f"generated output directory (default: {DEFAULT_RUN_DIR})",
    )
    parser.add_argument(
        "--db", help="SQLite checkpoint path; defaults to RUN_DIR/state.sqlite"
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=REQUEST_TIMEOUT_SECONDS,
        help="GET timeout in seconds",
    )
    parser.add_argument(
        "--min-interval",
        type=float,
        default=MIN_REQUEST_INTERVAL_SECONDS,
        help="minimum seconds between outbound GETs",
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help="skip successfully checkpointed records",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="show the action without making requests or writing output",
    )



def add_subdomain_arguments(parser: argparse.ArgumentParser) -> None:
    """Add DNS-only discovery options shared by initial-screening commands."""
    parser.add_argument(
        "--subdomain-discovery", action=argparse.BooleanOptionalAction,
        default=SUBDOMAIN_DISCOVERY_ENABLED,
        help="collect certificate-transparency and Nmap DNS-only subdomain evidence",
    )
    parser.add_argument(
        "--force-subdomain-refresh", action="store_true",
        help="ignore the 30-day root-domain discovery cache",
    )
    parser.add_argument(
        "--subdomain-wordlist", default=str(SUBDOMAIN_WORDLIST),
        help=f"Nmap dns-brute wordlist (default: {SUBDOMAIN_WORDLIST})",
    )
    parser.add_argument(
        "--nmap-path", default=SUBDOMAIN_NMAP_PATH,
        help=f"Nmap executable for DNS-only discovery (default: {SUBDOMAIN_NMAP_PATH})",
    )
    parser.add_argument(
        "--subdomain-nmap-threads", type=int, default=SUBDOMAIN_NMAP_THREADS,
        help=f"Nmap dns-brute DNS worker count (default: {SUBDOMAIN_NMAP_THREADS})",
    )
    parser.add_argument(
        "--subdomain-nmap-timeout", type=int, default=SUBDOMAIN_NMAP_TIMEOUT_SECONDS,
        help=f"maximum seconds for one DNS-only Nmap root run (default: {SUBDOMAIN_NMAP_TIMEOUT_SECONDS})",
    )

def add_auth_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--auth-state",
        help=f"private Playwright storage state (default: {DEFAULT_AUTH_STATE})",
    )
    parser.add_argument(
        "--browser-path",
        default=DEFAULT_BROWSER_PATH,
        help="Chromium executable used by Playwright",
    )
    parser.add_argument(
        "--browser-timeout",
        type=int,
        default=60,
        help="browser navigation timeout in seconds",
    )
    parser.add_argument(
        "--xauthority",
        default=DEFAULT_XAUTHORITY,
        help=f"X11 cookie file for a headed VNC browser (default: {DEFAULT_XAUTHORITY})",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    catalog = subparsers.add_parser("catalog", help="download the public project directory")
    add_common_runtime_arguments(catalog)
    catalog.add_argument("--start-page", type=int, default=1, help="first public catalog page")
    catalog.add_argument(
        "--page-limit",
        type=int,
        default=CATALOG_PAGE_HARD_LIMIT,
        help="maximum catalog pages to fetch",
    )
    catalog.set_defaults(handler=command_catalog)

    login = subparsers.add_parser(
        "login", help="create a private authenticated state through VNC"
    )
    login.add_argument(
        "--dry-run", action="store_true", help="show browser state locations only"
    )
    add_auth_arguments(login)
    login.add_argument(
        "--profile-dir",
        help=f"dedicated Chromium profile (default: {DEFAULT_BROWSER_PROFILE})",
    )
    login.add_argument(
        "--display",
        default=DEFAULT_VNC_DISPLAY,
        help="VNC X display for interactive SSO",
    )
    login.add_argument(
        "--verify-project-id",
        default="65453",
        help="project used to verify the post-login submit page",
    )
    login.set_defaults(handler=command_login)

    extract = subparsers.add_parser(
        "extract", help="extract official asset scope from authenticated submit pages"
    )
    add_common_runtime_arguments(extract)
    add_auth_arguments(extract)
    extract.add_argument(
        "--project-id",
        action="append",
        help="restrict to one or more catalog project IDs",
    )
    extract.add_argument("--limit", type=int, help="maximum catalog projects to extract")
    extract.add_argument(
        "--headful",
        action="store_true",
        help="show pages on the configured display while extracting",
    )
    extract.add_argument(
        "--display",
        default=DEFAULT_VNC_DISPLAY,
        help="VNC X display when --headful is used",
    )
    extract.set_defaults(handler=command_extract)

    prefilter = subparsers.add_parser(
        "prefilter", help="classify only confirmed official include-scope URLs"
    )
    add_common_runtime_arguments(prefilter)
    prefilter.add_argument(
        "--input",
        help="official asset JSON/JSONL file; omit to use the SQLite extraction records",
    )
    prefilter.add_argument(
        "--input-source",
        help="required as official_submit_page when importing plain URL text",
    )
    prefilter.add_argument("--limit", type=int, help="maximum URLs to classify")
    prefilter.add_argument(
        "--max-shallow-links",
        type=int,
        default=MAX_SHALLOW_LINKS,
        help="same-site explicit links fetched after the homepage",
    )
    prefilter.add_argument(
        "--prefilter-workers",
        type=int,
        default=PREFILTER_WORKERS,
        help=f"concurrent homepage/shallow-link probe workers (default: {PREFILTER_WORKERS}; max: 8)",
    )
    prefilter.add_argument(
        "--prefilter-http-attempts",
        type=int,
        default=PREFILTER_HTTP_MAX_ATTEMPTS,
        help=f"attempts per homepage/shallow-link GET (default: {PREFILTER_HTTP_MAX_ATTEMPTS}; max: {MAX_RETRIES})",
    )
    prefilter.add_argument(
        "--stop-after-keeps",
        type=int,
        default=0,
        help="stop this input run after this many newly classified keep URLs; 0 processes all",
    )
    prefilter.add_argument(
        "--ai",
        action="store_true",
        help="enable optional OpenAI-compatible boundary review",
    )
    add_subdomain_arguments(prefilter)
    prefilter.set_defaults(handler=command_prefilter)

    middle = subparsers.add_parser(
        "middle", help="DeepSeek-assisted middle screening for initial-pass URLs"
    )
    add_common_runtime_arguments(middle)
    middle.add_argument("--batch-id", required=True, help="completed or active batch ID to review")
    middle.add_argument(
        "--wiki-dir", help=f"Wiki archive directory (default: {DEFAULT_WIKI_BATCH_DIR})"
    )
    middle.add_argument("--limit", type=int, help="maximum initial-pass URLs to review")
    middle.add_argument("--ai", action="store_true", help="call DeepSeek V4 Flash for final tiering")
    middle.add_argument(
        "--force-middle-recheck", action="store_true",
        help="call DeepSeek again even when a middle-review result is cached",
    )
    middle.set_defaults(handler=command_middle)

    run = subparsers.add_parser(
        "run", help="catalog, extract when authenticated, then prefilter"
    )
    add_common_runtime_arguments(run)
    add_auth_arguments(run)
    run.add_argument("--start-page", type=int, default=1, help="first public catalog page")
    run.add_argument(
        "--page-limit",
        type=int,
        default=CATALOG_PAGE_HARD_LIMIT,
        help="maximum catalog pages to fetch",
    )
    run.add_argument(
        "--project-id",
        action="append",
        help="restrict extract to one or more catalog project IDs",
    )
    run.add_argument(
        "--limit", type=int, help="maximum projects/URLs for extract and prefilter"
    )
    run.add_argument(
        "--headful",
        action="store_true",
        help="show authenticated extraction browser",
    )
    run.add_argument(
        "--display",
        default=DEFAULT_VNC_DISPLAY,
        help="VNC X display when --headful is used",
    )
    run.add_argument(
        "--input",
        help="official asset JSON/JSONL file passed to the final prefilter stage",
    )
    run.add_argument(
        "--input-source",
        help="required as official_submit_page for plain URL input passed to prefilter",
    )
    run.add_argument(
        "--max-shallow-links",
        type=int,
        default=MAX_SHALLOW_LINKS,
        help="same-site explicit links fetched after the homepage",
    )
    run.add_argument(
        "--ai",
        action="store_true",
        help="enable optional OpenAI-compatible boundary review",
    )
    add_subdomain_arguments(run)
    run.set_defaults(handler=command_run)

    batch = subparsers.add_parser(
        "batch", help="process sequential public catalog pages into a persistent Wiki archive"
    )
    add_common_runtime_arguments(batch)
    add_auth_arguments(batch)
    batch.add_argument(
        "--target-kept", type=int, default=BATCH_TARGET_KEEP,
        help=f"new keep URLs required before stopping (default: {BATCH_TARGET_KEEP})",
    )
    batch.add_argument(
        "--resume-batch",
        help="continue an interrupted batch ID and retain its existing keep count",
    )
    batch.add_argument(
        "--page-span", type=int, default=BATCH_PAGE_SPAN,
        help=f"complete public catalog pages per chunk (default: {BATCH_PAGE_SPAN})",
    )
    batch.add_argument(
        "--start-page", type=int,
        help="explicit first catalog page; otherwise continue from the saved cursor",
    )
    batch.add_argument(
        "--wiki-dir",
        help=f"Wiki archive directory (default: {DEFAULT_WIKI_BATCH_DIR})",
    )
    batch.add_argument(
        "--force-recheck", action="store_true",
        help="re-run URLs that already have a global prefilter result",
    )
    batch.add_argument(
        "--headful", action="store_true",
        help="show authenticated extraction pages on the configured VNC display",
    )
    batch.add_argument(
        "--display", default=DEFAULT_VNC_DISPLAY,
        help="VNC X display when --headful is used",
    )
    batch.add_argument(
        "--max-shallow-links", type=int, default=MAX_SHALLOW_LINKS,
        help="same-site explicit links fetched after each homepage",
    )
    batch.add_argument(
        "--prefilter-workers",
        type=int,
        default=PREFILTER_WORKERS,
        help=f"concurrent homepage/shallow-link probe workers (default: {PREFILTER_WORKERS}; max: 8)",
    )
    batch.add_argument(
        "--prefilter-http-attempts",
        type=int,
        default=PREFILTER_HTTP_MAX_ATTEMPTS,
        help=f"attempts per homepage/shallow-link GET (default: {PREFILTER_HTTP_MAX_ATTEMPTS}; max: {MAX_RETRIES})",
    )
    batch.add_argument(
        "--ai", action="store_true",
        help="enable optional OpenAI-compatible boundary review",
    )
    add_subdomain_arguments(batch)
    batch.add_argument(
        "--middle-ai", action="store_true",
        default=MIDDLE_AI_ENABLED_BY_DEFAULT,
        help="run DeepSeek middle screening and count only priority_keep URLs",
    )
    batch.add_argument(
        "--force-middle-recheck", action="store_true",
        help="re-run cached DeepSeek middle reviews during this batch",
    )
    batch.set_defaults(handler=command_batch)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.handler(args))


if __name__ == "__main__":
    raise SystemExit(main())
