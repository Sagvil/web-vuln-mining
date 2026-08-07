"""Validate a bounded Web/API or DNS-candidate TARGET.yaml manifest."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

# ============================ Configuration zone ============================
# MAX_RATE_LIMIT: hard upper bound for HTTP request rate in requests per second.
MAX_RATE_LIMIT = 50
# MAX_CRAWL_DEPTH / MAX_CRAWL_PAGES: hard limits that prevent unbounded crawling.
MAX_CRAWL_DEPTH = 10
MAX_CRAWL_PAGES = 10_000
# ACTIVE_DNS_*: DNS-only discovery limits. They bound wordlist work and output,
# never expand the HTTP scope declared in include_hosts/base_urls.
ACTIVE_DNS_MAX_ROOTS = 20
ACTIVE_DNS_MAX_WORDS = 10_000
ACTIVE_DNS_MAX_THREADS = 20
ACTIVE_DNS_MAX_CANDIDATES = 5_000
# ============================================================================


@dataclass(frozen=True)
class ScopeError:
    field: str
    message: str


def _list(scope: dict[str, Any], name: str) -> list[Any]:
    value = scope.get(name, [])
    return value if isinstance(value, list) else []


def _integer(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _is_dns_root(value: str) -> bool:
    return bool(value) and '://' not in value and '/' not in value and '@' not in value and all(part and part.replace('-', '').isalnum() for part in value.split('.'))


def _validate_active_dns(scope: dict[str, Any], include_hosts: set[str], errors: list[ScopeError]) -> None:
    config = scope.get('active_dns_discovery')
    if not isinstance(config, dict):
        errors.append(ScopeError('active_dns_discovery', 'must be a mapping when active-dns-discovery is selected'))
        return
    roots = config.get('roots')
    if not isinstance(roots, list) or not roots:
        errors.append(ScopeError('active_dns_discovery.roots', 'must be a non-empty list of explicit DNS roots'))
    elif len(roots) > ACTIVE_DNS_MAX_ROOTS:
        errors.append(ScopeError('active_dns_discovery.roots', f'must contain at most {ACTIVE_DNS_MAX_ROOTS} roots'))
    else:
        for raw in roots:
            root = str(raw).strip().rstrip('.').lower()
            if not _is_dns_root(root):
                errors.append(ScopeError('active_dns_discovery.roots', f'{raw!r} must be a plain DNS root'))
                continue
            if not any(host == root or host.endswith('.' + root) for host in include_hosts):
                errors.append(ScopeError('active_dns_discovery.roots', f'{root!r} must be an include_hosts entry or its parent domain'))
    wordlist = str(config.get('wordlist', '')).strip()
    if not wordlist:
        errors.append(ScopeError('active_dns_discovery.wordlist', 'must name a repository-relative DNS wordlist'))
    elif Path(wordlist).is_absolute() or '..' in Path(wordlist).parts:
        errors.append(ScopeError('active_dns_discovery.wordlist', 'must stay repository-relative without parent traversal'))
    for key, maximum in (('max_words', ACTIVE_DNS_MAX_WORDS), ('threads', ACTIVE_DNS_MAX_THREADS), ('max_candidates', ACTIVE_DNS_MAX_CANDIDATES)):
        value = _integer(config.get(key))
        if not 1 <= value <= maximum:
            errors.append(ScopeError(f'active_dns_discovery.{key}', f'must be an integer from 1 to {maximum}'))


def validate_scope(scope: dict[str, Any], profile: str) -> list[ScopeError]:
    """Return all manifest errors; callers decide how to present them."""
    errors: list[ScopeError] = []
    name = str(scope.get('name', '')).strip()
    if not name or name.upper() == 'PROJECT':
        errors.append(ScopeError('name', 'must be a non-placeholder project name'))
    include_hosts = {str(item).strip().lower().rstrip('.') for item in _list(scope, 'include_hosts') if str(item).strip()}
    for host in include_hosts:
        if '://' in host or '/' in host or '@' in host:
            errors.append(ScopeError('include_hosts', f'{host!r} must be a hostname, not a URL'))
    urls = _list(scope, 'base_urls') + _list(scope, 'openapi')
    for url in urls:
        parsed = urlparse(str(url))
        if parsed.scheme not in {'http', 'https'} or not parsed.hostname:
            errors.append(ScopeError('base_urls/openapi', f'{url!r} must be an absolute HTTP(S) URL'))
        elif parsed.username or parsed.password:
            errors.append(ScopeError('base_urls/openapi', f'{url!r} must not contain credentials'))
        elif parsed.hostname.lower().rstrip('.') not in include_hosts:
            errors.append(ScopeError('include_hosts', f'{parsed.hostname!r} is not present in include_hosts'))
    web_profiles = {'web-baseline', 'api', 'verify-xss', 'verify-sqli', 'content-discovery'}
    if profile in web_profiles and not include_hosts:
        errors.append(ScopeError('include_hosts', f'{profile} requires at least one exact include host'))
    if profile == 'web-baseline' and not _list(scope, 'base_urls'):
        errors.append(ScopeError('base_urls', 'web-baseline requires at least one URL'))
    if profile == 'api' and not _list(scope, 'openapi'):
        errors.append(ScopeError('openapi', 'api requires at least one schema URL'))
    if profile == 'content-discovery' and not _list(scope, 'base_urls'):
        errors.append(ScopeError('base_urls', 'content-discovery requires at least one base URL'))
    if profile == 'content-discovery':
        discovery = scope.get('content_discovery') if isinstance(scope.get('content_discovery'), dict) else {}
        max_requests = _integer(discovery.get('max_requests', 300))
        if not 1 <= max_requests <= MAX_CRAWL_PAGES:
            errors.append(ScopeError('content_discovery.max_requests', f'must be an integer from 1 to {MAX_CRAWL_PAGES}'))
        statuses = discovery.get('match_statuses', [200, 204, 301, 302, 307, 401, 403])
        if not isinstance(statuses, list) or not statuses or any(not isinstance(status, int) or not 100 <= status <= 599 for status in statuses):
            errors.append(ScopeError('content_discovery.match_statuses', 'must be a non-empty list of HTTP status integers'))
    declared_profiles = {str(item) for item in _list(scope, 'profiles')}
    if profile == 'active-dns-discovery':
        if profile not in declared_profiles:
            errors.append(ScopeError('profiles', 'active-dns-discovery must be explicitly enabled by this target manifest'))
        _validate_active_dns(scope, include_hosts, errors)
    elif declared_profiles and profile not in declared_profiles:
        errors.append(ScopeError('profiles', f'{profile!r} is not enabled by this target manifest'))
    rate = _integer(scope.get('rate_limit', 0))
    if not 1 <= rate <= MAX_RATE_LIMIT:
        errors.append(ScopeError('rate_limit', f'must be an integer from 1 to {MAX_RATE_LIMIT}'))
    budget = scope.get('crawl_budget') if isinstance(scope.get('crawl_budget'), dict) else {}
    depth, pages = _integer(budget.get('max_depth', -1), -1), _integer(budget.get('max_pages', -1), -1)
    if not 0 <= depth <= MAX_CRAWL_DEPTH:
        errors.append(ScopeError('crawl_budget.max_depth', f'must be an integer from 0 to {MAX_CRAWL_DEPTH}'))
    if not 1 <= pages <= MAX_CRAWL_PAGES:
        errors.append(ScopeError('crawl_budget.max_pages', f'must be an integer from 1 to {MAX_CRAWL_PAGES}'))
    for path in _list(scope, 'exclude_paths'):
        if not isinstance(path, str) or not path.startswith('/'):
            errors.append(ScopeError('exclude_paths', f'{path!r} must start with /'))
    return errors
