"""Validate a Web/API-only TARGET.yaml manifest before a profile is executed."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

# ============================ Configuration zone ============================
# MAX_RATE_LIMIT: hard upper bound for tool request rate in requests per second.
MAX_RATE_LIMIT = 50
# MAX_CRAWL_DEPTH / MAX_CRAWL_PAGES: hard limits that prevent unbounded crawling.
MAX_CRAWL_DEPTH = 10
MAX_CRAWL_PAGES = 10_000
# ============================================================================
@dataclass(frozen=True)
class ScopeError:
    field: str
    message: str

def _list(scope: dict[str, Any], name: str) -> list[Any]:
    value = scope.get(name, [])
    return value if isinstance(value, list) else []

def validate_scope(scope: dict[str, Any], profile: str) -> list[ScopeError]:
    """Return all manifest errors; callers decide how to present them."""
    errors: list[ScopeError] = []
    name = str(scope.get("name", "")).strip()
    if not name or name.upper() == "PROJECT":
        errors.append(ScopeError("name", "must be a non-placeholder project name"))
    include_hosts = {str(item).strip().lower() for item in _list(scope, "include_hosts") if str(item).strip()}
    for host in include_hosts:
        if "://" in host or "/" in host or "@" in host:
            errors.append(ScopeError("include_hosts", f"{host!r} must be a hostname, not a URL"))
    urls = _list(scope, "base_urls") + _list(scope, "openapi")
    for url in urls:
        parsed = urlparse(str(url))
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            errors.append(ScopeError("base_urls/openapi", f"{url!r} must be an absolute HTTP(S) URL"))
        elif parsed.username or parsed.password:
            errors.append(ScopeError("base_urls/openapi", f"{url!r} must not contain credentials"))
        elif parsed.hostname.lower() not in include_hosts:
            errors.append(ScopeError("include_hosts", f"{parsed.hostname!r} is not present in include_hosts"))
    if profile in {"web-baseline", "api"} and not include_hosts:
        errors.append(ScopeError("include_hosts", f"{profile} requires at least one exact include host"))
    if profile == "web-baseline" and not _list(scope, "base_urls"):
        errors.append(ScopeError("base_urls", "web-baseline requires at least one URL"))
    if profile == "api" and not _list(scope, "openapi"):
        errors.append(ScopeError("openapi", "api requires at least one schema URL"))
    declared_profiles = {str(item) for item in _list(scope, "profiles")}
    if declared_profiles and profile not in declared_profiles:
        errors.append(ScopeError("profiles", f"{profile!r} is not enabled by this target manifest"))
    try: rate = int(scope.get("rate_limit", 0))
    except (TypeError, ValueError): rate = 0
    if not 1 <= rate <= MAX_RATE_LIMIT:
        errors.append(ScopeError("rate_limit", f"must be an integer from 1 to {MAX_RATE_LIMIT}"))
    budget = scope.get("crawl_budget") if isinstance(scope.get("crawl_budget"), dict) else {}
    try: depth, pages = int(budget.get("max_depth", -1)), int(budget.get("max_pages", -1))
    except (TypeError, ValueError): depth, pages = -1, -1
    if not 0 <= depth <= MAX_CRAWL_DEPTH:
        errors.append(ScopeError("crawl_budget.max_depth", f"must be an integer from 0 to {MAX_CRAWL_DEPTH}"))
    if not 1 <= pages <= MAX_CRAWL_PAGES:
        errors.append(ScopeError("crawl_budget.max_pages", f"must be an integer from 1 to {MAX_CRAWL_PAGES}"))
    for path in _list(scope, "exclude_paths"):
        if not isinstance(path, str) or not path.startswith("/"):
            errors.append(ScopeError("exclude_paths", f"{path!r} must start with /"))
    return errors
