"""Conservative URL canonicalisation, SURT-style urlkeys and timestamps."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from urllib.parse import quote, urlsplit

SUPPORTED_SCHEMES = {"http", "https"}
DEFAULT_PORTS = {"http": 80, "https": 443}
_PCT_BAD = re.compile(r"%(?![0-9A-Fa-f]{2})")
_PCT_UP = re.compile(r"%([0-9A-Fa-f]{2})")
_PATH_SAFE = "/%:@!$&'()*+,;=-._~"
_QUERY_SAFE = "=&?/%:@!$'()*+,;-._~"
_CONTROL = re.compile(r"[\x00-\x20\x7f]")


class UrlError(ValueError):
    """A URL cannot be safely normalised."""


def _normalise_pct(value: str) -> str:
    if _PCT_BAD.search(value):
        raise UrlError("invalid percent escape")
    return _PCT_UP.sub(lambda m: "%" + m.group(1).upper(), value)


def canonicalize_url(raw: str) -> str:
    """Canonicalise an absolute http(s) URL without reordering query fields."""
    if not isinstance(raw, str) or not raw.strip():
        raise UrlError("empty URL")
    value = raw.strip()
    if _CONTROL.search(value):
        raise UrlError("URL contains whitespace or control characters")
    try:
        parts = urlsplit(value)
        host = parts.hostname
        port = parts.port
    except ValueError as exc:
        raise UrlError(str(exc)) from exc
    scheme = parts.scheme.lower()
    if scheme not in SUPPORTED_SCHEMES:
        raise UrlError("only http and https URLs are supported")
    if not host:
        raise UrlError("URL has no host")
    if parts.username is not None or parts.password is not None:
        raise UrlError("URL credentials are not accepted")
    host = host.lower()
    if host.endswith("."):
        host = host[:-1]
    if not host:
        raise UrlError("URL has no host")
    if ":" in host:
        netloc_host = f"[{host}]"
    else:
        try:
            netloc_host = host.encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise UrlError("invalid international host") from exc
    if port is not None and port != DEFAULT_PORTS[scheme]:
        netloc = f"{netloc_host}:{port}"
    else:
        netloc = netloc_host
    path = _normalise_pct(parts.path) or "/"
    path = quote(path, safe=_PATH_SAFE)
    query = _normalise_pct(parts.query)
    query = quote(query, safe=_QUERY_SAFE)
    return f"{scheme}://{netloc}{path}" + (f"?{query}" if parts.query else "")


def split_canonical(url: str) -> tuple[str, str, int | None, str, str]:
    parts = urlsplit(url)
    if parts.scheme not in SUPPORTED_SCHEMES or not parts.hostname:
        raise UrlError("not a canonical http(s) URL")
    try:
        port = parts.port
    except ValueError as exc:
        raise UrlError(str(exc)) from exc
    if port == DEFAULT_PORTS[parts.scheme]:
        port = None
    return parts.scheme, parts.hostname, port, parts.path or "/", parts.query


def urlkey(url: str) -> str:
    """Return a SURT-style key: scheme://(reversed-host[:port])/path?query."""
    canonical = canonicalize_url(url)
    scheme, host, port, path, query = split_canonical(canonical)
    if ":" in host:
        host_key = f"[{host}]"
    else:
        host_key = ",".join(reversed(host.split(".")))
    if port is not None:
        host_key += f":{port}"
    return f"{scheme}://({host_key}){path}" + (f"?{query}" if query else "")


def normalize_timestamp(raw: str) -> str:
    """Normalise an ISO-8601 timestamp with timezone to UTC seconds + Z."""
    if not isinstance(raw, str) or not raw.strip():
        raise ValueError("empty timestamp")
    value = raw.strip()
    if value.endswith(("Z", "z")):
        value = value[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ValueError("invalid ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include a timezone")
    parsed = parsed.astimezone(timezone.utc)
    return parsed.strftime("%Y-%m-%dT%H:%M:%SZ")


def to_cdx_timestamp(timestamp: str) -> str:
    parsed = datetime.strptime(normalize_timestamp(timestamp), "%Y-%m-%dT%H:%M:%SZ")
    return parsed.strftime("%Y%m%d%H%M%S")


def from_cdx_timestamp(timestamp: str) -> str:
    if not re.fullmatch(r"\d{14}", timestamp or ""):
        raise ValueError("CDX timestamp must be 14 digits")
    parsed = datetime.strptime(timestamp, "%Y%m%d%H%M%S")
    return parsed.strftime("%Y-%m-%dT%H:%M:%SZ")
