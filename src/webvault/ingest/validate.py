"""Validation rules and stable error codes for capture metadata."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..digest import iter_file_chunks
from ..model import CaptureRecord, HeaderList
from ..urlnorm import UrlError, canonicalize_url, normalize_timestamp
from ..warc.headers import HeaderError, parse_headers, validate_headers

_MIME = re.compile(r"^[a-z0-9][a-z0-9!#$&^_.+-]*/[a-z0-9][a-z0-9!#$&^_.+-]*$")

ERROR_CODES = {
    "E_MISSING_FIELD",
    "E_BAD_JSON",
    "E_META_NOT_FOUND",
    "E_BAD_TIMESTAMP",
    "E_BODY_NOT_FOUND",
    "E_BAD_URL",
    "E_BAD_REDIRECT",
    "E_BAD_STATUS",
    "E_BAD_HEADERS",
    "E_BAD_MIME",
    "E_BAD_META",
    "E_BAD_BODY_PATH",
}


class IngestValidationError(ValueError):
    def __init__(self, code: str, detail: str):
        super().__init__(detail)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class CaptureMeta:
    """Fully validated capture metadata without any response body bytes."""

    url: str
    timestamp: str
    status: int
    method: str
    headers: HeaderList
    mime_type: str
    source: str
    redirect_url: str | None
    note: str | None
    body_file: str
    body_path: Path


def _required(meta: dict[str, Any], key: str) -> Any:
    if key not in meta or meta[key] is None:
        raise IngestValidationError("E_MISSING_FIELD", f"missing field: {key}")
    return meta[key]


def _parse_meta(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise IngestValidationError("E_META_NOT_FOUND", "meta.json not found")
    try:
        with path.open("r", encoding="utf-8") as handle:
            meta = json.load(handle)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise IngestValidationError("E_BAD_JSON", f"invalid meta.json: {exc}") from exc
    if not isinstance(meta, dict):
        raise IngestValidationError("E_BAD_META", "meta.json must contain an object")
    return meta


def _headers_from_meta(meta: dict[str, Any], record_dir: Path) -> tuple[tuple[str, str], ...]:
    raw = meta.get("headers")
    if raw is None:
        header_file = record_dir / "headers.txt"
        if not header_file.is_file():
            raise IngestValidationError("E_MISSING_FIELD", "missing field: headers")
        try:
            parsed = parse_headers(header_file.read_bytes(), strict_crlf=False)
        except (OSError, HeaderError) as exc:
            raise IngestValidationError("E_BAD_HEADERS", str(exc)) from exc
        return parsed
    if isinstance(raw, dict):
        raw = list(raw.items())
    if not isinstance(raw, list):
        raise IngestValidationError("E_BAD_HEADERS", "headers must be a list of pairs")
    headers: list[tuple[str, str]] = []
    for item in raw:
        if (
            not isinstance(item, (list, tuple))
            or len(item) != 2
            or not all(isinstance(part, str) for part in item)
        ):
            raise IngestValidationError("E_BAD_HEADERS", "header entries must be [name, value]")
        headers.append((item[0], item[1]))
    try:
        validate_headers(tuple(headers))
    except HeaderError as exc:
        raise IngestValidationError("E_BAD_HEADERS", str(exc)) from exc
    return tuple(headers)


def _resolve_body_path(meta: dict[str, Any], record_dir: Path) -> tuple[Path, str]:
    body_name = _required(meta, "body_file")
    if not isinstance(body_name, str) or not body_name:
        raise IngestValidationError("E_BAD_META", "body_file must be a non-empty string")
    relative = Path(body_name)
    if relative.is_absolute() or ".." in relative.parts:
        raise IngestValidationError("E_BAD_BODY_PATH", "body_file must stay inside record directory")
    body_path = record_dir / relative
    try:
        resolved = body_path.resolve()
        if record_dir.resolve() not in resolved.parents and resolved != record_dir.resolve():
            raise IngestValidationError("E_BAD_BODY_PATH", "body_file escapes record directory")
    except OSError as exc:
        raise IngestValidationError("E_BODY_NOT_FOUND", str(exc)) from exc
    if not body_path.is_file():
        raise IngestValidationError("E_BODY_NOT_FOUND", f"body file not found: {body_name}")
    return body_path, body_name


def _read_body(meta: dict[str, Any], record_dir: Path) -> tuple[bytes, str]:
    """Legacy whole-file read; new batch code must use the streaming path."""
    body_path, body_name = _resolve_body_path(meta, record_dir)
    try:
        return body_path.read_bytes(), body_name
    except OSError as exc:
        raise IngestValidationError("E_BODY_NOT_FOUND", str(exc)) from exc


def open_body(meta: CaptureMeta):
    """Open the validated body file for bounded chunked reads."""
    try:
        return meta.body_path.open("rb")
    except OSError as exc:
        raise IngestValidationError("E_BODY_NOT_FOUND", str(exc)) from exc


def iter_body_chunks(meta: CaptureMeta, chunk_size: int):
    """Yield body chunks without ever holding the whole body in memory."""
    handle = open_body(meta)
    try:
        yield from iter_file_chunks(handle, chunk_size)
    finally:
        handle.close()


def parse_capture_meta(record_dir: Path, source: str) -> CaptureMeta:
    """Validate one capture directory without reading its response body bytes."""
    meta = _parse_meta(record_dir / "meta.json")
    url_raw = _required(meta, "url")
    if not isinstance(url_raw, str):
        raise IngestValidationError("E_BAD_URL", "url must be a string")
    try:
        url = canonicalize_url(url_raw)
    except UrlError as exc:
        raise IngestValidationError("E_BAD_URL", str(exc)) from exc

    timestamp_raw = _required(meta, "fetched_at")
    if not isinstance(timestamp_raw, str):
        raise IngestValidationError("E_BAD_TIMESTAMP", "fetched_at must be a string")
    try:
        timestamp = normalize_timestamp(timestamp_raw)
    except ValueError as exc:
        raise IngestValidationError("E_BAD_TIMESTAMP", str(exc)) from exc

    status = _required(meta, "status")
    if isinstance(status, bool) or not isinstance(status, int) or not 100 <= status <= 599:
        raise IngestValidationError("E_BAD_STATUS", "status must be an integer from 100 to 599")
    method = _required(meta, "method")
    if not isinstance(method, str) or not method.strip():
        raise IngestValidationError("E_BAD_META", "method must be a non-empty string")

    mime_raw = _required(meta, "mime_type")
    if not isinstance(mime_raw, str):
        raise IngestValidationError("E_BAD_MIME", "mime_type must be a string")
    mime_type = mime_raw.split(";", 1)[0].strip().lower()
    if not _MIME.fullmatch(mime_type):
        raise IngestValidationError("E_BAD_MIME", "mime_type is not a media type")

    redirect_raw = meta.get("redirect_url")
    redirect = None
    if redirect_raw not in (None, ""):
        if not isinstance(redirect_raw, str):
            raise IngestValidationError("E_BAD_REDIRECT", "redirect_url must be a string")
        try:
            redirect = canonicalize_url(redirect_raw)
        except UrlError as exc:
            raise IngestValidationError("E_BAD_REDIRECT", str(exc)) from exc

    note = meta.get("note")
    if note is not None and not isinstance(note, str):
        raise IngestValidationError("E_BAD_META", "note must be a string or null")

    headers = _headers_from_meta(meta, record_dir)
    body_path, body_file = _resolve_body_path(meta, record_dir)
    return CaptureMeta(
        url=url,
        timestamp=timestamp,
        status=status,
        method=method,
        headers=headers,
        mime_type=mime_type,
        source=source,
        redirect_url=redirect,
        note=note,
        body_file=body_file,
        body_path=body_path,
    )


def parse_capture(record_dir: Path, source: str) -> CaptureRecord:
    """Validate one capture directory and return a normalised capture record.

    Retained for callers that materialise bodies; the bounded batch pipeline
    uses :func:`parse_capture_meta` plus chunked body streaming instead.
    """
    info = parse_capture_meta(record_dir, source)
    try:
        body = info.body_path.read_bytes()
    except OSError as exc:
        raise IngestValidationError("E_BODY_NOT_FOUND", str(exc)) from exc
    return CaptureRecord(
        url=info.url,
        timestamp=info.timestamp,
        status=info.status,
        method=info.method,
        headers=info.headers,
        mime_type=info.mime_type,
        body=body,
        source=info.source,
        redirect_url=info.redirect_url,
        note=info.note,
        body_file=info.body_file,
    )
