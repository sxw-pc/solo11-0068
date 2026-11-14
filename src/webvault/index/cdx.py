"""Deterministic CDX generation and parsing."""

from __future__ import annotations

import json
import os
from pathlib import Path

from ..model import CdxEntry, WarcRecord
from ..urlnorm import canonicalize_url, to_cdx_timestamp, urlkey as make_urlkey
from ..warc.headers import split_http_block


def cdx_path_for(archive: Path | str) -> Path:
    archive = Path(archive)
    name = archive.name
    for suffix in (".warc.gz", ".warc"):
        if name.endswith(suffix):
            name = name[: -len(suffix)]
            break
    return archive.with_name(name + ".cdx")


def _metadata_redirects(records: list[WarcRecord]) -> dict[str, str]:
    redirects: dict[str, str] = {}
    for record in records:
        if record.warc_type != "metadata" or not record.refers_to:
            continue
        try:
            payload = json.loads(record.block.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError):
            continue
        outlink = payload.get("outlink") if isinstance(payload, dict) else None
        if isinstance(outlink, str) and outlink:
            redirects[record.refers_to] = outlink
    return redirects


def entries_from_records(
    records: list[WarcRecord], filename: str
) -> list[CdxEntry]:
    """Build CDX rows for response records only."""
    redirects = _metadata_redirects(records)
    entries: list[CdxEntry] = []
    for record in records:
        if record.warc_type != "response":
            continue
        if not record.target_uri:
            continue
        try:
            original = canonicalize_url(record.target_uri)
            key = make_urlkey(original)
            timestamp = to_cdx_timestamp(record.date)
            status, _, _ = split_http_block(record.block)
        except (ValueError, UnicodeError):
            continue
        mimetype = (record.content_type.split(";", 1)[0].strip().lower() or "application/octet-stream")
        entries.append(
            CdxEntry(
                urlkey=key,
                timestamp=timestamp,
                original=original,
                mimetype=mimetype,
                status=status,
                digest=record.block_digest,
                redirect=redirects.get(record.record_id, ""),
                offset=record.offset,
                filename=filename,
            )
        )
    return dedupe_and_sort(entries)


def dedupe_and_sort(entries: list[CdxEntry]) -> list[CdxEntry]:
    """Sort by urlkey/timestamp and retain the smallest offset per triple."""
    ordered = sorted(entries, key=lambda e: e.sort_key())
    chosen: dict[tuple[str, str, str], CdxEntry] = {}
    for entry in ordered:
        key = (entry.urlkey, entry.timestamp, entry.digest)
        current = chosen.get(key)
        if current is None or (entry.offset, entry.filename) < (current.offset, current.filename):
            chosen[key] = entry
    return sorted(chosen.values(), key=lambda e: e.sort_key())


def write_cdx(path: Path | str, entries: list[CdxEntry]) -> Path:
    """Write CDX lines with LF endings, atomically."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    data = "".join(entry.line() for entry in dedupe_and_sort(entries)).encode("utf-8")
    try:
        temporary.write_bytes(data)
        os.replace(temporary, path)
    except BaseException:
        try:
            temporary.unlink()
        except OSError:
            pass
        raise
    return path


def read_cdx(path: Path | str) -> list[CdxEntry]:
    """Read and validate a CDX file.  Raises ValueError on malformed rows."""
    path = Path(path)
    entries: list[CdxEntry] = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line:
            continue
        try:
            entry = CdxEntry.parse_line(line + "\n")
        except ValueError as exc:
            raise ValueError(f"line {number}: {exc}") from exc
        if len(entry.timestamp) != 14 or not entry.timestamp.isdigit():
            raise ValueError(f"line {number}: timestamp must be 14 digits")
        entries.append(entry)
    return entries
