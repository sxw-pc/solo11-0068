"""CDX-to-archive correspondence checks used by the auditor."""

from __future__ import annotations

from pathlib import Path

from ..index.cdx import cdx_path_for, read_cdx
from ..model import CdxEntry, WarcRecord
from ..urlnorm import canonicalize_url, to_cdx_timestamp, urlkey as make_urlkey
from ..warc.headers import split_http_block
from .issues import add_issue


def _expected_entry(record: WarcRecord, filename: str) -> dict | None:
    try:
        original = canonicalize_url(record.target_uri)
        status, _, _ = split_http_block(record.block)
        return {
            "urlkey": make_urlkey(original),
            "timestamp": to_cdx_timestamp(record.date),
            "original": original,
            "mimetype": record.content_type.split(";", 1)[0].strip().lower(),
            "status": status,
            "digest": record.block_digest,
            "filename": filename,
        }
    except (ValueError, UnicodeError):
        return None


def check_cdx(archive_map: dict[str, list[WarcRecord]], cdx_rows: dict[str, list[CdxEntry]], issues) -> None:
    for filename, entries in cdx_rows.items():
        records = archive_map.get(filename)
        by_offset = {r.offset: r for r in records or [] if r.warc_type == "response"}
        for entry in entries:
            if records is None:
                add_issue(issues, "E_ORPHAN_CDX", filename, entry.offset, "", "no archive or record at index offset")
                continue
            record = by_offset.get(entry.offset)
            if record is None:
                add_issue(issues, "E_ORPHAN_CDX", filename, entry.offset, "", "no response record at index offset")
                continue
            expected = _expected_entry(record, filename)
            fields = ("urlkey", "timestamp", "original", "mimetype", "status", "digest", "filename")
            drift = expected is None or any(
                getattr(entry, field) != expected[field] for field in fields
            )
            if drift:
                add_issue(
                    issues,
                    "E_OFFSET_DRIFT",
                    filename,
                    entry.offset,
                    record.record_id,
                    "CDX fields do not match the record at this offset",
                )
    for filename, records in archive_map.items():
        keys = {
            (entry.urlkey, entry.timestamp, entry.digest)
            for entry in cdx_rows.get(filename, [])
        }
        for record in records:
            if record.warc_type != "response":
                continue
            expected = _expected_entry(record, filename)
            if expected is None:
                continue
            key = (expected["urlkey"], expected["timestamp"], expected["digest"])
            if key not in keys:
                add_issue(
                    issues,
                    "E_MISSING_CDX",
                    filename,
                    record.offset,
                    record.record_id,
                    "response record has no matching CDX row",
                )


def load_cdx(archives: list[Path], cdx_files: list[Path] | None, issues) -> dict[str, list[CdxEntry]]:
    paths = set(cdx_files or [])
    for archive in archives:
        candidate = cdx_path_for(archive)
        if candidate.is_file():
            paths.add(candidate)
    rows: dict[str, list[CdxEntry]] = {}
    for path in sorted(paths, key=lambda p: p.name):
        try:
            entries = read_cdx(path)
        except (OSError, ValueError) as exc:
            add_issue(issues, "E_MALFORMED_CDX", path.name, 0, "", str(exc))
            continue
        for entry in entries:
            rows.setdefault(entry.filename, []).append(entry)
    return rows
