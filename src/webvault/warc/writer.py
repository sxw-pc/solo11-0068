"""Deterministic WARC/1.0 writer, plain or one gzip member per record."""

from __future__ import annotations

import json
import os
import zlib
from pathlib import Path
from uuid import NAMESPACE_URL, uuid5

from .. import __version__
from ..digest import file_sha256, sha256_digest
from ..model import CaptureRecord, RawRecord, WriteResult
from .headers import build_http_block, serialize_headers

DEFAULT_MAX_RECORD_BYTES = 4 * 1024 * 1024
_GZIP_HEADER = b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff"


class RecordTooLargeError(ValueError):
    code = "E_RECORD_TOO_LARGE"

    def __init__(self, record_type: str, size: int, maximum: int, target: str = ""):
        self.record_type = record_type
        self.size = size
        self.maximum = maximum
        self.target = target
        super().__init__(
            f"{record_type} record is {size} bytes, above --max-record-bytes {maximum}"
        )


def _warcinfo(date: str, records_expected: int) -> RawRecord:
    block = (
        f"software: webvault/{__version__}\n"
        "format: WARC File Format 1.0\n"
        f"created: {date}\n"
        f"records-expected: {records_expected}\n"
    ).encode("ascii")
    record_id = f"<urn:uuid:{uuid5(NAMESPACE_URL, f'webvault-warcinfo|{date}|{records_expected}')}>"
    return RawRecord(
        "warcinfo", record_id, date, "", "application/warc-fields", block
    )


def serialize_raw(record: RawRecord) -> bytes:
    """Serialize one record.  Content-Length counts only the block."""
    headers = [
        ("WARC-Type", record.warc_type),
        ("WARC-Record-ID", record.record_id),
        ("WARC-Date", record.date),
    ]
    if record.target_uri:
        headers.append(("WARC-Target-URI", record.target_uri))
    headers.extend(
        [
            ("Content-Type", record.content_type),
            ("WARC-Block-Digest", sha256_digest(record.block)),
        ]
    )
    if record.refers_to:
        headers.append(("WARC-Refers-To", record.refers_to))
    headers.append(("Content-Length", str(len(record.block))))
    return (
        b"WARC/1.0\r\n"
        + serialize_headers(tuple(headers))
        + b"\r\n\r\n"
        + record.block
        + b"\r\n\r\n"
    )


def _gzip_member(payload: bytes) -> bytes:
    compressor = zlib.compressobj(9, zlib.DEFLATED, -15)
    compressed = compressor.compress(payload) + compressor.flush()
    trailer = (
        zlib.crc32(payload).to_bytes(4, "big")
        + (len(payload) & 0xFFFFFFFF).to_bytes(4, "little")
    )
    return _GZIP_HEADER + compressed + trailer


def _metadata_record(capture: CaptureRecord) -> RawRecord:
    payload = {
        "format": "webvault-metadata/1",
        "note": capture.note,
        "outlink": capture.redirect_url,
        "source_url": capture.url,
    }
    block = (
        json.dumps(payload, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")
    return RawRecord(
        "metadata",
        capture.metadata_id,
        capture.timestamp,
        capture.url,
        "application/json",
        block,
        refers_to=capture.record_id,
    )


def capture_raw_records(captures: list[CaptureRecord]) -> list[RawRecord]:
    records: list[RawRecord] = []
    for capture in captures:
        response = RawRecord(
            "response",
            capture.record_id,
            capture.timestamp,
            capture.url,
            capture.mime_type,
            build_http_block(capture.status, capture.headers, capture.body),
        )
        records.append(response)
        if capture.redirect_url:
            records.append(_metadata_record(capture))
    return records


def _write_members(handle, records: list[RawRecord], compress: bool, maximum: int) -> None:
    for record in records:
        payload = serialize_raw(record)
        if maximum > 0 and len(payload) > maximum:
            raise RecordTooLargeError(record.warc_type, len(payload), maximum, record.target_uri)
        handle.write(_gzip_member(payload) if compress else payload)


def write_raw_archive(
    path: Path | str,
    raw_records: list[RawRecord],
    *,
    gzip_compress: bool = False,
    max_record_bytes: int = DEFAULT_MAX_RECORD_BYTES,
    warcinfo_date: str | None = None,
) -> WriteResult:
    """Write raw records with a new deterministic warcinfo as the first record."""
    path = Path(path)
    if not raw_records:
        raise ValueError("cannot write an archive with no capture records")
    date = warcinfo_date or min(record.date for record in raw_records if record.date)
    records = [_warcinfo(date, len(raw_records) + 1)] + raw_records
    return _atomic_write(path, records, gzip_compress, max_record_bytes)


def write_archive(
    captures: list[CaptureRecord],
    path: Path | str,
    *,
    gzip_compress: bool = False,
    max_record_bytes: int = DEFAULT_MAX_RECORD_BYTES,
    warcinfo_date: str | None = None,
) -> WriteResult:
    """Write captures in deterministic (urlkey, timestamp, digest) order."""
    if not captures:
        raise ValueError("cannot write an archive with no capture records")
    ordered = sorted(captures, key=lambda r: (r.urlkey, r.timestamp, r.digest, r.source))
    raw_records = capture_raw_records(ordered)
    date = warcinfo_date or min(capture.timestamp for capture in ordered)
    return write_raw_archive(
        path,
        raw_records,
        gzip_compress=gzip_compress,
        max_record_bytes=max_record_bytes,
        warcinfo_date=date,
    )


def _atomic_write(
    path: Path, records: list[RawRecord], compress: bool, maximum: int
) -> WriteResult:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    try:
        with temporary.open("wb") as handle:
            _write_members(handle, records, compress, maximum)
        os.replace(temporary, path)
    except BaseException:
        try:
            temporary.unlink()
        except OSError:
            pass
        raise
    responses = sum(1 for record in records if record.warc_type == "response")
    return WriteResult(
        path=path,
        records=len(records),
        responses=responses,
        size=path.stat().st_size,
        sha256=file_sha256(path),
    )
