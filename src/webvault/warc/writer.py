"""Deterministic WARC/1.0 writer, plain or one gzip member per record.

Two write paths share the exact same serialisation primitives:

* the in-memory path (:func:`write_archive`, :func:`write_raw_archive`) keeps
  the historical behaviour for callers that already hold full records;
* the streaming path (:func:`write_archive_plan`) consumes an ordered ingest
  plan whose bodies live in a private spool, so peak resident body memory is
  bounded by the chunk buffer instead of the total batch size, while emitting
  byte-identical archives.
"""

from __future__ import annotations

import hashlib
import json
import os
import zlib
from pathlib import Path
from typing import Iterator, Protocol
from uuid import NAMESPACE_URL, uuid5

from .. import __version__
from ..digest import DEFAULT_CHUNK_SIZE, digest_from_hasher, file_sha256, sha256_digest
from ..model import CaptureRecord, RawRecord, WriteResult
from .errors import WarcSourceChangedError
from .headers import build_http_block, http_block_head, serialize_headers

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


def _warc_headers_bytes(
    warc_type: str,
    record_id: str,
    date: str,
    target_uri: str,
    content_type: str,
    block_digest: str,
    content_length: int,
    refers_to: str | None = None,
) -> bytes:
    """Serialise WARC headers in the exact order used by ``serialize_raw``."""
    headers = [
        ("WARC-Type", warc_type),
        ("WARC-Record-ID", record_id),
        ("WARC-Date", date),
    ]
    if target_uri:
        headers.append(("WARC-Target-URI", target_uri))
    headers.extend(
        [
            ("Content-Type", content_type),
            ("WARC-Block-Digest", block_digest),
        ]
    )
    if refers_to:
        headers.append(("WARC-Refers-To", refers_to))
    headers.append(("Content-Length", str(content_length)))
    return b"WARC/1.0\r\n" + serialize_headers(tuple(headers)) + b"\r\n\r\n"


def serialize_raw(record: RawRecord) -> bytes:
    """Serialize one record.  Content-Length counts only the block."""
    return (
        _warc_headers_bytes(
            record.warc_type,
            record.record_id,
            record.date,
            record.target_uri,
            record.content_type,
            sha256_digest(record.block),
            len(record.block),
            record.refers_to,
        )
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


class _MemberWriter:
    """Stream one WARC record to file, plain or as one gzip member.

    The gzip branch uses the same fixed header, level-9 raw deflate stream,
    big-endian CRC32 and little-endian ISIZE trailer as :func:`_gzip_member`,
    so compressed output is byte-identical without buffering the payload.
    """

    def __init__(self, handle, compress: bool):
        self.handle = handle
        self.compress = compress
        self.crc = 0
        self.size = 0
        self._compressor = (
            zlib.compressobj(9, zlib.DEFLATED, -15) if compress else None
        )
        if compress:
            handle.write(_GZIP_HEADER)

    def write(self, data: bytes) -> None:
        if not data:
            return
        self.size += len(data)
        self.crc = zlib.crc32(data, self.crc)
        if self._compressor is not None:
            self.handle.write(self._compressor.compress(data))
        else:
            self.handle.write(data)

    def finish(self) -> None:
        if self._compressor is not None:
            self.handle.write(self._compressor.flush())
            self.handle.write(
                self.crc.to_bytes(4, "big")
                + (self.size & 0xFFFFFFFF).to_bytes(4, "little")
            )


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


class _OrderedPlan(Protocol):
    def iter_ordered(self, page_size: int = ...) -> Iterator: ...

    def open_spool(self, planned): ...


def _metadata_block(planned) -> bytes:
    payload = {
        "format": "webvault-metadata/1",
        "note": planned.note,
        "outlink": planned.redirect_url,
        "source_url": planned.url,
    }
    return (
        json.dumps(payload, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def _check_record_size(
    warc_type: str, payload_length: int, maximum: int, target_uri: str
) -> None:
    if maximum > 0 and payload_length > maximum:
        raise RecordTooLargeError(warc_type, payload_length, maximum, target_uri)


def _response_payload_length(planned, head: bytes) -> int:
    return (
        len(
            _warc_headers_bytes(
                "response",
                planned.record_id,
                planned.timestamp,
                planned.url,
                planned.mime_type,
                planned.block_digest,
                planned.block_length,
            )
        )
        + len(head)
        + planned.body_length
        + 4
    )


def _metadata_payload_length(planned, block: bytes) -> int:
    return (
        len(
            _warc_headers_bytes(
                "metadata",
                planned.metadata_id,
                planned.timestamp,
                planned.url,
                "application/json",
                sha256_digest(block),
                len(block),
                planned.record_id,
            )
        )
        + len(block)
        + 4
    )


def _stream_response(
    handle, plan: _OrderedPlan, planned, compress: bool, maximum: int, chunk_size: int
) -> None:
    head = http_block_head(planned.status, planned.headers, planned.body_length)
    block_length = planned.block_length
    if block_length != len(head) + planned.body_length:
        raise WarcSourceChangedError(
            f"plan block length mismatch for {planned.source}: {block_length}"
        )
    warc_headers = _warc_headers_bytes(
        "response",
        planned.record_id,
        planned.timestamp,
        planned.url,
        planned.mime_type,
        planned.block_digest,
        block_length,
    )
    payload_length = len(warc_headers) + block_length + 4
    _check_record_size("response", payload_length, maximum, planned.url)

    member = _MemberWriter(handle, compress)
    member.write(warc_headers)
    member.write(head)
    body_hasher = hashlib.sha256()
    block_hasher = hashlib.sha256()
    block_hasher.update(head)
    seen_length = 0
    with plan.open_spool(planned) as spool:
        while True:
            chunk = spool.read(chunk_size)
            if not chunk:
                break
            seen_length += len(chunk)
            body_hasher.update(chunk)
            block_hasher.update(chunk)
            member.write(chunk)
    member.write(b"\r\n\r\n")
    member.finish()

    if seen_length != planned.body_length:
        raise WarcSourceChangedError(
            f"body length changed for {planned.source}: "
            f"planned {planned.body_length}, spool {seen_length}"
        )
    body_digest = digest_from_hasher(body_hasher)
    if body_digest != planned.body_digest:
        raise WarcSourceChangedError(
            f"body digest changed for {planned.source}: "
            f"planned {planned.body_digest}, spool {body_digest}"
        )
    block_digest = digest_from_hasher(block_hasher)
    if block_digest != planned.block_digest:
        raise WarcSourceChangedError(
            f"block digest changed for {planned.source}: "
            f"planned {planned.block_digest}, actual {block_digest}"
        )


def _stream_metadata(handle, planned, compress: bool, maximum: int) -> None:
    block = _metadata_block(planned)
    payload = (
        _warc_headers_bytes(
            "metadata",
            planned.metadata_id,
            planned.timestamp,
            planned.url,
            "application/json",
            sha256_digest(block),
            len(block),
            planned.record_id,
        )
        + block
        + b"\r\n\r\n"
    )
    _check_record_size("metadata", len(payload), maximum, planned.url)
    handle.write(_gzip_member(payload) if compress else payload)


def write_archive_plan(
    plan: _OrderedPlan,
    path: Path | str,
    *,
    gzip_compress: bool = False,
    max_record_bytes: int = DEFAULT_MAX_RECORD_BYTES,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    page_size: int = 128,
) -> WriteResult:
    """Write an archive from an ordered plan with bounded resident body memory.

    Output is byte-identical to :func:`write_archive` over the equivalent
    in-memory captures: same global ordering, record IDs, redirect metadata,
    ``records-expected`` and gzip members.  Every response body is re-read from
    the private spool in fixed chunks and its digests are re-verified against
    the plan before the member is finalised, so ordering digest and emitted
    bytes cannot diverge.  The target is only published via ``os.replace``
    after every record passes the size and digest checks.
    """
    path = Path(path)
    # First pass over the paged plan: counts, warcinfo date and every
    # single-record size limit, all without materialising the batch.  If any
    # record exceeds the limit we raise before the target temporary file is
    # created, so an over-limit capture leaves no partial archive behind.
    responses = 0
    metadata = 0
    date = None
    for planned in plan.iter_ordered(page_size=page_size):
        responses += 1
        if planned.redirect_url:
            metadata += 1
        if date is None or planned.timestamp < date:
            date = planned.timestamp
        head = http_block_head(planned.status, planned.headers, planned.body_length)
        _check_record_size(
            "response",
            _response_payload_length(planned, head),
            max_record_bytes,
            planned.url,
        )
        if planned.redirect_url:
            _check_record_size(
                "metadata",
                _metadata_payload_length(planned, _metadata_block(planned)),
                max_record_bytes,
                planned.url,
            )
    if responses == 0:
        raise ValueError("cannot write an archive with no capture records")

    total_records = 1 + responses + metadata
    warcinfo = serialize_raw(_warcinfo(date, total_records))
    _check_record_size("warcinfo", len(warcinfo), max_record_bytes, "")

    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    try:
        with temporary.open("wb") as handle:
            handle.write(_gzip_member(warcinfo) if gzip_compress else warcinfo)
            # Second paged pass: stream and re-verify each body from spool.
            for planned in plan.iter_ordered(page_size=page_size):
                _stream_response(
                    handle, plan, planned, gzip_compress, max_record_bytes, chunk_size
                )
                if planned.redirect_url:
                    _stream_metadata(handle, planned, gzip_compress, max_record_bytes)
        os.replace(temporary, path)
    except BaseException:
        try:
            temporary.unlink()
        except OSError:
            pass
        raise
    return WriteResult(
        path=path,
        records=total_records,
        responses=responses,
        size=path.stat().st_size,
        sha256=file_sha256(path),
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
