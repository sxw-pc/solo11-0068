"""Streaming WARC reader for plain and multi-member gzip archives."""

from __future__ import annotations

from pathlib import Path

from ..model import ReadResult, WarcRecord
from .errors import WarcReadError
from .gzip_reader import GZIP_MAGIC, iter_gzip_members
from .headers import HeaderError, get_header, parse_headers

KNOWN_TYPES = {
    "warcinfo",
    "response",
    "resource",
    "request",
    "metadata",
    "revisit",
    "conversion",
    "continuation",
}


def _header_int(headers, name: str, offset: int) -> int:
    value = get_header(headers, name)
    if value is None:
        raise WarcReadError("E_MALFORMED_WARC", f"missing {name}", offset=offset)
    try:
        number = int(value.strip())
    except ValueError as exc:
        raise WarcReadError("E_MALFORMED_WARC", f"invalid {name}", offset=offset) from exc
    if number < 0:
        raise WarcReadError("E_MALFORMED_WARC", f"negative {name}", offset=offset)
    return number


def _make_record(
    headers,
    block: bytes,
    *,
    offset: int,
    end_offset: int,
    warc_file: str,
    compressed: bool,
    uncompressed_offset: int,
    block_start: int,
    block_end: int,
    compressed_offset: int | None,
) -> WarcRecord:
    raw_type = get_header(headers, "WARC-Type") or ""
    record_type = raw_type.strip().lower()
    if record_type not in KNOWN_TYPES:
        record_type = "other"
    return WarcRecord(
        warc_type=record_type,
        raw_type=raw_type,
        record_id=get_header(headers, "WARC-Record-ID") or "",
        date=get_header(headers, "WARC-Date") or "",
        target_uri=get_header(headers, "WARC-Target-URI") or "",
        content_type=get_header(headers, "Content-Type") or "",
        block_digest=get_header(headers, "WARC-Block-Digest") or "",
        content_length=len(block),
        headers=headers,
        block=block,
        offset=offset,
        end_offset=end_offset,
        warc_file=warc_file,
        compressed=compressed,
        block_offset=block_start,
        block_end_offset=block_end,
        uncompressed_offset=uncompressed_offset,
        uncompressed_block_offset=block_start,
        uncompressed_block_end_offset=block_end,
        compressed_offset=compressed_offset,
    )


def _iter_plain(path: Path, warc_file: str):
    with path.open("rb") as handle:
        while True:
            record_offset = handle.tell()
            line = handle.readline()
            while line == b"\r\n":
                record_offset = handle.tell()
                line = handle.readline()
            if not line:
                return
            if not line.endswith(b"\r\n"):
                raise WarcReadError("E_MALFORMED_WARC", "non-CRLF WARC line", offset=record_offset)
            if line != b"WARC/1.0\r\n":
                raise WarcReadError(
                    "E_MALFORMED_WARC", "record does not start with WARC/1.0", offset=record_offset
                )
            header_lines = []
            while True:
                line = handle.readline()
                if not line:
                    raise WarcReadError("E_MALFORMED_WARC", "truncated WARC header", offset=record_offset)
                if not line.endswith(b"\r\n"):
                    raise WarcReadError("E_MALFORMED_WARC", "non-CRLF WARC header", offset=record_offset)
                if line == b"\r\n":
                    break
                header_lines.append(line[:-2])
            try:
                headers = parse_headers(b"\r\n".join(header_lines), strict_crlf=True)
            except HeaderError as exc:
                raise WarcReadError("E_MALFORMED_WARC", str(exc), offset=record_offset) from exc
            length = _header_int(headers, "Content-Length", record_offset)
            block_start = handle.tell()
            block = handle.read(length)
            if len(block) != length:
                raise WarcReadError(
                    "E_LENGTH_MISMATCH",
                    "declared Content-Length does not match available bytes",
                    offset=record_offset,
                    declared=length,
                    actual=len(block),
                )
            yield _make_record(
                headers,
                block,
                offset=record_offset,
                end_offset=handle.tell(),
                warc_file=warc_file,
                compressed=False,
                uncompressed_offset=record_offset,
                block_start=block_start,
                block_end=block_start + length,
                compressed_offset=None,
            )


def _parse_member(data: bytes, logical: int, compressed_start: int, compressed_end: int, warc_file: str):
    first_end = data.find(b"\r\n")
    if first_end < 0 or data[:first_end] != b"WARC/1.0":
        raise WarcReadError(
            "E_MALFORMED_WARC", "gzip member does not start with WARC/1.0", offset=compressed_start
        )
    header_end = data.find(b"\r\n\r\n", first_end + 2)
    if header_end < 0:
        raise WarcReadError("E_MALFORMED_WARC", "truncated WARC header", offset=compressed_start)
    try:
        headers = parse_headers(data[first_end + 2 : header_end], strict_crlf=True)
    except HeaderError as exc:
        raise WarcReadError("E_MALFORMED_WARC", str(exc), offset=compressed_start) from exc
    length = _header_int(headers, "Content-Length", compressed_start)
    block_start = header_end + 4
    block = data[block_start : block_start + length]
    if len(block) != length:
        raise WarcReadError(
            "E_LENGTH_MISMATCH",
            "declared Content-Length does not match member bytes",
            offset=compressed_start,
            declared=length,
            actual=len(block),
        )
    block_end = block_start + length
    if data[block_end:].strip(b"\r\n"):
        raise WarcReadError(
            "E_MALFORMED_WARC", "gzip member contains more than one record", offset=compressed_start
        )
    return _make_record(
        headers,
        block,
        offset=compressed_start,
        end_offset=compressed_end,
        warc_file=warc_file,
        compressed=True,
        uncompressed_offset=logical,
        block_start=logical + block_start,
        block_end=logical + block_end,
        compressed_offset=compressed_start,
    )


def iter_records(
    path: Path | str,
    *,
    skip: int = 0,
    limit: int | None = None,
):
    """Yield records lazily.  ``skip`` and ``limit`` count records."""
    if limit is not None and limit <= 0:
        return
    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(path)
    warc_file = path.name
    with path.open("rb") as probe:
        is_gzip = probe.read(2) == GZIP_MAGIC
    if is_gzip:
        logical = 0
        seen = 0
        emitted = 0
        for start, data, end in iter_gzip_members(path):
            record = _parse_member(data, logical, start, end, warc_file)
            logical += len(data)
            seen += 1
            if seen <= skip:
                continue
            yield record
            emitted += 1
            if limit is not None and emitted >= limit:
                return
    else:
        seen = 0
        emitted = 0
        for record in _iter_plain(path, warc_file):
            seen += 1
            if seen <= skip:
                continue
            yield record
            emitted += 1
            if limit is not None and emitted >= limit:
                return


def read_archive(
    path: Path | str, *, skip: int = 0, limit: int | None = None
) -> ReadResult:
    """Read as much as possible, preserving successful records and the error."""
    result = ReadResult()
    try:
        for record in iter_records(path, skip=skip, limit=limit):
            result.records.append(record)
            if record.warc_type == "other":
                result.other_count += 1
    except WarcReadError as exc:
        result.errors.append(exc)
    return result
