"""Resilient physical scanners used by the read-only salvage command.

Two layouts are handled, both with physical offset bookkeeping:

* multi-member gzip: every member is located through its own gzip header and
  independently CRC-validated; after a damaged span the scan resumes at the
  next gzip magic (option B -- member relocation, not blind retry);
* plain WARC: frames start at a ``WARC/1.0`` marker; after a malformed frame
  the scan re-synchronises on the next marker.

The scanner never raises for corrupt input.  Anything that cannot be parsed
into a record is reported as a damage span or unread tail so the recovery
report can account for every source byte.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from ..model import WarcRecord
from ..warc.errors import WarcReadError
from ..warc.gzip_reader import GZIP_MAGIC, GzipDamageEvent, scan_gzip_members
from ..warc.headers import HeaderError, parse_headers
from ..warc.reader import _header_int, _make_record, _parse_member

# A frame must begin with this exact marker (including its CRLF).
_WARC_MARKER = b"WARC/1.0\r\n"


@dataclass(frozen=True)
class SalvageUnit:
    """One physically located, fully parsed WARC record candidate."""

    record: WarcRecord
    # Logical (uncompressed) offset of the record inside the concatenated
    # gzip payload stream; identical to the physical offset for plain files.
    logical_offset: int
    logical_end: int


@dataclass(frozen=True)
class SalvageDamage:
    """Source bytes that could not be attributed to any member or frame."""

    start: int
    end: int
    code: str
    detail: str


@dataclass(frozen=True)
class RejectedFrame:
    """A located member/frame whose WARC record could not be parsed.

    The physical boundary is known (a CRC-valid gzip member, or a
    ``WARC/1.0`` marker span), so the bytes are accounted for even though no
    record identity can be recovered.
    """

    start: int
    end: int
    code: str
    detail: str


@dataclass
class ScanResult:
    units: list[SalvageUnit] = field(default_factory=list)
    damage: list[SalvageDamage] = field(default_factory=list)
    rejected: list[RejectedFrame] = field(default_factory=list)
    compressed: bool = False
    file_size: int = 0

    def unread_tail(self) -> SalvageDamage | None:
        """The uncovered suffix after the last located byte span."""
        covered = 0
        for unit in self.units:
            covered = max(covered, unit.record.end_offset)
        for event in list(self.damage) + list(self.rejected):
            covered = max(covered, event.end)
        if covered < self.file_size:
            # If no structure at all was found, keep the opening failure code.
            if not self.units and self.damage:
                first = self.damage[0]
                return SalvageDamage(
                    covered,
                    self.file_size,
                    first.code,
                    first.detail,
                )
            return SalvageDamage(
                covered,
                self.file_size,
                "E_UNREAD_TAIL",
                "trailing bytes not covered by any record or member",
            )
        return None


def scan_gzip(path: Path) -> ScanResult:
    """Isolate each gzip member, then parse at most one WARC record per
    validated member, proving member boundary, WARC offset and identity."""
    result = ScanResult(compressed=True, file_size=path.stat().st_size)
    logical = 0
    for event in scan_gzip_members(path):
        if isinstance(event, GzipDamageEvent):
            result.damage.append(SalvageDamage(event.start, event.end, event.code, event.detail))
            continue
        try:
            record = _parse_member(
                event.data,
                logical,
                event.start,
                event.end,
                path.name,
            )
        except Exception as exc:  # a valid gzip member may hold a malformed record
            code = getattr(exc, "code", "E_MALFORMED_WARC")
            detail = getattr(exc, "detail", str(exc))
            result.rejected.append(RejectedFrame(event.start, event.end, code, detail))
        else:
            result.units.append(
                SalvageUnit(
                    record=record,
                    logical_offset=logical,
                    logical_end=logical + len(event.data),
                )
            )
        logical += len(event.data)
    return result


def _parse_plain_frame(data: bytes, offset: int, warc_file: str) -> tuple[WarcRecord, int]:
    """Parse one plain WARC frame at ``offset``; return record and end offset."""
    if not data.startswith(_WARC_MARKER, offset):
        raise ValueError("frame does not start with WARC/1.0")
    header_end = data.find(b"\r\n\r\n", offset + len(_WARC_MARKER))
    if header_end < 0:
        raise ValueError("truncated WARC header")
    try:
        headers = parse_headers(
            data[offset + len(_WARC_MARKER) : header_end], strict_crlf=True
        )
    except HeaderError as exc:
        raise WarcReadError("E_MALFORMED_WARC", str(exc), offset=offset) from exc
    length = _header_int(headers, "Content-Length", offset)
    block_start = header_end + 4
    block = data[block_start : block_start + length]
    if len(block) != length:
        raise WarcReadError(
            "E_LENGTH_MISMATCH",
            "declared Content-Length does not match available bytes",
            offset=offset,
            declared=length,
            actual=len(block),
        )
    block_end = block_start + length
    cursor = block_end
    while data[cursor : cursor + 2] == b"\r\n" and cursor < len(data):
        cursor += 2
    record = _make_record(
        headers,
        block,
        offset=offset,
        end_offset=cursor,
        warc_file=warc_file,
        compressed=False,
        uncompressed_offset=offset,
        block_start=block_start,
        block_end=block_end,
        compressed_offset=None,
    )
    return record, cursor


def scan_plain(path: Path) -> ScanResult:
    """Scan a plain WARC, resynchronising on the next frame marker after
    every malformed frame."""
    data = path.read_bytes()
    result = ScanResult(compressed=False, file_size=len(data))
    position = 0
    while position < len(data):
        if data[position:position + 2] == b"\r\n":
            position += 2
            continue
        marker = data.find(_WARC_MARKER, position)
        if marker < 0:
            result.damage.append(
                SalvageDamage(
                    position,
                    len(data),
                    "E_MALFORMED_WARC",
                    "no further WARC/1.0 frame; unread tail",
                )
            )
            return result
        if marker > position:
            result.damage.append(
                SalvageDamage(
                    position,
                    marker,
                    "E_MALFORMED_WARC",
                    "bytes outside any WARC frame",
                )
            )
            position = marker
        try:
            record, end = _parse_plain_frame(data, position, path.name)
        except Exception as exc:
            code = getattr(exc, "code", "E_MALFORMED_WARC")
            detail = getattr(exc, "detail", str(exc))
            resume = data.find(_WARC_MARKER, position + len(_WARC_MARKER))
            span_end = resume if resume >= 0 else len(data)
            result.rejected.append(RejectedFrame(position, span_end, code, detail))
            position = span_end
            continue
        result.units.append(
            SalvageUnit(record=record, logical_offset=position, logical_end=end)
        )
        position = end
    return result


def scan_archive(path: Path | str) -> ScanResult:
    """Dispatch on the gzip magic; the source file is only ever read."""
    path = Path(path)
    with path.open("rb") as probe:
        is_gzip = probe.read(2) == GZIP_MAGIC
    return scan_gzip(path) if is_gzip else scan_plain(path)
