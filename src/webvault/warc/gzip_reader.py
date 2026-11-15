"""Read independent gzip members while tracking compressed offsets.

The original :func:`iter_gzip_members` keeps its strict contract: the first
member that fails header/deflate/CRC validation terminates iteration with an
:class:`E_GZIP_CORRUPT` error.  Salvage recovery additionally uses
:func:`scan_gzip_members`, which isolates every member on its own physical
boundary and resumes at the next gzip magic after a damaged span instead of
blindly continuing inside the broken member.
"""

from __future__ import annotations

import zlib
from dataclasses import dataclass
from pathlib import Path

from .errors import WarcReadError

GZIP_MAGIC = b"\x1f\x8b"
_CHUNK = 65536


def _skip_cstring(handle) -> None:
    while True:
        char = handle.read(1)
        if not char:
            raise EOFError
        if char == b"\x00":
            return


def _find_next_magic(handle, position: int) -> int | None:
    """Locate the next gzip magic at or after ``position`` without loading
    the whole archive; a magic split across two read chunks is still found."""
    handle.seek(position)
    carried = b""
    while True:
        chunk = handle.read(_CHUNK)
        if not chunk:
            return None
        index = (carried + chunk).find(GZIP_MAGIC)
        if index >= 0:
            return position + index - len(carried)
        carried = chunk[-1:]


def read_gzip_member(handle, start: int) -> tuple[bytes, int]:
    """Read one gzip member beginning at ``start`` and return
    ``(decompressed_bytes, end_offset)``.

    Raises :class:`WarcReadError` for any structural or checksum failure,
    leaving the handle position unspecified (callers re-seek explicitly).
    """
    handle.seek(start)
    header = handle.read(10)
    if len(header) < 10 or header[:2] != GZIP_MAGIC or header[2] != 8:
        raise WarcReadError("E_GZIP_CORRUPT", "invalid gzip member header", offset=start)
    flags = header[3]
    if flags & 0xE0:
        raise WarcReadError("E_GZIP_CORRUPT", "reserved gzip flags set", offset=start)
    try:
        if flags & 0x04:
            extra_len = int.from_bytes(handle.read(2), "little")
            handle.read(extra_len)
        if flags & 0x08:
            _skip_cstring(handle)
        if flags & 0x10:
            _skip_cstring(handle)
        if flags & 0x02:
            handle.read(2)
    except EOFError as exc:
        raise WarcReadError(
            "E_GZIP_CORRUPT", "truncated gzip header", offset=start
        ) from exc
    decompressor = zlib.decompressobj(-15)
    output = bytearray()
    try:
        while not decompressor.eof:
            chunk = handle.read(65536)
            if not chunk:
                raise WarcReadError(
                    "E_GZIP_CORRUPT", "truncated deflate stream", offset=start
                )
            output.extend(decompressor.decompress(chunk))
            if decompressor.eof and decompressor.unused_data:
                handle.seek(-len(decompressor.unused_data), 1)
    except zlib.error as exc:
        raise WarcReadError(
            "E_GZIP_CORRUPT", f"invalid deflate stream: {exc}", offset=start
        ) from exc
    trailer = handle.read(8)
    if len(trailer) != 8:
        raise WarcReadError("E_GZIP_CORRUPT", "truncated gzip trailer", offset=start)
    # RFC 1952 stores CRC32 and ISIZE little-endian; older webvault archives
    # wrote the CRC big-endian, so both known-good encodings are accepted.
    size = int.from_bytes(trailer[4:], "little")
    crc_raw = trailer[:4]
    actual_crc = zlib.crc32(output) & 0xFFFFFFFF
    valid_le = crc_raw == actual_crc.to_bytes(4, "little")
    valid_be = crc_raw == actual_crc.to_bytes(4, "big")
    if not (valid_le or valid_be) or size != (len(output) & 0xFFFFFFFF):
        raise WarcReadError("E_GZIP_CORRUPT", "gzip CRC/size mismatch", offset=start)
    return bytes(output), handle.tell()


def iter_gzip_members(path: Path):
    """Yield (compressed_start, member_bytes, compressed_end), validating CRCs."""
    with path.open("rb") as handle:
        if handle.read(2) != GZIP_MAGIC:
            raise WarcReadError("E_GZIP_CORRUPT", "not a gzip stream", offset=0)
        handle.seek(0)
        while True:
            start = handle.tell()
            header = handle.read(10)
            if not header:
                return
            if len(header) < 10 or header[:2] != GZIP_MAGIC or header[2] != 8:
                raise WarcReadError("E_GZIP_CORRUPT", "invalid gzip member header", offset=start)
            flags = header[3]
            if flags & 0xE0:
                raise WarcReadError("E_GZIP_CORRUPT", "reserved gzip flags set", offset=start)
            try:
                if flags & 0x04:
                    extra_len = int.from_bytes(handle.read(2), "little")
                    handle.read(extra_len)
                if flags & 0x08:
                    _skip_cstring(handle)
                if flags & 0x10:
                    _skip_cstring(handle)
                if flags & 0x02:
                    handle.read(2)
            except EOFError as exc:
                raise WarcReadError(
                    "E_GZIP_CORRUPT", "truncated gzip header", offset=start
                ) from exc
            decompressor = zlib.decompressobj(-15)
            output = bytearray()
            try:
                while not decompressor.eof:
                    chunk = handle.read(65536)
                    if not chunk:
                        raise WarcReadError(
                            "E_GZIP_CORRUPT", "truncated deflate stream", offset=start
                        )
                    output.extend(decompressor.decompress(chunk))
                    if decompressor.eof and decompressor.unused_data:
                        handle.seek(-len(decompressor.unused_data), 1)
            except zlib.error as exc:
                raise WarcReadError(
                    "E_GZIP_CORRUPT", f"invalid deflate stream: {exc}", offset=start
                ) from exc
            trailer = handle.read(8)
            if len(trailer) != 8:
                raise WarcReadError("E_GZIP_CORRUPT", "truncated gzip trailer", offset=start)
            size = int.from_bytes(trailer[4:], "little")
            actual_crc = zlib.crc32(output) & 0xFFFFFFFF
            valid_le = trailer[:4] == actual_crc.to_bytes(4, "little")
            valid_be = trailer[:4] == actual_crc.to_bytes(4, "big")
            if not (valid_le or valid_be) or size != (len(output) & 0xFFFFFFFF):
                raise WarcReadError("E_GZIP_CORRUPT", "gzip CRC/size mismatch", offset=start)
            yield start, bytes(output), handle.tell()


@dataclass(frozen=True)
class GzipMemberEvent:
    """A gzip member that passed full header, deflate and CRC validation."""

    start: int
    end: int
    data: bytes


@dataclass(frozen=True)
class GzipDamageEvent:
    """A physical byte span that could not be attributed to a valid member."""

    start: int
    end: int
    code: str
    detail: str

    @property
    def length(self) -> int:
        return self.end - self.start


def scan_gzip_members(path: Path):
    """Yield :class:`GzipMemberEvent` and :class:`GzipDamageEvent` in
    physical order, never raising for member-level corruption.

    Every valid member is isolated on its own boundaries via its gzip header
    and verified with the same CRC/size rules as :func:`iter_gzip_members`.
    After a damaged span the stream is re-synchronised by scanning for the
    next gzip magic rather than retrying the failed bytes, so a later intact
    member can still be recovered with a provable offset mapping.
    """
    path = Path(path)
    file_size = path.stat().st_size
    with path.open("rb") as handle:
        if handle.read(2) != GZIP_MAGIC:
            yield GzipDamageEvent(0, file_size, "E_GZIP_CORRUPT", "not a gzip stream")
            return
        position = 0
        members_seen = 0
        while position < file_size:
            start = position
            try:
                data, end = read_gzip_member(handle, start)
            except WarcReadError as exc:
                resume = _find_next_magic(handle, start + 2)
                if resume is None:
                    if members_seen == 0:
                        # No valid member exists anywhere: surface the
                        # structural failure instead of a generic tail note.
                        yield GzipDamageEvent(
                            start,
                            file_size,
                            exc.code,
                            f"{exc.detail}; no further gzip member",
                        )
                    # Otherwise the surviving prefix is already emitted and
                    # the remaining bytes are reported as the unread tail.
                    return
                yield GzipDamageEvent(start, resume, exc.code, exc.detail)
                position = resume
                continue
            yield GzipMemberEvent(start=start, end=end, data=data)
            members_seen += 1
            position = end
