"""Read independent gzip members while tracking compressed offsets."""

from __future__ import annotations

import zlib
from pathlib import Path

from .errors import WarcReadError

GZIP_MAGIC = b"\x1f\x8b"


def _skip_cstring(handle) -> None:
    while True:
        char = handle.read(1)
        if not char:
            raise EOFError
        if char == b"\x00":
            return


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
            crc = int.from_bytes(trailer[:4], "big")
            size = int.from_bytes(trailer[4:], "little")
            if crc != (zlib.crc32(output) & 0xFFFFFFFF) or size != (len(output) & 0xFFFFFFFF):
                raise WarcReadError("E_GZIP_CORRUPT", "gzip CRC/size mismatch", offset=start)
            yield start, bytes(output), handle.tell()
