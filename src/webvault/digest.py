"""Digest helpers.  WARC digests use unpadded, uppercase base32."""

from __future__ import annotations

import base64
import hashlib
from pathlib import Path
from typing import IO, Iterator

ALGORITHMS = ("sha256", "sha1")
DEFAULT_CHUNK_SIZE = 1024 * 1024


def _b32(raw: bytes) -> str:
    return base64.b32encode(raw).decode("ascii").rstrip("=")


def iter_file_chunks(handle: IO[bytes], chunk_size: int = DEFAULT_CHUNK_SIZE) -> Iterator[bytes]:
    """Yield fixed-size chunks from an open binary file (bounded memory)."""
    while True:
        chunk = handle.read(chunk_size)
        if not chunk:
            break
        yield chunk


def digest_from_hasher(hasher: "hashlib._Hash", algorithm: str = "sha256") -> str:
    """Format a streaming hasher's state as ``algorithm:BASE32`` (unpadded)."""
    algorithm = algorithm.lower()
    if algorithm not in ALGORITHMS:
        raise ValueError(f"unsupported digest algorithm: {algorithm}")
    return f"{algorithm}:{_b32(hasher.digest())}"


def digest_bytes(data: bytes, algorithm: str = "sha256") -> str:
    """Return ``algorithm:BASE32`` for *data*."""
    algorithm = algorithm.lower()
    try:
        h = hashlib.new(algorithm)
    except ValueError as exc:
        raise ValueError(f"unsupported digest algorithm: {algorithm}") from exc
    h.update(data)
    return f"{algorithm}:{_b32(h.digest())}"


def sha256_digest(data: bytes) -> str:
    return digest_bytes(data, "sha256")


def sha1_digest(data: bytes) -> str:
    return digest_bytes(data, "sha1")


def digest_payload(value: str) -> tuple[str, str]:
    """Split a digest header into (algorithm, base32) without padding."""
    if not isinstance(value, str) or ":" not in value:
        raise ValueError("malformed digest")
    algorithm, payload = value.split(":", 1)
    algorithm = algorithm.strip().lower()
    if algorithm not in ALGORITHMS or not payload.strip():
        raise ValueError("unsupported digest")
    normalized = payload.strip().upper().rstrip("=")
    if any(ch not in "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567" for ch in normalized):
        raise ValueError("digest is not base32")
    return algorithm, normalized


def digest_equal(left: str, right: str) -> bool:
    try:
        return digest_payload(left) == digest_payload(right)
    except ValueError:
        return False


def file_sha256(path: Path | str, chunk_size: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with Path(path).open("rb") as handle:
        while True:
            chunk = handle.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()
