"""Bounded-memory ingest planner.

Two-pass capture-drop pipeline with a private on-disk spool:

1. *snapshot pass* -- each capture directory is validated without reading its
   body into memory; the body is copied in fixed-size chunks to a private
   spool file while streaming digests are computed for both the raw body
   (the sort key / record identity) and the HTTP block that will actually be
   written.  Normalised metadata plus the global sort key land in a temporary
   SQLite database; only one body chunk is resident at a time.
2. *plan pass* -- SQLite returns the rows pre-sorted by the same global key
   ``(urlkey, timestamp, digest, source)`` the in-memory writer uses, paged so
   the plan itself never materialises the batch.  The WARC writer reopens the
   spool entry, re-streams it and verifies the digests, proving the bytes used
   for ordering are the bytes emitted.

Snapshot semantics (H3 route A): once the snapshot pass completes, output is
built strictly from spooled bytes captured at import time; later replacement
of a source body file cannot alter the archive and never pairs an old sort
key with new bytes.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import sqlite3
import tempfile
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType
from typing import Iterator

from ..digest import DEFAULT_CHUNK_SIZE, digest_from_hasher
from ..model import IngestError, capture_record_id, metadata_record_id
from ..urlnorm import urlkey
from ..warc.headers import http_block_head
from .validate import (
    CaptureMeta,
    IngestValidationError,
    iter_body_chunks,
    parse_capture_meta,
)


@dataclass(frozen=True)
class PlannedRecord:
    """One row of the ordered write plan; never carries body bytes."""

    seq: int
    url: str
    urlkey_value: str
    timestamp: str
    status: int
    method: str
    headers_json: str
    mime_type: str
    source: str
    redirect_url: str | None
    note: str | None
    body_file: str
    spool_name: str
    body_length: int
    body_digest: str
    block_digest: str
    block_length: int
    record_id: str
    metadata_id: str

    @property
    def headers(self) -> tuple[tuple[str, str], ...]:
        return tuple((name, value) for name, value in json.loads(self.headers_json))


_SCHEMA = """
CREATE TABLE captures (
    seq INTEGER PRIMARY KEY,
    url TEXT NOT NULL,
    urlkey_value TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    status INTEGER NOT NULL,
    method TEXT NOT NULL,
    headers_json TEXT NOT NULL,
    mime_type TEXT NOT NULL,
    source TEXT NOT NULL,
    redirect_url TEXT,
    note TEXT,
    body_file TEXT NOT NULL,
    spool_name TEXT NOT NULL,
    body_length INTEGER NOT NULL,
    body_digest TEXT NOT NULL,
    block_digest TEXT NOT NULL,
    block_length INTEGER NOT NULL,
    record_id TEXT NOT NULL,
    metadata_id TEXT NOT NULL
)
"""

_ORDERED_COLUMNS = (
    "seq, url, urlkey_value, timestamp, status, method, headers_json, "
    "mime_type, source, redirect_url, note, body_file, spool_name, "
    "body_length, body_digest, block_digest, block_length, record_id, metadata_id"
)


def _http_head(meta: CaptureMeta, body_length: int) -> bytes:
    return http_block_head(meta.status, meta.headers, body_length)


class IngestPlan:
    """Managed snapshot: SQLite plan database plus a private spool directory."""

    def __init__(self, workdir: Path, chunk_size: int = DEFAULT_CHUNK_SIZE):
        self._workdir = workdir
        self.chunk_size = chunk_size
        self.spool_dir = workdir / "spool"
        self.spool_dir.mkdir(parents=True, exist_ok=True)
        self._db_path = workdir / "plan.sqlite3"
        self.connection = sqlite3.connect(str(self._db_path))
        self.connection.execute("PRAGMA journal_mode = MEMORY")
        self.connection.execute("PRAGMA synchronous = OFF")
        self.connection.execute(_SCHEMA)
        self.errors: list[IngestError] = []
        self._closed = False

    @property
    def ok(self) -> bool:
        return not self.errors

    def count(self) -> int:
        row = self.connection.execute("SELECT COUNT(*) FROM captures").fetchone()
        return int(row[0])

    def iter_ordered(self, page_size: int = 128) -> Iterator[PlannedRecord]:
        """Yield the plan in the global WARC order, one page at a time."""
        offset = 0
        while True:
            rows = self.connection.execute(
                f"SELECT {_ORDERED_COLUMNS} FROM captures "
                "ORDER BY urlkey_value, timestamp, body_digest, source LIMIT ? OFFSET ?",
                (page_size, offset),
            ).fetchall()
            if not rows:
                break
            for row in rows:
                yield PlannedRecord(*row)
            offset += len(rows)
            if len(rows) < page_size:
                break

    def open_spool(self, planned: PlannedRecord):
        return (self.spool_dir / planned.spool_name).open("rb")

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self.connection.close()

    def cleanup(self) -> None:
        self.close()
        # The whole working tree is private and disposable.
        shutil.rmtree(self._workdir, ignore_errors=True)

    def __enter__(self) -> "IngestPlan":
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.cleanup()


def _spool_one(meta: CaptureMeta, spool_path: Path, chunk_size: int) -> tuple[int, str, str, int]:
    """Copy one body to the private spool in bounded chunks, streaming digests.

    Returns ``(body_length, body_digest, block_digest, block_length)`` where
    the block digest covers the exact HTTP block the writer will emit, so the
    write pass can prove byte identity without materialising the block.
    """
    body_hasher = hashlib.sha256()
    body_length = 0

    with spool_path.open("wb") as spool:
        for chunk in iter_body_chunks(meta, chunk_size):
            spool.write(chunk)
            body_hasher.update(chunk)
            body_length += len(chunk)

    head = _http_head(meta, body_length)
    block_hasher = hashlib.sha256()
    block_hasher.update(head)
    with spool_path.open("rb") as handle:
        while True:
            chunk = handle.read(chunk_size)
            if not chunk:
                break
            block_hasher.update(chunk)
    block_length = len(head) + body_length
    return (
        body_length,
        digest_from_hasher(body_hasher),
        digest_from_hasher(block_hasher),
        block_length,
    )


def build_ingest_plan(
    root: Path | str,
    workdir: Path | str,
    *,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> IngestPlan:
    """Snapshot and index an incoming batch with bounded resident body bytes.

    Validation errors use the same strict per-drop semantics as
    :func:`webvault.ingest.loader.load_incoming`; the returned plan's
    :attr:`IngestPlan.ok` must be checked before any archive is written.
    """
    root = Path(root)
    if not root.is_dir():
        raise FileNotFoundError(f"incoming directory not found: {root}")
    workdir = Path(workdir)
    workdir.mkdir(parents=True, exist_ok=True)
    plan = IngestPlan(workdir, chunk_size=chunk_size)
    errors: list[IngestError] = []
    rows: list[tuple] = []
    try:
        record_dirs = sorted(
            (p for p in root.iterdir() if p.is_dir()), key=lambda p: p.name
        )
        for seq, record_dir in enumerate(record_dirs):
            source = record_dir.name
            try:
                meta = parse_capture_meta(record_dir, source)
                spool_name = f"body-{seq:08d}.bin"
                spool_path = plan.spool_dir / spool_name
                body_length, body_digest, block_digest, block_length = _spool_one(
                    meta, spool_path, chunk_size
                )
            except IngestValidationError as exc:
                errors.append(IngestError(source, exc.code, exc.detail))
                continue
            except OSError as exc:
                errors.append(IngestError(source, "E_IO", str(exc)))
                continue

            record_id = capture_record_id(meta.url, meta.timestamp, body_digest)
            metadata_id = metadata_record_id(meta.url, meta.timestamp, body_digest)
            rows.append(
                (
                    seq,
                    meta.url,
                    urlkey(meta.url),
                    meta.timestamp,
                    meta.status,
                    meta.method,
                    json.dumps(list(meta.headers), ensure_ascii=True),
                    meta.mime_type,
                    meta.source,
                    meta.redirect_url,
                    meta.note,
                    meta.body_file,
                    spool_name,
                    body_length,
                    body_digest,
                    block_digest,
                    block_length,
                    record_id,
                    metadata_id,
                )
            )
        errors.sort(key=lambda e: (e.source, e.code, e.detail))
        plan.errors = errors
        plan.connection.executemany(
            f"INSERT INTO captures ({_ORDERED_COLUMNS}) "
            f"VALUES ({', '.join('?' for _ in _ORDERED_COLUMNS.split(', '))})",
            rows,
        )
        plan.connection.commit()
        return plan
    except BaseException:
        plan.cleanup()
        raise


def open_temp_plan_dir(prefix: str = "webvault-ingest-") -> Path:
    """Create a private temporary working tree for a snapshot pass."""
    return Path(tempfile.mkdtemp(prefix=prefix))
