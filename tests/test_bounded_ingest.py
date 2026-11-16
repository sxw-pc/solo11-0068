"""Tests for the bounded-memory snapshot/plan/streaming-write pipeline.

These tests prove the properties the in-memory pipeline cannot give:

* the write plan is globally ordered *before* writing, even when directory
  order is the exact reverse and keys repeat (three fixtures, H1);
* peak resident response-body buffers stay bounded by the chunk size while
  batch total bytes grow without limit;
* the streaming archive is byte-identical to the legacy in-memory writer on
  the same captures, including redirect metadata and gzip members;
* an over-limit final record aborts atomically and preserves an existing
  target (no half-published WARC);
* snapshot semantics (H3 route A): replacing a source body after the snapshot
  pass does not change the archive -- the spooled bytes are authoritative and
  their digests are re-verified during streaming;
* any single validation error rejects the whole build without an archive;
* incoming source files are never modified.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from webvault.digest import sha256_digest
from webvault.ingest import build_ingest_plan, open_temp_plan_dir
from webvault.model import CaptureRecord
from webvault.warc import (
    RecordTooLargeError,
    WarcSourceChangedError,
    read_archive,
    write_archive,
    write_archive_plan,
)
from webvault.warc.headers import build_http_block

CHUNK = 4096


def _make_drop(root: Path, name: str, *, url: str, timestamp: str, body: bytes,
               redirect_url=None, note=None) -> Path:
    directory = root / name
    directory.mkdir()
    meta = {
        "url": url,
        "fetched_at": timestamp,
        "status": 301 if redirect_url else 200,
        "method": "GET",
        "headers": [["Content-Type", "text/html"]],
        "mime_type": "text/html",
        "body_file": "body.bin",
        "redirect_url": redirect_url,
        "note": note,
    }
    (directory / "meta.json").write_text(
        json.dumps(meta, sort_keys=True, indent=2) + "\n", encoding="utf-8"
    )
    (directory / "body.bin").write_bytes(body)
    return directory


def _build(root: Path, tmp_path: Path, **kwargs):
    workdir = open_temp_plan_dir()
    plan = build_ingest_plan(root, workdir, chunk_size=CHUNK)
    assert plan.ok, plan.errors
    out = tmp_path / "archive.warc"
    result = write_archive_plan(plan, out, chunk_size=CHUNK, **kwargs)
    plan.cleanup()
    return out, result


# --- H1: three reverse-order / duplicate-key / redirect fixtures -------------

def test_plan_orders_reverse_directory_with_duplicate_keys(tmp_path):
    """Directory order is the reverse of the global WARC order."""
    root = tmp_path / "incoming"
    root.mkdir()
    # Directory order: z..., m..., a... -- reverse host order.
    _make_drop(root, "0003-zeta", url="https://zeta.test/x",
               timestamp="2024-03-01T09:00:00Z", body=b"zeta")
    _make_drop(root, "0002-mid", url="https://mid.test/x",
               timestamp="2024-03-01T09:00:00Z", body=b"mid")
    _make_drop(root, "0001-alpha", url="https://alpha.test/x",
               timestamp="2024-03-01T09:00:00Z", body=b"alpha")
    workdir = open_temp_plan_dir()
    plan = build_ingest_plan(root, workdir, chunk_size=CHUNK)
    try:
        ordered = [p.url for p in plan.iter_ordered()]
        assert ordered == [
            "https://alpha.test/x",
            "https://mid.test/x",
            "https://zeta.test/x",
        ]
    finally:
        plan.cleanup()


def test_plan_orders_duplicate_url_timestamp_by_digest(tmp_path):
    """Same urlkey + timestamp: digest (body content) breaks the tie."""
    root = tmp_path / "incoming"
    root.mkdir()
    same_url = "https://dup.test/page"
    same_ts = "2024-03-01T09:00:00Z"
    # Bodies chosen so digest order differs from directory order.
    _make_drop(root, "c-third", url=same_url, timestamp=same_ts, body=b"ccc")
    _make_drop(root, "a-first", url=same_url, timestamp=same_ts, body=b"aaa")
    _make_drop(root, "b-second", url=same_url, timestamp=same_ts, body=b"bbb")
    workdir = open_temp_plan_dir()
    plan = build_ingest_plan(root, workdir, chunk_size=CHUNK)
    try:
        ordered = list(plan.iter_ordered())
        # The tie-break is the base32 WARC digest string, not the source name;
        # derive the expected order instead of assuming alphabetical bodies.
        bodies = {"a-first": b"aaa", "b-second": b"bbb", "c-third": b"ccc"}
        expected_sources = [
            source
            for source, _ in sorted(
                bodies.items(), key=lambda item: sha256_digest(item[1])
            )
        ]
        assert [p.source for p in ordered] == expected_sources
        assert [p.body_digest for p in ordered] == [
            sha256_digest(bodies[source]) for source in expected_sources
        ]
    finally:
        plan.cleanup()


def test_plan_keeps_redirect_metadata_beside_its_response(tmp_path):
    """Redirect captures emit a metadata record right after their response."""
    root = tmp_path / "incoming"
    root.mkdir()
    _make_drop(root, "0003-redirect", url="https://z.test/r",
               timestamp="2024-03-01T09:00:00Z", body=b"go",
               redirect_url="https://z.test/landing", note="moved")
    _make_drop(root, "0002-plain", url="https://m.test/p",
               timestamp="2024-03-01T09:00:00Z", body=b"mid")
    _make_drop(root, "0001-redirect-two", url="https://a.test/r",
               timestamp="2024-03-01T09:00:00Z", body=b"go2",
               redirect_url="https://a.test/landing")
    archive, written = _build(root, tmp_path)
    # 1 warcinfo + 3 responses + 2 metadata
    assert written.records == 6
    assert written.responses == 3

    records = read_archive(archive).records
    types = [r.warc_type for r in records]
    assert types == [
        "warcinfo",
        "response",   # a.test/r
        "metadata",   # its redirect
        "response",   # m.test/p
        "response",   # z.test/r
        "metadata",   # its redirect
    ]
    # The metadata record refers to the immediately preceding response ID.
    assert records[2].refers_to == records[1].record_id
    assert records[5].refers_to == records[4].record_id
    assert b'"outlink":"https://a.test/landing"' in records[2].block
    assert b'"note":"moved"' in records[5].block


# --- bounded memory -----------------------------------------------------------

class _ChunkBoundedFile:
    """File wrapper recording the largest single read ever issued."""

    def __init__(self, handle):
        self._handle = handle
        self.max_read = 0
        self.total_read = 0

    def read(self, size=-1):
        if size is not None and size >= 0:
            self.max_read = max(self.max_read, size)
        chunk = self._handle.read(size)
        self.total_read += len(chunk)
        return chunk

    def __getattr__(self, name):
        return getattr(self._handle, name)

    def __enter__(self):
        self._handle.__enter__()
        return self

    def __exit__(self, *exc):
        return self._handle.__exit__(*exc)


class _BoundedPlan:
    """Wrap a plan so every spool open is observed for read sizing."""

    def __init__(self, plan):
        self._plan = plan
        self.wrappers: list[_ChunkBoundedFile] = []

    def iter_ordered(self, page_size=128):
        return self._plan.iter_ordered(page_size=page_size)

    def open_spool(self, planned):
        wrapper = _ChunkBoundedFile(self._plan.open_spool(planned))
        self.wrappers.append(wrapper)
        return wrapper


def test_peak_body_memory_is_independent_of_batch_size(tmp_path):
    """Many multi-chunk bodies: no read exceeds the chunk buffer."""
    root = tmp_path / "incoming"
    root.mkdir()
    records = 24
    body_size = CHUNK * 8  # each body is eight chunks; total batch ~ 768 KiB
    for index in range(records):
        _make_drop(
            root,
            f"drop-{index:03d}",
            url=f"https://host-{index:02d}.test/page",
            timestamp="2024-03-01T09:00:00Z",
            body=bytes([index % 256]) * body_size,
        )

    workdir = open_temp_plan_dir()
    plan = build_ingest_plan(root, workdir, chunk_size=CHUNK)
    try:
        assert plan.count() == records
        bounded = _BoundedPlan(plan)
        archive = tmp_path / "big.warc"
        write_archive_plan(bounded, archive, chunk_size=CHUNK, page_size=4)

        # Every response body was streamed in chunk-sized reads only: the
        # pipeline can never hold more than one chunk per open body, no matter
        # how large the batch total grows.
        assert len(bounded.wrappers) == records
        assert all(wrapper.max_read <= CHUNK for wrapper in bounded.wrappers)
        assert sum(wrapper.total_read for wrapper in bounded.wrappers) == (
            records * body_size
        )
        assert archive.is_file()
    finally:
        plan.cleanup()


def test_snapshot_pass_reads_bodies_in_bounded_chunks(tmp_path, monkeypatch):
    """The first (spool) pass also streams bodies without whole-file reads."""
    root = tmp_path / "incoming"
    root.mkdir()
    records = 12
    body_size = CHUNK * 6
    for index in range(records):
        _make_drop(
            root,
            f"drop-{index:03d}",
            url=f"https://host-{index:02d}.test/page",
            timestamp="2024-03-01T09:00:00Z",
            body=bytes([index]) * body_size,
        )

    observed: list[int] = []
    real_open = Path.open

    def tracking_open(self, mode="r", *args, **kwargs):
        handle = real_open(self, mode, *args, **kwargs)
        if "b" in mode and self.name == "body.bin":
            real_read = handle.read

            def tracked_read(size=-1):
                if size is not None and size >= 0:
                    observed.append(size)
                return real_read(size)

            handle.read = tracked_read
        return handle

    monkeypatch.setattr(Path, "open", tracking_open)
    workdir = open_temp_plan_dir()
    plan = build_ingest_plan(root, workdir, chunk_size=CHUNK)
    try:
        assert plan.count() == records
        assert observed, "snapshot pass never issued chunked body reads"
        assert max(observed) <= CHUNK
    finally:
        plan.cleanup()


# --- byte identity with the legacy writer ------------------------------------

def _drop_to_capture(directory: Path) -> CaptureRecord:
    meta = json.loads((directory / "meta.json").read_text(encoding="utf-8"))
    body = (directory / "body.bin").read_bytes()
    return CaptureRecord(
        url=meta["url"],
        timestamp=meta["fetched_at"],
        status=meta["status"],
        method=meta["method"],
        headers=tuple(tuple(pair) for pair in meta["headers"]),
        mime_type=meta["mime_type"],
        body=body,
        source=directory.name,
        redirect_url=meta["redirect_url"],
        note=meta["note"],
    )


@pytest.mark.parametrize("gzip", [False, True])
def test_streaming_output_is_byte_identical_to_legacy_writer(tmp_path, gzip):
    root = tmp_path / "incoming"
    root.mkdir()
    _make_drop(root, "0003-z", url="https://z.test/x",
               timestamp="2024-03-01T09:03:00Z", body=b"zebra" * 50,
               redirect_url="https://z.test/end")
    _make_drop(root, "0002-m", url="https://m.test/x",
               timestamp="2024-03-01T09:02:00Z", body=b"mid" * 80)
    _make_drop(root, "0001-a", url="https://a.test/x",
               timestamp="2024-03-01T09:01:00Z", body=b"alpha" * 70)
    captures = [_drop_to_capture(p) for p in sorted(root.iterdir())]

    legacy = tmp_path / ("legacy.warc.gz" if gzip else "legacy.warc")
    streamed = tmp_path / ("streamed.warc.gz" if gzip else "streamed.warc")
    write_archive(captures, legacy, gzip_compress=gzip)

    workdir = open_temp_plan_dir()
    plan = build_ingest_plan(root, workdir, chunk_size=CHUNK)
    try:
        write_archive_plan(plan, streamed, gzip_compress=gzip, chunk_size=CHUNK)
    finally:
        plan.cleanup()
    assert streamed.read_bytes() == legacy.read_bytes()


def test_block_digest_covers_exact_http_block(tmp_path):
    """The planner's stored block digest equals the writer's HTTP block."""
    root = tmp_path / "incoming"
    root.mkdir()
    body = b"verify-block-bytes\n" * 100
    _make_drop(root, "0001-only", url="https://a.test/x",
               timestamp="2024-03-01T09:00:00Z", body=body)
    workdir = open_temp_plan_dir()
    plan = build_ingest_plan(root, workdir, chunk_size=CHUNK)
    try:
        planned = next(plan.iter_ordered())
        capture = _drop_to_capture(root / "0001-only")
        expected_block = build_http_block(capture.status, capture.headers, capture.body)
        assert planned.block_digest == sha256_digest(expected_block)
        assert planned.block_length == len(expected_block)
    finally:
        plan.cleanup()


# --- atomic failure: over-limit record last ----------------------------------

def test_oversize_final_record_preserves_existing_target(tmp_path):
    root = tmp_path / "incoming"
    root.mkdir()
    _make_drop(root, "0001-small", url="https://a.test/x",
               timestamp="2024-03-01T09:00:00Z", body=b"small")
    # The over-limit capture sorts last (host z), so failure happens at the end.
    _make_drop(root, "0002-huge", url="https://z.test/x",
               timestamp="2024-03-01T09:00:00Z", body=b"x" * 4096)

    target = tmp_path / "archive.warc"
    target.write_bytes(b"PREVIOUS ARCHIVE BYTES")
    before = target.read_bytes()

    workdir = open_temp_plan_dir()
    plan = build_ingest_plan(root, workdir, chunk_size=CHUNK)
    try:
        with pytest.raises(RecordTooLargeError) as excinfo:
            # Above the ~200-byte warcinfo/small-response payloads, below the
            # 4 KiB response that sorts last.
            write_archive_plan(plan, target, max_record_bytes=512, chunk_size=CHUNK)
        assert excinfo.value.record_type == "response"
    finally:
        plan.cleanup()

    assert target.read_bytes() == before
    assert not (tmp_path / "archive.warc.tmp").exists()


def test_warcinfo_size_limit_still_enforced_before_writing(tmp_path):
    root = tmp_path / "incoming"
    root.mkdir()
    _make_drop(root, "0001-only", url="https://a.test/x",
               timestamp="2024-03-01T09:00:00Z", body=b"x")
    workdir = open_temp_plan_dir()
    plan = build_ingest_plan(root, workdir, chunk_size=CHUNK)
    try:
        target = tmp_path / "archive.warc"
        with pytest.raises(RecordTooLargeError):
            write_archive_plan(plan, target, max_record_bytes=10, chunk_size=CHUNK)
        assert not target.exists()
        assert not (tmp_path / "archive.warc.tmp").exists()
    finally:
        plan.cleanup()


# --- H3 route A: snapshot semantics -------------------------------------------

def test_source_body_replaced_after_snapshot_uses_spooled_bytes(tmp_path):
    root = tmp_path / "incoming"
    root.mkdir()
    directory = _make_drop(root, "0001-only", url="https://a.test/x",
                           timestamp="2024-03-01T09:00:00Z", body=b"original bytes")
    original_meta = (directory / "meta.json").read_bytes()
    original_body = (directory / "body.bin").read_bytes()

    workdir = open_temp_plan_dir()
    plan = build_ingest_plan(root, workdir, chunk_size=CHUNK)
    try:
        # Consuming the plan proves the snapshot pass has fully completed.
        assert plan.count() == 1
        # Mutate the incoming tree *after* the snapshot pass but before write.
        (directory / "body.bin").write_bytes(b"tampered replacement bytes!!")
        archive = tmp_path / "snapshot.warc"
        write_archive_plan(plan, archive, chunk_size=CHUNK)
    finally:
        plan.cleanup()

    data = archive.read_bytes()
    assert b"original bytes" in data
    assert b"tampered replacement bytes" not in data
    # The incoming directory must remain exactly as the operator left it.
    assert (directory / "body.bin").read_bytes() == b"tampered replacement bytes!!"
    assert (directory / "meta.json").read_bytes() == original_meta
    assert original_body == b"original bytes"


def test_tampered_spool_is_detected_and_fails_atomically(tmp_path):
    """Corrupting the private spool itself trips the write-time digest check."""
    root = tmp_path / "incoming"
    root.mkdir()
    _make_drop(root, "0001-only", url="https://a.test/x",
               timestamp="2024-03-01T09:00:00Z", body=b"spooled once")
    workdir = open_temp_plan_dir()
    plan = build_ingest_plan(root, workdir, chunk_size=CHUNK)
    target = tmp_path / "archive.warc"
    target.write_bytes(b"KEEP ME")
    try:
        spool_files = list(plan.spool_dir.glob("*.bin"))
        assert len(spool_files) == 1
        spool_files[0].write_bytes(b"spool corruption")
        with pytest.raises(WarcSourceChangedError):
            write_archive_plan(plan, target, chunk_size=CHUNK)
        assert target.read_bytes() == b"KEEP ME"
        assert not (tmp_path / "archive.warc.tmp").exists()
    finally:
        plan.cleanup()


# --- strict validation: one bad drop rejects the whole build ------------------

def test_validation_error_rejects_whole_batch_without_archive(tmp_path):
    root = tmp_path / "incoming"
    root.mkdir()
    _make_drop(root, "0001-good", url="https://a.test/x",
               timestamp="2024-03-01T09:00:00Z", body=b"good")
    bad = root / "0002-bad"
    bad.mkdir()
    # JSON parses, but required fields are absent: strict per-drop rejection.
    (bad / "meta.json").write_text('{"url": "https://bad.test/x"}', encoding="utf-8")
    (bad / "body.bin").write_bytes(b"x")

    workdir = open_temp_plan_dir()
    plan = build_ingest_plan(root, workdir, chunk_size=CHUNK)
    try:
        assert not plan.ok
        assert plan.errors[0].source == "0002-bad"
        assert plan.errors[0].code == "E_MISSING_FIELD"
        # No write happens; nothing is published.
        target = tmp_path / "archive.warc"
        assert not target.exists()
    finally:
        plan.cleanup()


def test_incoming_files_are_not_modified_by_build(tmp_path):
    root = tmp_path / "incoming"
    root.mkdir()
    _make_drop(root, "0001-only", url="https://a.test/x",
               timestamp="2024-03-01T09:00:00Z", body=b"do not touch")
    fingerprints = {
        path: (path.stat().st_size, hashlib.sha256(path.read_bytes()).hexdigest())
        for path in root.rglob("*")
        if path.is_file()
    }
    _build(root, tmp_path)
    for path, fingerprint in fingerprints.items():
        assert path.is_file()
        assert (path.stat().st_size, hashlib.sha256(path.read_bytes()).hexdigest()) == fingerprint
