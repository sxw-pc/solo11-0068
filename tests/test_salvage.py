"""Tests for the read-only ``salvage`` command (strategy B).

Five physical-damage fixtures are exercised:

1. a middle gzip member is destroyed while later members hold valid responses;
2. the archive tail is truncated inside the final member;
3. a gzip member header is corrupted;
4. a record header inside an otherwise valid member is corrupted;
5. duplicate record IDs and block-digest errors must never become evidence.

Every test re-asserts that the source bytes are untouched, the derived
archive passes the existing audit, retained responses replay byte-faithfully
from their new offsets, and the recovery report matches the output one to one.
"""

from __future__ import annotations

import gzip
import hashlib
import json
from pathlib import Path

import pytest

from webvault.audit import audit_archives
from webvault.cli import main
from webvault.index.cdx import cdx_path_for, read_cdx
from webvault.index.query import search_records
from webvault.model import RawRecord
from webvault.replay import replay_one
from webvault.salvage import REPORT_NAME, salvage_archive
from webvault.salvage.scanner import scan_archive
from webvault.warc import read_archive, write_raw_archive
from webvault.warc.gzip_reader import iter_gzip_members
from webvault.warc.writer import _gzip_member

from conftest import split_gzip_members


def _sha(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _member_payloads(path: Path) -> list[bytes]:
    return [data for _, data, _ in iter_gzip_members(path)]


def _deflate_span(span: tuple[int, int]) -> int:
    # The 10-byte gzip header (no extra/name/comment fields in these
    # fixtures) precedes the deflate stream; offset well inside it.
    return span[0] + 30


def _damage_middle_deflate(data: bytes, spans) -> bytes:
    # Flip a byte inside the middle member's deflate stream so its CRC
    # validation must fail; assert the member is genuinely unreadable.
    start, end = spans[2]
    position = _deflate_span(spans[2])
    assert start < position < end - 8
    broken = bytearray(data)
    broken[position] ^= 0xFF
    with pytest.raises(Exception):
        gzip.decompress(bytes(broken[start:end]))
    return bytes(broken)


def _damage_middle_gzip_header(data: bytes, spans) -> bytes:
    # Overwrite the gzip magic of the middle member so the scanner must
    # re-locate the next member by magic scanning.
    start, _ = spans[2]
    broken = bytearray(data)
    broken[start : start + 3] = b"XXX"
    return bytes(broken)


def _damage_warc_header_in_middle_member(data: bytes, spans) -> bytes:
    # The gzip framing stays CRC-valid; only the WARC header inside the
    # decompressed payload is destroyed, then the member is re-compressed.
    start, end = spans[2]
    payload = gzip.decompress(data[start:end])
    damaged = payload.replace(b"WARC/1.0\r\n", b"WARC/9.9\r\n", 1)
    rebuilt = _gzip_member(damaged)
    return data[:start] + rebuilt + data[end:]


def _duplicate_record_id_member(data: bytes, spans) -> bytes:
    # Copy the first response member's payload over the middle member after
    # rewriting nothing else: identical WARC-Record-ID, valid gzip/digest.
    first_start, first_end = spans[1]
    mid_start, mid_end = spans[2]
    payload = gzip.decompress(data[first_start:first_end])
    rebuilt = _gzip_member(payload)
    return data[:mid_start] + rebuilt + data[mid_end:]


def _bad_digest_member(data: bytes, spans) -> bytes:
    # Corrupt the WARC-Block-Digest header inside the middle member while
    # keeping its block bytes and gzip framing intact.
    start, end = spans[2]
    payload = gzip.decompress(data[start:end])
    marker = b"WARC-Block-Digest: sha256:"
    index = payload.find(marker) + len(marker)
    replacement = b"B" if payload[index : index + 1] != b"B" else b"C"
    damaged = payload[:index] + replacement + payload[index + 1 :]
    rebuilt = _gzip_member(damaged)
    return data[:start] + rebuilt + data[end:]


def _assert_source_untouched(path: Path, sha_before: str, cdx_before: bytes | None) -> None:
    assert _sha(path) == sha_before
    sibling = cdx_path_for(path)
    if cdx_before is not None:
        assert sibling.read_bytes() == cdx_before
    else:
        assert not sibling.exists()


def _assert_report_matches_output(result, out_dir: Path) -> dict:
    report = json.loads((out_dir / REPORT_NAME).read_text(encoding="utf-8"))
    assert report["format"] == "webvault-salvage/1"
    assert report["strategy"] == "B-member-relocation"
    derived = Path(result.archive)
    # One report row per retained record, aligned by record id and new offset.
    archived = {r.record_id: r for r in read_archive(derived).records}
    assert len(report["retained"]) == len(result.retained)
    for row, item in zip(report["retained"], result.retained):
        assert row["record_id"] == item.record_id
        assert row["source_offset"] == item.source_offset
        assert row["output_offset"] == item.output_offset
        assert archived[item.record_id].offset == item.output_offset
        assert row["output_file"] == derived.name
    # Every excluded row carries a physical source offset and a reason.
    for row in report["excluded"]:
        assert row["source_offset"] >= 0
        assert row["source_end_offset"] > row["source_offset"]
        assert row["code"] and row["reason"]
    return report


def _assert_each_response_replays(result, source_records) -> None:
    entries = read_cdx(result.cdx)
    assert entries, "derived CDX must index the recovered responses"
    rows, total = search_records(result.database)
    assert total == len(entries)
    source_by_id = {r.record_id: r for r in source_records}
    for entry in entries:
        assert entry.filename == result.archive.name
        item = replay_one(result.archive, entry.offset, result.out_dir / "check")
        record = item.record
        # New offset must resolve in the derived archive and the replayed
        # bytes must equal the original source response bytes.
        assert record.offset == entry.offset
        assert record.block == source_by_id[record.record_id].block
        assert item.bytes_written == len(record.block)


def _response_offsets(path: Path) -> list[int]:
    return [r.offset for r in read_archive(path).records if r.warc_type == "response"]


def test_middle_gzip_member_damaged_later_responses_recovered(tmp_path, broken_gzip_factory):
    build, spans, base = broken_gzip_factory
    base_response_offsets = _response_offsets(base)
    source = build("middle-damaged.warc.gz", mutate=_damage_middle_deflate)
    sha_before = _sha(source)
    result = salvage_archive(source, tmp_path / "out")
    assert result.ok
    # The damaged member carries one response; every other response survives.
    damaged_member_offset = spans[2][0]
    lost = 1 if damaged_member_offset in base_response_offsets else 0
    assert result.recovered_responses == len(base_response_offsets) - lost
    assert len(result.damage) == 1
    damage = result.damage[0]
    assert damage.start == damaged_member_offset
    assert damage.code == "E_GZIP_CORRUPT"
    # Non-contiguous source mapping: later retained offsets follow the gap.
    source_offsets = [item.source_offset for item in result.retained]
    assert source_offsets == sorted(source_offsets)
    assert damaged_member_offset not in source_offsets
    assert any(off > spans[2][1] for off in source_offsets)
    report = _assert_report_matches_output(result, tmp_path / "out")
    assert report["totals"]["damaged_spans"] == 1
    assert report["totals"]["unread_tail_bytes"] == 0
    assert report["unread_tail"] is None
    audit = audit_archives([result.archive], [result.cdx])
    assert audit.conclusion == "pass"
    scan = scan_archive(source)
    _assert_each_response_replays(result, [u.record for u in scan.units])
    _assert_source_untouched(source, sha_before, None)


def test_truncated_tail_is_reported_as_unread(tmp_path, broken_gzip_factory):
    build, spans, base = broken_gzip_factory
    base_response_offsets = _response_offsets(base)
    source = build("truncated.warc.gz", truncate=12)
    sha_before = _sha(source)
    result = salvage_archive(source, tmp_path / "out")
    assert result.ok
    # Only the final member is lost to the truncated tail.
    last_member_responses = 1 if spans[-1][0] in base_response_offsets else 0
    assert result.recovered_responses == len(base_response_offsets) - last_member_responses
    assert result.unread_tail is not None
    tail = result.unread_tail
    assert tail.end == source.stat().st_size
    assert tail.start < tail.end
    report = _assert_report_matches_output(result, tmp_path / "out")
    assert report["totals"]["unread_tail_bytes"] == tail.end - tail.start
    assert report["unread_tail"]["source_end_offset"] == source.stat().st_size
    assert audit_archives([result.archive], [result.cdx]).conclusion == "pass"
    _assert_source_untouched(source, sha_before, None)


def test_corrupt_gzip_member_header_resyncs_at_next_magic(tmp_path, broken_gzip_factory):
    build, spans, base = broken_gzip_factory
    base_response_offsets = _response_offsets(base)
    source = build("bad-gzip-header.warc.gz", mutate=_damage_middle_gzip_header)
    result = salvage_archive(source, tmp_path / "out")
    assert result.ok
    damaged_member_offset = spans[2][0]
    lost = 1 if damaged_member_offset in base_response_offsets else 0
    assert result.recovered_responses == len(base_response_offsets) - lost
    assert result.damage
    assert result.damage[0].start == damaged_member_offset
    # The damaged span ends exactly where the next valid member begins.
    next_member = spans[3][0]
    assert result.damage[0].end == next_member
    recovered_offsets = [item.source_offset for item in result.retained]
    assert next_member in recovered_offsets
    assert audit_archives([result.archive], [result.cdx]).conclusion == "pass"


def test_corrupt_warc_header_inside_valid_member_is_excluded(tmp_path, broken_gzip_factory):
    build, spans, base = broken_gzip_factory
    base_response_offsets = _response_offsets(base)
    source = build("bad-warc-header.warc.gz", mutate=_damage_warc_header_in_middle_member)
    result = salvage_archive(source, tmp_path / "out")
    assert result.ok
    # Gzip framing is fine for every member, so there is no gzip damage span;
    # the malformed WARC frame is rejected at its located member boundary but
    # member relocation still recovers the following response.
    assert result.damage == []
    assert len(result.rejected) == 1
    assert result.rejected[0].start == spans[2][0]
    assert result.rejected[0].code == "E_MALFORMED_WARC"
    excluded_codes = {row["code"] for row in json.loads(
        (result.report_path).read_text(encoding="utf-8")
    )["excluded"]}
    assert "E_MALFORMED_WARC" in excluded_codes
    lost = 1 if spans[2][0] in base_response_offsets else 0
    assert result.recovered_responses == len(base_response_offsets) - lost
    assert audit_archives([result.archive], [result.cdx]).conclusion == "pass"


def test_duplicate_record_id_is_excluded_not_indexed(tmp_path, broken_gzip_factory):
    build, spans, _ = broken_gzip_factory
    source = build("duplicate-id.warc.gz", mutate=_duplicate_record_id_member)
    result = salvage_archive(source, tmp_path / "out")
    assert result.ok
    dupes = [row for row in json.loads(result.report_path.read_text(encoding="utf-8"))["excluded"]
             if row["code"] == "E_DUP_RECORD_ID"]
    assert len(dupes) == 1
    assert dupes[0]["source_offset"] == spans[2][0]
    # The duplicate identity is absent from both the archive and the index.
    archived_ids = [r.record_id for r in read_archive(result.archive).records]
    assert len(archived_ids) == len(set(archived_ids))
    rows, _ = search_records(result.database)
    indexed_ids = {r.record_id for r in read_archive(result.archive).records
                   if r.warc_type == "response"}
    assert all(row["warc_file"] == result.archive.name for row in rows)
    assert len(rows) == result.recovered_responses
    assert indexed_ids
    assert audit_archives([result.archive], [result.cdx]).conclusion == "pass"


def test_block_digest_error_is_excluded_not_indexed(tmp_path, broken_gzip_factory):
    build, spans, _ = broken_gzip_factory
    source = build("bad-digest.warc.gz", mutate=_bad_digest_member)
    result = salvage_archive(source, tmp_path / "out")
    assert result.ok
    report = json.loads(result.report_path.read_text(encoding="utf-8"))
    digest_rows = [row for row in report["excluded"] if row["code"] == "E_DIGEST_MISMATCH"]
    assert len(digest_rows) == 1
    assert digest_rows[0]["source_offset"] == spans[2][0]
    # No retained record may carry a bad digest.
    for item in result.retained:
        record = next(u.record for u in scan_archive(source).units
                      if u.record.record_id == item.record_id)
        assert record.computed_digest == record.declared_digest
    assert audit_archives([result.archive], [result.cdx]).conclusion == "pass"


def test_salvage_is_deterministic_and_never_overwrites(tmp_path, broken_gzip_factory):
    build, _, base = broken_gzip_factory
    source = build("rerun.warc.gz", mutate=_damage_middle_deflate)
    sha_before = _sha(source)
    first = tmp_path / "one"
    second = tmp_path / "two"
    r1 = salvage_archive(source, first)
    r2 = salvage_archive(source, second)
    assert _sha(r1.archive) == _sha(r2.archive)
    assert _sha(r1.cdx) == _sha(r2.cdx)
    assert r1.report_path.read_bytes() == r2.report_path.read_bytes()
    # Source stays byte-identical and the derived file has a distinct name.
    assert _sha(source) == sha_before
    assert r1.archive.name != source.name


def test_salvage_refuses_a_derived_path_that_collides_with_source(tmp_path, broken_gzip_factory):
    from webvault.salvage.engine import derived_archive_path

    build, _, _ = broken_gzip_factory
    source = build("collide.warc.gz", mutate=_damage_middle_deflate)
    out = tmp_path / "collide"
    out.mkdir()
    # Force the derived path to resolve onto the source archive.
    derived_archive_path(source, out).symlink_to(source)
    with pytest.raises(ValueError):
        salvage_archive(source, out)
    # A failed run must not have truncated or replaced the source.
    assert source.is_file()


def test_salvage_cli_end_to_end_and_cdx_untouched(tmp_path, broken_gzip_factory):
    build, _, _ = broken_gzip_factory
    source = build("cli.warc.gz", mutate=_damage_middle_deflate)
    # Give the source a sibling CDX that must never be modified.
    source_cdx = cdx_path_for(source)
    source_cdx.write_text("canonical marker\n", encoding="utf-8")
    sha_before = _sha(source)
    cdx_before = source_cdx.read_bytes()
    out = tmp_path / "cli-out"
    assert main(["salvage", "--archive", str(source), "--out", str(out)]) == 0
    assert (out / "cli.salvaged.warc.gz").is_file()
    assert (out / "cli.salvaged.cdx").is_file()
    assert (out / "index.sqlite3").is_file()
    assert (out / REPORT_NAME).is_file()
    # A second run reproduces identical outputs.
    again = tmp_path / "cli-again"
    assert main(["salvage", "--archive", str(source), "--out", str(again)]) == 0
    assert _sha(again / "cli.salvaged.warc.gz") == _sha(out / "cli.salvaged.warc.gz")
    _assert_source_untouched(source, sha_before, cdx_before)


def test_salvage_cli_exit_2_when_nothing_survives(tmp_path, captures):
    # The only response gets a bad digest inside a CRC-valid member: no
    # evidence may be written.
    archive = tmp_path / "all-bad.warc.gz"
    write_raw_archive(
        archive,
        [
            RawRecord(
                "response",
                "<urn:uuid:deadbeef-dead-dead-dead-deaddeaddead>",
                "2024-03-01T09:00:00Z",
                "https://site-a.test/x",
                "text/plain",
                b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
            )
        ],
        gzip_compress=True,
    )
    data = archive.read_bytes()
    spans = split_gzip_members(data)
    start, end = spans[1]  # the single response member
    payload = gzip.decompress(data[start:end])
    marker = b"WARC-Block-Digest: sha256:"
    index = payload.find(marker) + len(marker)
    damaged = payload[:index] + b"Z" + payload[index + 1 :]
    archive.write_bytes(data[:start] + _gzip_member(damaged) + data[end:])
    out = tmp_path / "empty-out"
    assert main(["salvage", "--archive", str(archive), "--out", str(out)]) == 2
    assert not list(out.glob("*.warc*"))
    report = json.loads((out / REPORT_NAME).read_text(encoding="utf-8"))
    assert report["totals"]["records_recovered"] == 0
    assert any(row["code"] == "E_DIGEST_MISMATCH" for row in report["excluded"])


def test_plain_warc_resync_recovers_after_bad_frame(tmp_path, captures):
    from webvault.warc import write_archive

    plain = tmp_path / "plain.warc"
    write_archive(captures, plain)
    data = plain.read_bytes()
    markers = []
    pos = 0
    while True:
        found = data.find(b"WARC/1.0\r\n", pos)
        if found < 0:
            break
        markers.append(found)
        pos = found + 1
    # Corrupt the second record frame (first response); later frames stay valid.
    target = markers[1]
    broken = data[:target] + b"WARC/9.9\r\n" + data[target + 10:]
    plain.write_bytes(broken)
    result = salvage_archive(plain, tmp_path / "plain-out")
    assert result.ok
    assert not result.compressed
    # Frames after the malformed one are still recovered via marker resync.
    assert result.recovered_responses == 2
    report = json.loads(result.report_path.read_text(encoding="utf-8"))
    assert result.damage, "the destroyed frame must be reported as a damage span"
    assert report["totals"]["damaged_spans"] >= 1
    assert audit_archives([result.archive], [result.cdx]).conclusion == "pass"
