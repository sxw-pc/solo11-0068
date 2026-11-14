import pytest

from webvault.digest import sha256_digest
from webvault.model import RawRecord
from webvault.warc import RecordTooLargeError, read_archive, write_archive
from webvault.warc.gzip_reader import iter_gzip_members
from webvault.warc.writer import serialize_raw


def test_warcinfo_and_response_headers_are_deterministic(tmp_path, captures):
    first = tmp_path / "a.warc"
    second = tmp_path / "b.warc"
    write_archive(captures, first)
    write_archive(captures, second)
    assert first.read_bytes() == second.read_bytes()
    result = read_archive(first)
    assert not result.errors
    assert result.records[0].warc_type == "warcinfo"
    assert result.records[0].content_type == "application/warc-fields"
    assert b"software: webvault/" in result.records[0].block
    assert b"records-expected: 5" in result.records[0].block
    responses = [r for r in result.records if r.warc_type == "response"]
    assert [r.target_uri for r in responses] == sorted(r.target_uri for r in responses)


def test_content_length_counts_only_the_block(tmp_path, captures):
    archive = tmp_path / "archive.warc"
    write_archive(captures, archive)
    raw = archive.read_bytes()
    header, block = raw.split(b"\r\n\r\n", 1)
    record = read_archive(archive).records[0]
    assert f"Content-Length: {len(record.block)}".encode() in header
    assert block.startswith(record.block)


def test_gzip_is_one_deterministic_member_per_record(tmp_path, captures):
    archive = tmp_path / "archive.warc.gz"
    write_archive(captures, archive, gzip_compress=True)
    data = archive.read_bytes()
    assert data[:10] == b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff"
    members = list(iter_gzip_members(archive))
    assert len(members) == 5
    assert all(member[1].startswith(b"WARC/1.0\r\n") for member in members)
    assert len({record.record_id for record in read_archive(archive).records}) == 5


def test_redirect_writes_metadata_with_outlink(tmp_path, captures):
    archive = tmp_path / "archive.warc"
    write_archive(captures, archive)
    metadata = [r for r in read_archive(archive).records if r.warc_type == "metadata"]
    assert len(metadata) == 1
    assert b'"outlink":"https://site-c.test/landing"' in metadata[0].block
    assert metadata[0].refers_to.startswith("<urn:uuid:")


def test_record_limit_rejects_without_leaving_a_file(tmp_path, captures):
    archive = tmp_path / "archive.warc"
    with pytest.raises(RecordTooLargeError):
        write_archive(captures, archive, max_record_bytes=128)
    assert not archive.exists()
    assert not (tmp_path / "archive.warc.tmp").exists()


def test_raw_record_serialization_uses_crlf_and_digest():
    record = RawRecord(
        "response",
        "<urn:uuid:00000000-0000-0000-0000-000000000000>",
        "2024-03-01T09:00:00Z",
        "https://site-a.test/x",
        "text/plain",
        b"hello",
    )
    payload = serialize_raw(record)
    assert b"\n" not in payload.replace(b"\r\n", b"")
    assert f"WARC-Block-Digest: {sha256_digest(b'hello')}".encode() in payload
    assert b"Content-Length: 5\r\n\r\nhello\r\n\r\n" in payload
