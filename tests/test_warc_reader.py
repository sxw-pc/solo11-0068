from pathlib import Path

from webvault.model import RawRecord
from webvault.warc import read_archive, write_archive, write_raw_archive
from webvault.warc.gzip_reader import iter_gzip_members
from webvault.warc.reader import iter_records


def test_plain_and_gzip_offsets_point_back_to_records(tmp_path, captures):
    plain = tmp_path / "plain.warc"
    gz = tmp_path / "gzip.warc.gz"
    write_archive(captures, plain)
    write_archive(captures, gz, gzip_compress=True)
    plain_records = read_archive(plain).records
    gzip_records = read_archive(gz).records
    assert [r.warc_type for r in plain_records] == [r.warc_type for r in gzip_records]
    with plain.open("rb") as handle:
        for record in plain_records:
            if record.warc_type == "response":
                handle.seek(record.offset)
                assert handle.read(9) == b"WARC/1.0\r"
    for record, member in zip(gzip_records, iter_gzip_members(gz)):
        assert record.offset == member[0]
        assert record.compressed_offset == member[0]
        assert record.end_offset == member[2]
    assert gzip_records[-1].block_offset > gzip_records[0].block_offset


def test_unknown_warc_type_is_counted_as_other(tmp_path):
    response = RawRecord(
        "response",
        "<urn:uuid:11111111-1111-1111-1111-111111111111>",
        "2024-03-01T09:00:00Z",
        "https://site-a.test/x",
        "text/plain",
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
    )
    odd = RawRecord(
        "future-type",
        "<urn:uuid:22222222-2222-2222-2222-222222222222>",
        "2024-03-01T09:01:00Z",
        "https://site-a.test/y",
        "application/octet-stream",
        b"data",
    )
    archive = tmp_path / "archive.warc"
    write_raw_archive(archive, [response, odd])
    result = read_archive(archive)
    assert not result.errors
    assert result.other_count == 1
    assert result.records[-1].warc_type == "other"
    assert result.records[-1].raw_type == "future-type"


def test_length_mismatch_preserves_error_fields(tmp_path, captures):
    archive = tmp_path / "archive.warc"
    write_archive(captures, archive)
    data = archive.read_bytes()
    archive.write_bytes(data[:-9])
    result = read_archive(archive)
    assert result.records
    error = result.errors[0]
    assert error.code == "E_LENGTH_MISMATCH"
    assert error.declared > error.actual
    assert error.offset > 0


def test_gzip_corruption_is_partial_success(tmp_path, captures):
    archive = tmp_path / "archive.warc.gz"
    write_archive(captures, archive, gzip_compress=True)
    archive.write_bytes(archive.read_bytes()[:-12])
    result = read_archive(archive)
    assert result.records
    assert result.errors[0].code == "E_GZIP_CORRUPT"


def test_limit_and_skip_are_record_based(tmp_path, captures):
    archive = tmp_path / "archive.warc"
    write_archive(captures, archive)
    all_records = list(iter_records(archive))
    assert list(iter_records(archive, skip=2, limit=2)) == all_records[2:4]
    assert list(iter_records(archive, limit=0)) == []
    assert read_archive(archive, skip=1, limit=1).records == all_records[1:2]


def test_malformed_crlf_is_reported(tmp_path):
    archive = tmp_path / "bad.warc"
    archive.write_bytes(b"WARC/1.0\nWARC-Type: warcinfo\n\n")
    result = read_archive(archive)
    assert result.errors[0].code == "E_MALFORMED_WARC"
