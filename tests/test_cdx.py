import pytest

from webvault.index.cdx import (
    cdx_path_for,
    dedupe_and_sort,
    entries_from_records,
    read_cdx,
    write_cdx,
)
from webvault.model import CdxEntry
from webvault.warc import read_archive, write_archive


def entry(urlkey="https://(test,site-a)/a", timestamp="20240301090000", digest="sha256:A", offset=10):
    return CdxEntry(
        urlkey, timestamp, "https://site-a.test/a", "text/html", 200, digest, "", offset, "x.warc"
    )


def test_cdx_line_format_and_redirect_dash():
    text = entry().line()
    assert text.endswith("\n") and "\r" not in text
    fields = text.split(" ")
    assert len(fields) == 9
    assert fields[6] == "-"
    parsed = CdxEntry.parse_line(text)
    assert parsed.offset == 10
    assert parsed.redirect == ""


def test_sort_and_dedupe_keep_smallest_offset():
    rows = [
        entry(urlkey="https://(test,site-b)/a", offset=30),
        entry(offset=20),
        entry(offset=5),
        entry(timestamp="20240301080000", offset=2),
    ]
    result = dedupe_and_sort(rows)
    assert [row.offset for row in result] == [2, 5, 30]
    with pytest.raises(ValueError):
        CdxEntry.parse_line("too few fields\n")


def test_entries_from_archive_include_query_order_and_redirect(tmp_path, captures):
    archive = tmp_path / "archive.warc.gz"
    write_archive(captures, archive, gzip_compress=True)
    records = read_archive(archive).records
    entries = entries_from_records(records, archive.name)
    assert len(entries) == 3
    assert all(not entry.urlkey.startswith("urn:") for entry in entries)
    redirect = next(item for item in entries if item.status == 301)
    assert redirect.redirect == "https://site-c.test/landing"
    assert redirect.filename == "archive.warc.gz"
    assert entries == sorted(entries, key=lambda item: item.sort_key())


def test_cdx_write_read_roundtrip_is_lf(tmp_path):
    rows = [entry(urlkey=f"https://(test,site-a)/{number}", offset=number) for number in range(5)]
    path = tmp_path / "set.cdx"
    write_cdx(path, rows)
    raw = path.read_bytes()
    assert b"\r\n" not in raw and raw.count(b"\n") == 5
    loaded = read_cdx(path)
    assert loaded == sorted(rows, key=lambda item: item.sort_key())
    assert cdx_path_for("archive.warc.gz").name == "archive.cdx"


def test_cdx_rejects_bad_timestamp(tmp_path):
    path = tmp_path / "bad.cdx"
    path.write_text(entry(timestamp="2024").line(), encoding="utf-8")
    with pytest.raises(ValueError):
        read_cdx(path)
