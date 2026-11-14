from pathlib import Path

from webvault.audit import audit_archives, render_json, render_markdown, write_reports
from webvault.index.cdx import entries_from_records, write_cdx
from webvault.model import RawRecord
from webvault.warc import read_archive, write_archive, write_raw_archive


def codes(report):
    return {issue.code for issue in report.issues}


def test_clean_archive_passes_and_reports_are_deterministic(tmp_path, captures):
    archive = tmp_path / "archive.warc.gz"
    write_archive(captures, archive, gzip_compress=True)
    entries = entries_from_records(read_archive(archive).records, archive.name)
    cdx = tmp_path / "archive.cdx"
    write_cdx(cdx, entries)
    report = audit_archives([archive], [cdx])
    assert report.conclusion == "pass"
    assert not report.issues
    assert render_json(report) == render_json(audit_archives([archive], [cdx]))
    assert "**pass**" in render_markdown(report)
    first, second = write_reports(report, tmp_path / "reports")
    assert first.read_text(encoding="utf-8") == render_json(report)
    assert second.read_text(encoding="utf-8") == render_markdown(report)


def test_missing_cdx_is_a_fatal_integrity_issue(tmp_path, captures):
    archive = tmp_path / "archive.warc"
    write_archive(captures, archive)
    report = audit_archives([archive])
    assert report.conclusion == "fail"
    assert "E_MISSING_CDX" in codes(report)


def test_digest_flip_and_truncation_are_detected(tmp_path, captures):
    archive = tmp_path / "archive.warc"
    write_archive(captures, archive)
    data = archive.read_bytes()
    index = data.find(b"WARC-Block-Digest: sha256:") + len(b"WARC-Block-Digest: sha256:")
    bad = tmp_path / "bad_digest.warc"
    bad.write_bytes(data[:index] + b"B" + data[index + 1 :])
    assert "E_DIGEST_MISMATCH" in codes(audit_archives([bad]))
    truncated = tmp_path / "truncated.warc"
    truncated.write_bytes(data[:-10])
    assert "E_LENGTH_MISMATCH" in codes(audit_archives([truncated]))


def test_no_warcinfo_and_duplicate_record_id(tmp_path):
    response = RawRecord(
        "response",
        "<urn:uuid:aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa>",
        "2024-03-01T09:00:00Z",
        "https://site-a.test/x",
        "text/plain",
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
    )
    archive = tmp_path / "duplicate.warc"
    write_raw_archive(archive, [response, response])
    report = audit_archives([archive])
    assert "E_DUP_RECORD_ID" in codes(report)
    second = archive.read_bytes().find(b"WARC/1.0\r\n", 10)
    no_info = tmp_path / "no_warcinfo.warc"
    no_info.write_bytes(archive.read_bytes()[second:])
    assert "E_NO_WARCINFO" in codes(audit_archives([no_info]))


def test_offset_drift_orphan_and_malformed_cdx(tmp_path, captures):
    archive = tmp_path / "archive.warc"
    write_archive(captures, archive)
    entries = entries_from_records(read_archive(archive).records, archive.name)
    entries[0] = entries[0].__class__(
        entries[0].urlkey,
        entries[0].timestamp,
        entries[0].original,
        entries[0].mimetype,
        entries[0].status,
        entries[0].digest,
        entries[0].redirect,
        entries[1].offset,
        entries[0].filename,
    )
    drift = tmp_path / "archive.cdx"
    write_cdx(drift, entries)
    assert "E_OFFSET_DRIFT" in codes(audit_archives([archive], [drift]))
    orphan = tmp_path / "orphan.cdx"
    orphan.write_text(entries[0].line().replace("archive.warc", "missing.warc"), encoding="utf-8")
    assert "E_ORPHAN_CDX" in codes(audit_archives([archive], [orphan]))
    malformed = tmp_path / "malformed.cdx"
    malformed.write_text("broken\n", encoding="utf-8")
    assert "E_MALFORMED_CDX" in codes(audit_archives([archive], [malformed]))


def test_bad_target_is_warning_and_report_has_three_levels(tmp_path):
    weird = RawRecord(
        "response",
        "<urn:uuid:bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb>",
        "2024-03-01T09:00:00Z",
        "not a URL",
        "text/plain",
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
    )
    archive = tmp_path / "warning.warc"
    write_raw_archive(archive, [weird])
    report = audit_archives([archive])
    assert report.conclusion == "warn"
    assert report.warn_count == 1
    assert report.to_dict()["by_code"] == {"E_BAD_TARGET_URI": 1}
