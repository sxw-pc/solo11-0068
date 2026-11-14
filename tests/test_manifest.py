import json

from webvault.manifest import (
    build_manifest,
    diff_manifests,
    load_manifest,
    merge_archives,
    write_manifest,
)
from webvault.model import CaptureRecord
from webvault.warc import read_archive, write_archive


def capture(url, timestamp, body):
    return CaptureRecord(
        url=url,
        timestamp=timestamp,
        status=200,
        method="GET",
        headers=(("Content-Type", "text/plain"), ("Content-Length", str(len(body)))),
        mime_type="text/plain",
        body=body,
    )


def test_manifest_totals_distributions_and_determinism(tmp_path):
    a = tmp_path / "a.warc"
    b = tmp_path / "b.warc"
    write_archive(
        [
            capture("https://site-a.test/x", "2024-03-01T09:00:00Z", b"one"),
            capture("https://site-a.test/y", "2024-03-01T09:01:00Z", b"two"),
        ],
        a,
    )
    write_archive(
        [capture("https://site-a.test/x", "2024-03-01T08:00:00Z", b"one")],
        b,
    )
    manifest = build_manifest([a, b])
    assert manifest["totals"]["archives"] == 2
    assert manifest["totals"]["records"] == 5
    assert manifest["totals"]["responses"] == 3
    assert manifest["totals"]["unique_urlkey_digest"] == 2
    assert manifest["mimetypes"] == {"text/plain": 3}
    assert manifest["statuses"] == {"200": 3}
    first = tmp_path / "one.json"
    second = tmp_path / "two.json"
    write_manifest(first, manifest)
    write_manifest(second, build_manifest([b, a]))
    assert first.read_bytes() == second.read_bytes()
    assert load_manifest(first)["format"] == "webvault-manifest/1"


def test_merge_deduplicates_by_urlkey_digest_earliest_wins(tmp_path):
    a = tmp_path / "a.warc"
    b = tmp_path / "b.warc"
    write_archive(
        [
            capture("https://site-a.test/x", "2024-03-01T09:00:00Z", b"one"),
            capture("https://site-a.test/y", "2024-03-01T09:01:00Z", b"two"),
        ],
        a,
    )
    write_archive([capture("https://site-a.test/x", "2024-03-01T08:00:00Z", b"one")], b)
    merged = tmp_path / "merged.warc"
    report_path = tmp_path / "merge-report.json"
    result = merge_archives([a, b], merged, report_path)
    assert result.kept == 2 and result.dropped == 1
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["dropped"][0]["source"] == "a.warc"
    responses = [r for r in read_archive(merged).records if r.warc_type == "response"]
    x_record = next(r for r in responses if r.target_uri.endswith("/x"))
    assert x_record.date == "2024-03-01T08:00:00Z"
    again = tmp_path / "again.warc"
    merge_archives([a, b], again)
    assert merged.read_bytes() == again.read_bytes()


def test_manifest_diff_added_removed_changed(tmp_path):
    before_archive = tmp_path / "before.warc"
    after_archive = tmp_path / "after.warc"
    write_archive(
        [
            capture("https://site-a.test/x", "2024-03-01T09:00:00Z", b"one"),
            capture("https://site-a.test/y", "2024-03-01T09:01:00Z", b"two"),
        ],
        before_archive,
    )
    write_archive(
        [
            capture("https://site-a.test/x", "2024-03-01T09:00:00Z", b"changed"),
            capture("https://site-a.test/z", "2024-03-01T09:02:00Z", b"three"),
        ],
        after_archive,
    )
    diff = diff_manifests(build_manifest([before_archive]), build_manifest([after_archive]))
    assert diff["counts"] == {"added": 1, "removed": 1, "changed": 1}
    assert diff["changed"][0]["timestamp"] == "20240301090000"
    assert diff["added"][0]["url"].endswith("/z")
    assert diff["removed"][0]["url"].endswith("/y")
