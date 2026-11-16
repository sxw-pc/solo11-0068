import hashlib
import json
import tempfile
from pathlib import Path

import pytest

from webvault.cli import main


def _sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def test_demo_runs_full_pipeline_and_is_deterministic(tmp_path, capsys):
    first = tmp_path / "demo-one"
    second = tmp_path / "demo-two"
    assert main(["demo", "--out", str(first)]) == 0
    assert main(["demo", "--out", str(second)]) == 0
    for name in ("archive.warc.gz", "archive.cdx", "manifest.json"):
        assert _sha(first / name) == _sha(second / name)
    report = json.loads((first / "audit" / "audit-report.json").read_text(encoding="utf-8"))
    assert report["conclusion"] == "pass"
    expected = Path(__file__).resolve().parents[1] / "fixtures" / "expected"
    assert (first / "archive.cdx").read_bytes() == (expected / "archive.cdx").read_bytes()
    summary = json.loads((expected / "audit-summary.json").read_text(encoding="utf-8"))
    assert {key: report[key] for key in ("conclusion", "by_code", "records")} == {
        key: summary[key] for key in ("conclusion", "by_code", "records")
    }
    assert (first / "replay" / "sample" / "response.http").is_file()
    assert (first / "index.sqlite3").is_file()
    assert "demo complete" in capsys.readouterr().out


def test_build_import_replay_manifest_and_audit_commands(tmp_path, capsys):
    out = tmp_path / "build"
    root = Path(__file__).resolve().parents[1] / "fixtures" / "incoming"
    assert main(["import", "--incoming", str(root), "--out", str(tmp_path / "import.json")]) == 0
    assert main(["build", "--incoming", str(root), "--out", str(out), "--gzip"]) == 0
    assert (out / "archive.warc.gz").is_file()
    assert main(["manifest", "--archives", str(out), "--out", str(out / "manifest.json")]) == 0
    assert main(["audit", "--archives", str(out), "--db", str(out / "index.sqlite3")]) == 0
    report = json.loads((out / "audit-report.json").read_text(encoding="utf-8"))
    assert report["issues"] == []
    from webvault.index.sqlite_index import search_records

    rows, _ = search_records(out / "index.sqlite3", url="https://site-a.test/data.json")
    assert len(rows) == 1
    assert main(
        [
            "replay",
            "--archive",
            str(out / "archive.warc.gz"),
            "--offset",
            str(rows[0]["offset"]),
            "--out",
            str(tmp_path / "replay"),
        ]
    ) == 0
    assert (tmp_path / "replay" / "response.http").is_file()
    assert "webvault:" in capsys.readouterr().out


def test_cli_exit_codes_for_bad_input_audit_fail_and_diff_regression(tmp_path, drop_factory):
    make, root = drop_factory
    make("bad", url="not-a-url")
    assert main(["import", "--incoming", str(root)]) == 2
    assert main(["build", "--incoming", str(root), "--out", str(tmp_path / "out")]) == 2
    broken = Path(__file__).resolve().parents[1] / "fixtures" / "broken" / "bad_digest.warc"
    assert main(["audit", "--archives", str(broken), "--out", str(tmp_path / "audit")]) == 3
    before = tmp_path / "before.json"
    after = tmp_path / "after.json"
    record = {
        "urlkey": "https://(test,site-a)/x",
        "url": "https://site-a.test/x",
        "timestamp": "20240301090000",
        "digest": "sha256:A",
    }
    before.write_text(json.dumps({"format": "webvault-manifest/1", "records": [record]}), encoding="utf-8")
    after.write_text(json.dumps({"format": "webvault-manifest/1", "records": []}), encoding="utf-8")
    assert main(["diff", str(before), str(after), "--fail-on", "removed"]) == 3


def test_help_and_version_exit_zero(capsys):
    with pytest.raises(SystemExit) as help_exit:
        main(["--help"])
    assert help_exit.value.code == 0
    with pytest.raises(SystemExit) as version_exit:
        main(["--version"])
    assert version_exit.value.code == 0


def _make_large_drop(root: Path, name: str, url: str, body: bytes, redirect=None):
    directory = root / name
    directory.mkdir()
    meta = {
        "url": url,
        "fetched_at": "2024-03-01T09:00:00Z",
        "status": 301 if redirect else 200,
        "method": "GET",
        "headers": [["Content-Type", "text/html"]],
        "mime_type": "text/html",
        "body_file": "body.bin",
        "redirect_url": redirect,
        "note": None,
    }
    (directory / "meta.json").write_text(json.dumps(meta), encoding="utf-8")
    (directory / "body.bin").write_bytes(body)
    return directory


def test_build_streams_large_batch_and_publishes_atomically(tmp_path, capsys):
    """The build command runs the bounded pipeline end to end and indexes output."""
    incoming = tmp_path / "incoming"
    incoming.mkdir()
    # Directory order deliberately reversed vs. WARC urlkey order, with a redirect.
    _make_large_drop(
        incoming, "0003-zeta", "https://zeta.test/page", b"z" * 30000,
        redirect="https://zeta.test/landing",
    )
    _make_large_drop(incoming, "0002-mid", "https://mid.test/page", b"m" * 20000)
    _make_large_drop(incoming, "0001-alpha", "https://alpha.test/page", b"a" * 10000)
    out = tmp_path / "built"

    assert main(["build", "--incoming", str(incoming), "--out", str(out), "--gzip"]) == 0
    archive = out / "archive.warc.gz"
    assert archive.is_file()
    # Private spool/plan working trees are cleaned up after the build.
    leftovers = [p for p in Path(tempfile.gettempdir()).glob("webvault-ingest-*") if p.exists()]
    assert not leftovers

    from webvault.warc import read_archive

    records = read_archive(archive).records
    assert records[0].warc_type == "warcinfo"
    # 1 warcinfo + 3 responses + 1 redirect metadata
    assert b"records-expected: 5" in records[0].block
    responses = [r for r in records if r.warc_type == "response"]
    assert [r.target_uri for r in responses] == [
        "https://alpha.test/page",
        "https://mid.test/page",
        "https://zeta.test/page",
    ]
    # The archive feeds the existing CDX / SQLite pipeline unchanged.
    assert (out / "index.sqlite3").is_file()
    assert (out / "archive.cdx").is_file()
    from webvault.index.sqlite_index import search_records

    rows, _ = search_records(out / "index.sqlite3", url="https://zeta.test/page")
    assert len(rows) == 1


def test_build_oversize_record_keeps_previous_archive_untouched(tmp_path):
    incoming = tmp_path / "incoming"
    incoming.mkdir()
    _make_large_drop(incoming, "0001-small", "https://a.test/page", b"small")
    _make_large_drop(incoming, "0002-huge", "https://z.test/page", b"x" * 40000)
    out = tmp_path / "built"

    # A first successful build publishes a known-good archive.
    assert main(["build", "--incoming", str(incoming), "--out", str(out)]) == 0
    archive = out / "archive.warc"
    good_bytes = archive.read_bytes()

    # A second build with a limit the huge (last-sorted) record violates must
    # fail the whole batch and leave the published archive byte-identical.
    rc = main(
        [
            "build",
            "--incoming",
            str(incoming),
            "--out",
            str(out),
            "--max-record-bytes",
            "2048",
        ]
    )
    assert rc == 2
    assert archive.read_bytes() == good_bytes
    assert not (out / "archive.warc.tmp").exists()


def test_build_rejects_bad_drop_without_creating_archive(tmp_path):
    incoming = tmp_path / "incoming"
    incoming.mkdir()
    _make_large_drop(incoming, "0001-good", "https://a.test/page", b"good")
    bad = incoming / "0002-bad"
    bad.mkdir()
    (bad / "meta.json").write_text('{"url": "https://bad.test/x"}', encoding="utf-8")
    (bad / "body.bin").write_bytes(b"x")
    out = tmp_path / "built"

    assert main(["build", "--incoming", str(incoming), "--out", str(out)]) == 2
    assert not (out / "archive.warc").exists()
    assert not (out / "index.sqlite3").exists()
