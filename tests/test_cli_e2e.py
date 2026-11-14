import hashlib
import json
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
