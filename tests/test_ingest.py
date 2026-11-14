import json

from webvault.ingest import load_incoming


def test_load_valid_drops_and_preserve_header_order(drop_factory):
    make, root = drop_factory
    make(
        "0002-b",
        url="https://site-a.test/b",
        fetched_at="2024-03-01T09:02:00Z",
        headers=(("X-First", "1"), ("Content-Type", "text/html")),
    )
    make("0001-a", url="https://site-a.test/a", fetched_at="2024-03-01T09:01:00Z")
    result = load_incoming(root)
    assert not result.errors
    assert [record.url for record in result.records] == [
        "https://site-a.test/a",
        "https://site-a.test/b",
    ]
    assert result.records[1].headers[0] == ("X-First", "1")
    assert result.records[0].digest.startswith("sha256:")
    assert result.records[0].record_id.startswith("<urn:uuid:")


def test_bad_drop_does_not_block_the_batch(drop_factory):
    make, root = drop_factory
    make("0001-good")
    make("0002-bad-url", url="not-a-url")
    make("0003-bad-time", fetched_at="yesterday")
    make("0004-no-body", body_file="missing.bin")
    meta = {"url": "https://site-a.test/x"}
    bad = root / "0005-missing-fields"
    bad.mkdir()
    (bad / "meta.json").write_text(json.dumps(meta), encoding="utf-8")
    result = load_incoming(root)
    assert len(result.records) == 1
    codes = {error.code for error in result.errors}
    assert codes == {"E_BAD_URL", "E_BAD_TIMESTAMP", "E_BODY_NOT_FOUND", "E_MISSING_FIELD"}
    assert {error.source for error in result.errors} == {
        "0002-bad-url",
        "0003-bad-time",
        "0004-no-body",
        "0005-missing-fields",
    }


def test_bad_json_and_body_path_escape(drop_factory):
    make, root = drop_factory
    broken = root / "0001-json"
    broken.mkdir()
    (broken / "meta.json").write_text("{nope", encoding="utf-8")
    make("0002-escape", body_file="../outside.bin")
    (root.parent / "outside.bin").write_bytes(b"do not read")
    result = load_incoming(root)
    codes = {error.code for error in result.errors}
    assert "E_BAD_JSON" in codes
    assert "E_BAD_BODY_PATH" in codes


def test_headers_file_fallback(drop_factory):
    make, root = drop_factory
    directory = make("0001-fallback")
    meta = json.loads((directory / "meta.json").read_text(encoding="utf-8"))
    meta.pop("headers")
    (directory / "meta.json").write_text(json.dumps(meta), encoding="utf-8")
    (directory / "headers.txt").write_bytes(
        b"X-From-File: yes\r\nContent-Type: text/plain\r\n\r\n"
    )
    result = load_incoming(root)
    assert not result.errors
    assert result.records[0].headers[0] == ("X-From-File", "yes")
