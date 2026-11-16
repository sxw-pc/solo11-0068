import hashlib
import json
import sqlite3
from pathlib import Path

import pytest

from webvault.index.sqlite_index import build_archive_data, create_database, write_archive_index
from webvault.ingest import load_incoming
from webvault.model import RawRecord
from webvault.replay import (
    ReplayError,
    replay_chain,
    replay_one,
    replay_query,
)
from webvault.warc import write_archive, write_raw_archive
from webvault.warc.headers import build_http_block, split_http_block


def test_single_replay_is_byte_faithful(tmp_path, captures, built):
    record = next(r for r in built["data"].records if r.warc_type == "response")
    item = replay_one(built["archive"], record.offset, tmp_path / "out")
    assert item.output.name == "response.http"
    assert item.output.read_bytes() == record.block
    _, _, body = split_http_block(record.block)
    original = next(capture for capture in captures if capture.url == record.target_uri)
    assert hashlib.sha256(body).digest() == hashlib.sha256(original.body).digest()


def test_replay_rejects_warcinfo_and_bad_offset(tmp_path, built):
    warcinfo = built["data"].records[0]
    with pytest.raises(ReplayError) as error:
        replay_one(built["archive"], warcinfo.offset, tmp_path / "out")
    assert error.value.code == "E_NOT_RESPONSE"
    with pytest.raises(ReplayError) as error:
        replay_one(built["archive"], -1, tmp_path / "out")
    assert error.value.code == "E_OFFSET_NOT_FOUND"


def test_batch_replay_manifest_and_url_hash_directory(tmp_path, built):
    url = "https://site-a.test/index.html"
    items, manifest_path = replay_query(built["db"], tmp_path / "batch", url=url)
    assert len(items) == 1
    expected_name = hashlib.sha256(url.encode()).hexdigest()[:16]
    assert items[0].output.parent.name == expected_name
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["format"] == "webvault-replay/1"
    assert manifest["records"][0]["output"] == f"{expected_name}/response.http"
    assert manifest["failures"] == []
    assert manifest_path.read_bytes() == replay_query(
        built["db"], tmp_path / "batch", url=url
    )[1].read_bytes()


# ---------------------------------------------------------------------------
# Chain replay helpers
# ---------------------------------------------------------------------------


def _raw_response(record_id, date, url, status, headers, body):
    return RawRecord(
        "response",
        record_id,
        date,
        url,
        "text/html",
        build_http_block(status, headers, body),
    )


def _chain_fixture(tmp_path, records):
    """Write one archive holding *records* and index it into SQLite."""
    archive = tmp_path / "chain.warc"
    write_raw_archive(archive, records)
    data = build_archive_data(archive)
    write_archive_index(data)
    db_path = create_database(tmp_path / "chain.sqlite3", [data])
    return archive, db_path, data


@pytest.fixture
def fixture_chain(tmp_path):
    """Build the repository's incoming fixtures (which keep a raw Location)."""
    incoming = Path(__file__).resolve().parents[1] / "fixtures" / "incoming"
    loaded = load_incoming(incoming)
    assert not loaded.errors
    archive = tmp_path / "fixtures.warc.gz"
    write_archive(loaded.records, archive, gzip_compress=True)
    data = build_archive_data(archive)
    write_archive_index(data)
    db_path = create_database(tmp_path / "fixtures.sqlite3", [data])
    return {"archive": archive, "db": db_path, "data": data}


def _read_manifest(path):
    return json.loads(path.read_text(encoding="utf-8"))


def test_two_hop_relative_location_chain_resolves_against_each_hop(tmp_path):
    """A relative Location resolves against the response URL; two-hop chains work."""
    records = [
        _raw_response(
            "<urn:uuid:r0>", "2024-03-01T09:00:00Z", "https://site-a.test/x/start", 301,
            (("Location", "../y/mid"), ("Content-Length", "0")), b"",
        ),
        _raw_response(
            "<urn:uuid:r1>", "2024-03-01T09:00:00Z", "https://site-a.test/y/mid", 302,
            (("Location", "final?q=1"), ("Content-Length", "0")), b"",
        ),
        _raw_response(
            "<urn:uuid:r2>", "2024-03-01T09:00:00Z", "https://site-a.test/y/final?q=1", 200,
            (("Content-Length", "2"),), b"ok",
        ),
    ]
    _, db_path, _ = _chain_fixture(tmp_path, records)
    manifest, _ = replay_chain(
        db_path, tmp_path, "https://site-a.test/x/start", "2024-03-01T09:00:00Z", "as_of",
        tmp_path / "out",
    )
    assert manifest["status"] == "complete"
    assert [hop["url"] for hop in manifest["hops"]] == [
        "https://site-a.test/x/start",
        "https://site-a.test/y/mid",
        "https://site-a.test/y/final?q=1",
    ]
    assert manifest["hops"][0]["location_target"] == "https://site-a.test/y/mid"
    assert manifest["hops"][1]["location_target"] == "https://site-a.test/y/final?q=1"


def test_chain_follows_relative_location_and_preserves_byte_sources(tmp_path, fixture_chain):
    built = fixture_chain
    manifest, manifest_path = replay_chain(
        built["db"],
        built["archive"].parent,
        "http://site-b.test/redirect",
        "2024-03-01T10:00:02Z",
        "as_of",
        tmp_path / "chain",
    )
    assert manifest["format"] == "webvault-replay-chain/1"
    assert manifest["status"] == "complete"
    assert manifest["termination"]["code"] == "CHAIN_COMPLETE"
    assert [hop["url"] for hop in manifest["hops"]] == [
        "http://site-b.test/redirect",
        "https://site-c.test/landing",
    ]
    assert [hop["status"] for hop in manifest["hops"]] == [301, 200]
    first, second = manifest["hops"]
    assert first["location"] == "https://site-c.test/landing"
    assert first["location_target"] == "https://site-c.test/landing"
    assert first["cdx_redirect"] == "https://site-c.test/landing"
    assert first["cdx_redirect_matches"] is True
    assert first["warc_file"] == "fixtures.warc.gz"
    assert first["output"] == "chain/000001/response.http"
    assert second["output"] == "chain/000002/response.http"
    # Byte faithfulness: each hop output is exactly the WARC response block.
    by_offset = {record.offset: record for record in built["data"].records}
    for hop in manifest["hops"]:
        record = by_offset[hop["offset"]]
        assert hop["digest"] == record.block_digest
        assert hop["warc_date"] == record.date
        output = tmp_path / "chain" / hop["output"]
        assert output.read_bytes() == record.block
        assert output.stat().st_size == hop["bytes"]
    assert manifest["hops"][0]["cdx_redirect"] == "https://site-c.test/landing"
    assert manifest_path.read_bytes() == replay_chain(
        built["db"],
        built["archive"].parent,
        "http://site-b.test/redirect",
        "2024-03-01T10:00:02Z",
        "as_of",
        tmp_path / "chain-again",
    )[1].read_bytes()


def test_exact_capture_requires_same_timestamp_while_as_of_crosses_time(
    tmp_path, fixture_chain
):
    built = fixture_chain
    exact, _ = replay_chain(
        built["db"],
        built["archive"].parent,
        "http://site-b.test/redirect",
        "2024-03-01T10:00:02Z",
        "exact_capture",
        tmp_path / "exact",
    )
    assert exact["status"] == "incomplete"
    assert exact["termination"]["code"] == "E_EXACT_CAPTURE_MISSING"
    assert len(exact["hops"]) == 1  # the redirect evidence is kept
    assert exact["mixed_timestamps"] is False
    assert (tmp_path / "exact" / "chain" / "000001" / "response.http").is_file()

    as_of, _ = replay_chain(
        built["db"],
        built["archive"].parent,
        "http://site-b.test/redirect",
        "2024-03-01T10:00:02Z",
        "as_of",
        tmp_path / "asof",
    )
    assert as_of["status"] == "complete"
    assert as_of["mixed_timestamps"] is True
    assert as_of["distinct_timestamps"] == ["20240301100000", "20240301100002"]


def test_as_of_never_uses_a_capture_after_the_time_point(tmp_path, fixture_chain):
    built = fixture_chain
    manifest, _ = replay_chain(
        built["db"],
        built["archive"].parent,
        "https://site-c.test/not-found",
        "2024-03-01T10:03:00Z",
        "as_of",
        tmp_path / "chain",
    )
    assert manifest["status"] == "incomplete"
    assert manifest["hops"] == []
    assert manifest["termination"]["code"] == "E_CAPTURE_AFTER_AT"


def test_relative_location_is_resolved_against_current_response_url(tmp_path):
    records = [
        _raw_response(
            "<urn:uuid:rel-1>",
            "2024-03-01T09:00:00Z",
            "https://site-a.test/dir/start",
            302,
            (("Location", "next/page"), ("Content-Length", "0")),
            b"",
        ),
        _raw_response(
            "<urn:uuid:rel-2>",
            "2024-03-01T09:00:01Z",
            "https://site-a.test/dir/next/page",
            200,
            (("Content-Length", "2"),),
            b"ok",
        ),
    ]
    _, db_path, _ = _chain_fixture(tmp_path, records)
    manifest, _ = replay_chain(
        db_path,
        tmp_path,
        "https://site-a.test/dir/start",
        "2024-03-01T09:00:01Z",
        "as_of",
        tmp_path / "out",
    )
    assert manifest["status"] == "complete"
    assert manifest["hops"][0]["location"] == "next/page"
    assert manifest["hops"][0]["location_target"] == "https://site-a.test/dir/next/page"
    assert manifest["hops"][1]["url"] == "https://site-a.test/dir/next/page"


def test_two_hop_chain_loop_and_hop_limit(tmp_path):
    records = [
        _raw_response(
            "<urn:uuid:a>", "2024-03-01T09:00:00Z", "https://site-a.test/a", 301,
            (("Location", "https://site-a.test/b"), ("Content-Length", "0")), b"",
        ),
        _raw_response(
            "<urn:uuid:b>", "2024-03-01T09:00:00Z", "https://site-a.test/b", 302,
            (("Location", "https://site-a.test/a"), ("Content-Length", "0")), b"",
        ),
    ]
    _, db_path, _ = _chain_fixture(tmp_path, records)
    looped, _ = replay_chain(
        db_path, tmp_path, "https://site-a.test/a", "2024-03-01T09:00:00Z", "as_of",
        tmp_path / "loop",
    )
    assert looped["status"] == "incomplete"
    assert looped["termination"]["code"] == "E_REDIRECT_LOOP"
    assert len(looped["hops"]) == 2
    assert [hop["output"] for hop in looped["hops"]] == [
        "chain/000001/response.http",
        "chain/000002/response.http",
    ]

    limited, _ = replay_chain(
        db_path, tmp_path, "https://site-a.test/a", "2024-03-01T09:00:00Z", "as_of",
        tmp_path / "limit", max_hops=1,
    )
    assert limited["termination"]["code"] == "E_HOP_LIMIT"
    assert len(limited["hops"]) == 1


@pytest.mark.parametrize(
    "status,headers,expected",
    [
        (302, (), "E_LOCATION_MISSING"),
        (302, (("Location", "https://site-a.test/x"), ("Location", "https://site-a.test/y")), "E_LOCATION_MULTIPLE"),
        (302, (("Location", "ftp://site-a.test/x"),), "E_LOCATION_INVALID"),
        (200, (("Location", "https://site-a.test/x"),), "E_UNEXPECTED_LOCATION"),
    ],
)
def test_redirect_edge_cases_terminate_with_distinct_codes(tmp_path, status, headers, expected):
    block_headers = tuple(headers) + (("Content-Length", "0"),)
    records = [
        _raw_response(
            "<urn:uuid:edge>", "2024-03-01T09:00:00Z", "https://site-a.test/start",
            status, block_headers, b"",
        )
    ]
    _, db_path, _ = _chain_fixture(tmp_path, records)
    manifest, _ = replay_chain(
        db_path, tmp_path, "https://site-a.test/start", "2024-03-01T09:00:00Z", "as_of",
        tmp_path / "out",
    )
    assert manifest["status"] == "incomplete"
    assert manifest["termination"]["code"] == expected
    # The offending hop's raw bytes are still written before terminating.
    assert len(manifest["hops"]) == 1
    assert (tmp_path / "out" / "chain" / "000001" / "response.http").is_file()
    hop = manifest["hops"][0]
    source = next(r for r in build_archive_data(tmp_path / "chain.warc").records if r.warc_type == "response")
    assert (tmp_path / "out" / "chain" / "000001" / "response.http").read_bytes() == source.block
    if expected == "E_LOCATION_MULTIPLE":
        assert len(hop["locations"]) == 2
        assert hop["location"] is None


def test_missing_cdx_target_and_missing_archive_keep_partial_chain(tmp_path):
    records = [
        _raw_response(
            "<urn:uuid:one>", "2024-03-01T09:00:00Z", "https://site-a.test/start", 301,
            (("Location", "https://site-a.test/gone"), ("Content-Length", "0")), b"",
        )
    ]
    archive, db_path, _ = _chain_fixture(tmp_path, records)
    missing, _ = replay_chain(
        db_path, tmp_path, "https://site-a.test/start", "2024-03-01T09:00:00Z", "as_of",
        tmp_path / "missing",
    )
    assert missing["termination"]["code"] == "E_NO_CDX_TARGET"
    assert len(missing["hops"]) == 1
    assert (tmp_path / "missing" / "chain" / "000001" / "response.http").is_file()

    archive.unlink()
    gone, _ = replay_chain(
        db_path, tmp_path, "https://site-a.test/start", "2024-03-01T09:00:00Z", "as_of",
        tmp_path / "gone",
    )
    assert gone["termination"]["code"] == "E_ARCHIVE_NOT_FOUND"
    assert gone["hops"] == []


def test_offset_pointing_at_metadata_is_not_response(tmp_path):
    from webvault.model import RawRecord, metadata_record_id

    response = _raw_response(
        "<urn:uuid:meta-src>", "2024-03-01T09:00:00Z", "https://site-a.test/start", 200,
        (("Content-Length", "0"),), b"",
    )
    metadata = RawRecord(
        "metadata",
        metadata_record_id("https://site-a.test/start", "2024-03-01T09:00:00Z", "sha256:X"),
        "2024-03-01T09:00:00Z",
        "https://site-a.test/start",
        "application/json",
        b'{"outlink":"https://site-a.test/x"}',
        refers_to="<urn:uuid:meta-src>",
    )
    archive, db_path, data = _chain_fixture(tmp_path, [response, metadata])
    metadata_offset = next(r.offset for r in data.records if r.warc_type == "metadata")
    connection = sqlite3.connect(db_path)
    connection.execute(
        "UPDATE records SET offset = ? WHERE url = ?",
        (metadata_offset, "https://site-a.test/start"),
    )
    connection.commit()
    connection.close()
    manifest, _ = replay_chain(
        db_path, tmp_path, "https://site-a.test/start", "2024-03-01T09:00:00Z", "as_of",
        tmp_path / "out",
    )
    assert manifest["status"] == "incomplete"
    assert manifest["termination"]["code"] == "E_NOT_RESPONSE"
    assert manifest["hops"] == []


def test_cdx_warc_location_conflict_is_reported_not_followed(tmp_path):
    records = [
        _raw_response(
            "<urn:uuid:a>", "2024-03-01T09:00:00Z", "https://site-a.test/a", 301,
            (("Location", "https://site-a.test/b"), ("Content-Length", "0")), b"",
        ),
        _raw_response(
            "<urn:uuid:b>", "2024-03-01T09:00:00Z", "https://site-a.test/b", 200,
            (("Content-Length", "0"),), b"",
        ),
    ]
    _, db_path, _ = _chain_fixture(tmp_path, records)
    # Simulate a CDX redirect column that disagrees with the raw Location header.
    connection = sqlite3.connect(db_path)
    connection.execute(
        "UPDATE records SET redirect = ? WHERE url = ?",
        ("https://site-a.test/elsewhere", "https://site-a.test/a"),
    )
    connection.commit()
    connection.close()
    manifest, manifest_path = replay_chain(
        db_path, tmp_path, "https://site-a.test/a", "2024-03-01T09:00:00Z", "as_of",
        tmp_path / "out",
    )
    assert manifest["termination"]["code"] == "E_CDX_WARC_LOCATION_MISMATCH"
    assert manifest["hops"][0]["cdx_redirect_matches"] is False
    assert manifest["hops"][0]["location"] == "https://site-a.test/b"
    assert len(manifest["hops"]) == 1
    assert (tmp_path / "out" / "chain" / "000001" / "response.http").is_file()
    assert "elsewhere" in _read_manifest(manifest_path)["hops"][0]["cdx_redirect"]


def test_ambiguous_rows_are_stable_and_recorded(tmp_path):
    records = [
        _raw_response(
            "<urn:uuid:a1>", "2024-03-01T09:00:00Z", "https://site-a.test/a", 301,
            (("Location", "https://site-a.test/b"), ("Content-Length", "0")), b"first",
        ),
        _raw_response(
            "<urn:uuid:a2>", "2024-03-01T09:00:00Z", "https://site-a.test/a", 301,
            (("Location", "https://site-a.test/b"), ("Content-Length", "0")), b"second",
        ),
        _raw_response(
            "<urn:uuid:b>", "2024-03-01T09:00:00Z", "https://site-a.test/b", 200,
            (("Content-Length", "0"),), b"",
        ),
    ]
    _, db_path, _ = _chain_fixture(tmp_path, records)
    first, _ = replay_chain(
        db_path, tmp_path, "https://site-a.test/a", "2024-03-01T09:00:00Z", "as_of",
        tmp_path / "one",
    )
    second, _ = replay_chain(
        db_path, tmp_path, "https://site-a.test/a", "2024-03-01T09:00:00Z", "as_of",
        tmp_path / "two",
    )
    assert len(first["ambiguities"]) == 1
    entry = first["ambiguities"][0]
    assert len(entry["candidates"]) == 2
    assert entry["selected"] == {
        "digest": entry["candidates"][0]["digest"],
        "warc_file": entry["candidates"][0]["warc_file"],
        "offset": entry["candidates"][0]["offset"],
    }
    # digest/file/offset sorting makes the choice deterministic across runs.
    assert first["hops"][0]["digest"] == second["hops"][0]["digest"]


def test_index_row_pointing_at_other_urls_response_is_rejected(tmp_path):
    records = [
        _raw_response(
            "<urn:uuid:a>", "2024-03-01T09:00:00Z", "https://site-a.test/a", 200,
            (("Content-Length", "0"),), b"",
        ),
        _raw_response(
            "<urn:uuid:b>", "2024-03-01T09:00:00Z", "https://site-a.test/b", 200,
            (("Content-Length", "0"),), b"",
        ),
    ]
    _, db_path, data = _chain_fixture(tmp_path, records)
    other_offset = next(r.offset for r in data.records if r.target_uri.endswith("/b"))
    connection = sqlite3.connect(db_path)
    connection.execute(
        "UPDATE records SET offset = ? WHERE url = ?", (other_offset, "https://site-a.test/a")
    )
    connection.commit()
    connection.close()
    manifest, _ = replay_chain(
        db_path, tmp_path, "https://site-a.test/a", "2024-03-01T09:00:00Z", "as_of",
        tmp_path / "out",
    )
    assert manifest["termination"]["code"] == "E_TARGET_URI_MISMATCH"
    assert manifest["hops"] == []
    assert not (tmp_path / "out" / "chain").exists()


def test_chain_rejects_bad_mode_timestamp_and_hop_limit(tmp_path, fixture_chain):
    built = fixture_chain
    base = dict(
        db_path=built["db"],
        archives_root=built["archive"].parent,
        start_url="http://site-b.test/redirect",
        at="2024-03-01T10:00:02Z",
        out_dir=tmp_path / "out",
    )
    with pytest.raises(ReplayError) as error:
        replay_chain(mode="newest", **base)
    assert error.value.code == "E_BAD_MODE"
    with pytest.raises(ReplayError) as error:
        replay_chain(mode="as_of", **{**base, "at": "not-a-time"})
    assert error.value.code == "E_BAD_TIMESTAMP"
    with pytest.raises(ReplayError) as error:
        replay_chain(mode="as_of", max_hops=0, **base)
    assert error.value.code == "E_BAD_HOP_LIMIT"
    with pytest.raises(ReplayError) as error:
        replay_chain(mode="as_of", **{**base, "start_url": "ftp://site-a.test/x"})
    assert error.value.code == "E_BAD_START_URL"
