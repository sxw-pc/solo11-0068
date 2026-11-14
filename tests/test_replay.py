import hashlib
import json

import pytest

from webvault.replay import ReplayError, replay_one, replay_query
from webvault.warc.headers import split_http_block


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
