import json
from pathlib import Path

import pytest

from webvault.index.cdx import cdx_path_for
from webvault.index.sqlite_index import build_archive_data, create_database, write_archive_index
from webvault.model import CaptureRecord
from webvault.warc import write_archive
from webvault.warc.writer import _gzip_member


def make_capture(url="https://site-a.test/index.html", timestamp="2024-03-01T09:00:00Z", **kwargs):
    body = kwargs.pop("body", b"<!doctype html><title>fixture</title>\n")
    headers = kwargs.pop(
        "headers",
        (("Content-Type", "text/html; charset=utf-8"), ("Content-Length", str(len(body)))),
    )
    values = {
        "url": url,
        "timestamp": timestamp,
        "status": 200,
        "method": "GET",
        "headers": tuple(headers),
        "mime_type": "text/html",
        "body": body,
    }
    values.update(kwargs)
    return CaptureRecord(**values)


@pytest.fixture
def captures():
    return [
        make_capture(),
        make_capture(
            url="http://site-b.test/redirect",
            timestamp="2024-03-01T10:00:00Z",
            status=301,
            body=b"moved\n",
            redirect_url="https://site-c.test/landing",
        ),
        make_capture(
            url="https://site-c.test/not-found",
            timestamp="2024-03-01T10:01:00Z",
            status=404,
            body=b"missing\n",
        ),
    ]


@pytest.fixture
def drop_factory(tmp_path):
    root = tmp_path / "incoming"
    root.mkdir()

    def make(name="0001-record", body=b"hello fixture\n", **overrides):
        directory = root / name
        directory.mkdir()
        meta = {
            "url": "https://site-a.test/page.html",
            "fetched_at": "2024-03-01T09:00:00Z",
            "status": 200,
            "method": "GET",
            "headers": [["Content-Type", "text/html"], ["Content-Length", str(len(body))]],
            "mime_type": "text/html",
            "body_file": "body.bin",
            "redirect_url": None,
            "note": None,
        }
        for key, value in overrides.items():
            if key == "headers":
                meta[key] = [list(pair) for pair in value]
            else:
                meta[key] = value
        (directory / "meta.json").write_text(
            json.dumps(meta, sort_keys=True, indent=2) + "\n", encoding="utf-8"
        )
        lines = "".join(f"{n}: {v}\r\n" for n, v in meta["headers"]) + "\r\n"
        (directory / "headers.txt").write_text(lines, encoding="utf-8", newline="")
        if meta["body_file"] == "body.bin":
            (directory / "body.bin").write_bytes(body)
        return directory

    return make, root


@pytest.fixture
def built(tmp_path, captures):
    archive = tmp_path / "archive.warc.gz"
    write_archive(captures, archive, gzip_compress=True)
    data = build_archive_data(archive)
    write_archive_index(data)
    db_path = create_database(tmp_path / "index.sqlite3", [data])
    return {"archive": archive, "cdx": cdx_path_for(archive), "db": db_path, "data": data}


def split_gzip_members(data: bytes) -> list[tuple[int, int]]:
    """Return ``[(start, end), ...]`` physical spans of every gzip member."""
    spans = []
    start = 0
    while True:
        nxt = data.find(b"\x1f\x8b\x08", start + 1)
        if nxt < 0:
            spans.append((start, len(data)))
            return spans
        spans.append((start, nxt))
        start = nxt


def re_member(payload: bytes) -> bytes:
    """Build a fresh, CRC-valid gzip member around an existing WARC payload."""
    return _gzip_member(payload)


@pytest.fixture
def broken_gzip_factory(tmp_path, captures):
    """Build multi-member gzip archives with controlled physical damage.

    Records: one warcinfo followed by three response members, so the middle
    response can be destroyed while later members remain intact.
    """
    base = tmp_path / "base.warc.gz"
    write_archive(captures, base, gzip_compress=True)
    original = bytearray(base.read_bytes())
    spans = split_gzip_members(bytes(original))

    def build(name: str, *, mutate=None, truncate: int = 0) -> Path:
        data = bytearray(original)
        if mutate is not None:
            data = bytearray(mutate(bytes(data), spans))
        if truncate:
            data = data[:-truncate]
        path = tmp_path / name
        path.write_bytes(bytes(data))
        return path

    return build, spans, base
