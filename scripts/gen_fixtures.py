"""Generate deterministic synthetic capture drops under fixtures/incoming."""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INCOMING = ROOT / "fixtures" / "incoming"

RECORDS = [
    {
        "name": "0001-site-a-index",
        "url": "https://Site-A.test/index.html?b=2&a=1#top",
        "fetched_at": "2024-03-01T09:00:00Z",
        "status": 200,
        "method": "GET",
        "mime_type": "text/html",
        "headers": [
            ("Content-Type", "text/html; charset=utf-8"),
            ("Content-Length", "186"),
            ("X-Archive-Fixture", "webvault"),
            ("Date", "Fri, 01 Mar 2024 09:00:00 GMT"),
        ],
        "body": (
            b"<!doctype html><html><head><title>Site A index</title></head>"
            b"<body><h1>Site A</h1><p>Offline fixture.</p>"
            b"<a href=\"/about.html\">About</a></body></html>\n"
        ),
        "note": "synthetic HTML fixture",
    },
    {
        "name": "0002-site-a-about",
        "url": "https://site-a.test/about.html",
        "fetched_at": "2024-03-01T09:02:00Z",
        "status": 200,
        "method": "GET",
        "mime_type": "text/html",
        "headers": [
            ("Content-Type", "text/html; charset=utf-8"),
            ("Content-Length", "137"),
            ("X-Archive-Fixture", "webvault"),
        ],
        "body": (
            b"<!doctype html><html><head><title>About Site A</title></head>"
            b"<body><p>About page for the reserved test domain.</p></body></html>\n"
        ),
        "note": None,
    },
    {
        "name": "0003-site-a-data",
        "url": "https://site-a.test/data.json",
        "fetched_at": "2024-03-01T09:04:00Z",
        "status": 200,
        "method": "GET",
        "mime_type": "application/json",
        "headers": [
            ("Content-Type", "application/json"),
            ("Content-Length", "74"),
            ("X-Archive-Fixture", "webvault"),
        ],
        "body": b'{"domain":"site-a.test","items":[1,2,3],"synthetic":true}\n',
        "note": "JSON fixture",
    },
    {
        "name": "0004-site-b-redirect",
        "url": "http://site-b.test/redirect",
        "fetched_at": "2024-03-01T10:00:00Z",
        "status": 301,
        "method": "GET",
        "mime_type": "text/html",
        "headers": [
            ("Content-Type", "text/html"),
            ("Content-Length", "56"),
            ("Location", "https://site-c.test/landing"),
            ("X-Archive-Fixture", "webvault"),
        ],
        "body": b"<!doctype html><title>Moved</title><p>Moved.</p>\n",
        "redirect_url": "https://site-c.test/landing",
        "note": "redirect fixture",
    },
    {
        "name": "0005-site-c-landing",
        "url": "https://site-c.test/landing",
        "fetched_at": "2024-03-01T10:00:02Z",
        "status": 200,
        "method": "GET",
        "mime_type": "text/html",
        "headers": [
            ("Content-Type", "text/html; charset=utf-8"),
            ("Content-Length", "130"),
            ("X-Archive-Fixture", "webvault"),
        ],
        "body": (
            b"<!doctype html><html><head><title>Landing</title></head>"
            b"<body><p>Landing page on site-c.test.</p></body></html>\n"
        ),
        "note": None,
    },
    {
        "name": "0006-site-b-style",
        "url": "http://site-b.test/assets/style.css",
        "fetched_at": "2024-03-01T10:03:00Z",
        "status": 200,
        "method": "GET",
        "mime_type": "text/css",
        "headers": [
            ("Content-Type", "text/css"),
            ("Content-Length", "52"),
            ("X-Archive-Fixture", "webvault"),
        ],
        "body": b"body{font-family:serif;background:#f4f1e8;color:#18201e}\n",
        "note": "CSS fixture",
    },
    {
        "name": "0007-site-c-not-found",
        "url": "https://site-c.test/not-found",
        "fetched_at": "2024-03-01T10:04:00Z",
        "status": 404,
        "method": "GET",
        "mime_type": "text/html",
        "headers": [
            ("Content-Type", "text/html; charset=utf-8"),
            ("Content-Length", "120"),
            ("X-Archive-Fixture", "webvault"),
        ],
        "body": (
            b"<!doctype html><html><head><title>Not found</title></head>"
            b"<body><h1>404</h1><p>Fixture page not found.</p></body></html>\n"
        ),
        "note": "404 fixture",
    },
    {
        "name": "0008-site-a-logo",
        "url": "https://site-a.test/logo.png",
        "fetched_at": "2024-03-01T10:05:00Z",
        "status": 200,
        "method": "GET",
        "mime_type": "image/png",
        "headers": [
            ("Content-Type", "image/png"),
            ("Content-Length", "68"),
            ("X-Archive-Fixture", "webvault"),
        ],
        "body": bytes.fromhex(
            "89504e470d0a1a0a0000000d4948445200000001000000010806000000"
            "1f15c4890000000b49444154789c6360000000020001e221bc3300000000"
            "49454e44ae426082"
        ),
        "note": "synthetic PNG bytes",
    },
]


def _write(record: dict) -> None:
    directory = INCOMING / record["name"]
    directory.mkdir(parents=True, exist_ok=True)
    body = record["body"]
    headers = []
    for name, value in record["headers"]:
        if name.lower() == "content-length":
            value = str(len(body))
        headers.append([name, value])
    meta = {
        "url": record["url"],
        "fetched_at": record["fetched_at"],
        "status": record["status"],
        "method": record["method"],
        "headers": headers,
        "mime_type": record["mime_type"],
        "body_file": "body.bin",
        "redirect_url": record.get("redirect_url"),
        "note": record.get("note"),
    }
    (directory / "meta.json").write_text(
        json.dumps(meta, sort_keys=True, indent=2, ensure_ascii=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    header_text = "".join(f"{name}: {value}\r\n" for name, value in headers) + "\r\n"
    (directory / "headers.txt").write_bytes(header_text.encode("utf-8"))
    (directory / "body.bin").write_bytes(body)


def main() -> int:
    INCOMING.mkdir(parents=True, exist_ok=True)
    expected = {record["name"] for record in RECORDS}
    for child in list(INCOMING.iterdir()):
        if child.is_dir() and child.name not in expected:
            shutil.rmtree(child)
    for record in RECORDS:
        _write(record)
    print(f"webvault: generated {len(RECORDS)} capture drops in {INCOMING}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
