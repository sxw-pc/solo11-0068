"""Strict CRLF header parsing and HTTP block construction."""

from __future__ import annotations

import re
from http import HTTPStatus

from ..model import HeaderList

_HEADER_NAME = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_LONE_LF = re.compile(rb"(?<!\r)\n")
_LONE_CR = re.compile(rb"\r(?!\n)")


class HeaderError(ValueError):
    """Malformed or unsafe header data."""


def validate_headers(headers: HeaderList) -> None:
    for name, value in headers:
        if not isinstance(name, str) or not _HEADER_NAME.fullmatch(name):
            raise HeaderError(f"invalid header name: {name!r}")
        if not isinstance(value, str):
            raise HeaderError(f"invalid header value for {name}")
        if "\r" in value or "\n" in value or "\x00" in value:
            raise HeaderError(f"header {name} contains a forbidden character")
        try:
            value.encode("latin-1")
        except UnicodeEncodeError as exc:
            raise HeaderError(f"header {name} is not latin-1") from exc


def serialize_headers(headers: HeaderList) -> bytes:
    validate_headers(headers)
    if not headers:
        return b""
    return b"\r\n".join(
        f"{name}: {value}".encode("latin-1") for name, value in headers
    )


def parse_headers(raw: bytes, strict_crlf: bool = True) -> HeaderList:
    """Parse header lines (without the terminating empty line)."""
    if not raw:
        return ()
    if strict_crlf and (_LONE_LF.search(raw) or _LONE_CR.search(raw)):
        raise HeaderError("headers must use CRLF line endings")
    if not strict_crlf:
        raw = raw.replace(b"\r\n", b"\n")
    lines = raw.split(b"\r\n") if strict_crlf else raw.split(b"\n")
    headers: list[tuple[str, str]] = []
    for line in lines:
        if not line:
            continue
        if line[:1] in (b" ", b"\t"):
            raise HeaderError("folded header lines are not supported")
        if b":" not in line:
            raise HeaderError("header line has no colon")
        name, value = line.split(b":", 1)
        try:
            name_text = name.decode("ascii")
            value_text = value.lstrip(b" ").decode("latin-1")
        except UnicodeDecodeError as exc:
            raise HeaderError("header name is not ASCII") from exc
        validate_headers(((name_text, value_text),))
        headers.append((name_text, value_text))
    return tuple(headers)


def get_header(headers: HeaderList, name: str) -> str | None:
    lower = name.lower()
    for key, value in headers:
        if key.lower() == lower:
            return value
    return None


def reason_phrase(status: int) -> str:
    try:
        return HTTPStatus(status).phrase
    except ValueError:
        return "Unknown"


def build_http_block(status: int, headers: HeaderList, body: bytes) -> bytes:
    """Build status line + original header order + blank + body bytes."""
    working = list(headers)
    if get_header(tuple(working), "Content-Length") is None:
        working.append(("Content-Length", str(len(body))))
    head = serialize_headers(tuple(working))
    status_line = f"HTTP/1.1 {status} {reason_phrase(status)}".encode("latin-1")
    return status_line + b"\r\n" + head + b"\r\n\r\n" + body


def split_http_block(block: bytes) -> tuple[int, HeaderList, bytes]:
    """Split a WARC response block without altering any body byte."""
    marker = block.find(b"\r\n\r\n")
    if marker < 0:
        raise HeaderError("HTTP block has no header terminator")
    head = block[:marker]
    body = block[marker + 4 :]
    lines = head.split(b"\r\n")
    if not lines or not lines[0].startswith(b"HTTP/"):
        raise HeaderError("HTTP block has no status line")
    try:
        parts = lines[0].decode("latin-1").split(" ", 2)
        status = int(parts[1])
    except (IndexError, ValueError) as exc:
        raise HeaderError("malformed HTTP status line") from exc
    headers = parse_headers(b"\r\n".join(lines[1:]), strict_crlf=True)
    return status, headers, body
