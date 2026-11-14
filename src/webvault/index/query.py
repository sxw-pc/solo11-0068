"""Read-only SQLite queries used by the CLI and browser."""

from __future__ import annotations

import re
import sqlite3
from pathlib import Path

from ..urlnorm import canonicalize_url, to_cdx_timestamp


def connect_readonly(db_path: Path | str) -> sqlite3.Connection:
    path = Path(db_path).resolve()
    if not path.is_file():
        raise FileNotFoundError(path)
    connection = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    return connection


def _timestamp_filter(value: str | None) -> str | None:
    if not value:
        return None
    if re.fullmatch(r"\d{14}", value):
        return value
    return to_cdx_timestamp(value)


def search_records(
    db_path: Path | str,
    *,
    url: str | None = None,
    urlkey_prefix: str | None = None,
    start: str | None = None,
    end: str | None = None,
    mimetype: str | None = None,
    status: int | None = None,
    limit: int = 100,
    page_offset: int = 0,
) -> tuple[list[sqlite3.Row], int]:
    clauses = []
    values: list[object] = []
    if url:
        try:
            url = canonicalize_url(url)
        except ValueError:
            pass
        clauses.append("url = ?")
        values.append(url)
    if urlkey_prefix:
        clauses.append("urlkey LIKE ? ESCAPE '\\'")
        escaped = urlkey_prefix.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        values.append(escaped + "%")
    start_cdx = _timestamp_filter(start)
    end_cdx = _timestamp_filter(end)
    if start_cdx:
        clauses.append("timestamp >= ?")
        values.append(start_cdx)
    if end_cdx:
        clauses.append("timestamp <= ?")
        values.append(end_cdx)
    if mimetype:
        clauses.append("mimetype = ?")
        values.append(mimetype.split(";", 1)[0].strip().lower())
    if status is not None:
        clauses.append("status = ?")
        values.append(status)
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    limit = max(1, min(int(limit), 1000))
    page_offset = max(0, int(page_offset))
    connection = connect_readonly(db_path)
    try:
        total = connection.execute("SELECT COUNT(*) FROM records" + where, values).fetchone()[0]
        rows = connection.execute(
            "SELECT * FROM records"
            + where
            + " ORDER BY timestamp, url, digest, warc_file, offset LIMIT ? OFFSET ?",
            values + [limit, page_offset],
        ).fetchall()
        return list(rows), int(total)
    finally:
        connection.close()


def list_archives(db_path: Path | str) -> list[sqlite3.Row]:
    connection = connect_readonly(db_path)
    try:
        return list(connection.execute("SELECT * FROM archives ORDER BY file").fetchall())
    finally:
        connection.close()


def get_record(db_path: Path | str, record_id: int) -> sqlite3.Row | None:
    connection = connect_readonly(db_path)
    try:
        return connection.execute("SELECT * FROM records WHERE id = ?", (record_id,)).fetchone()
    finally:
        connection.close()


def list_audits(db_path: Path | str, limit: int = 20) -> list[sqlite3.Row]:
    connection = connect_readonly(db_path)
    try:
        return list(
            connection.execute(
                "SELECT * FROM audits ORDER BY batch_id DESC LIMIT ?", (max(1, limit),)
            ).fetchall()
        )
    finally:
        connection.close()
