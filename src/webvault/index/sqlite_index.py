"""SQLite search index construction and public query facades."""

from __future__ import annotations

import json
import os
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path

from ..digest import file_sha256
from ..model import ArchiveInfo, CdxEntry, WarcRecord
from ..urlnorm import normalize_timestamp
from ..warc.reader import WarcReadError, read_archive
from .cdx import cdx_path_for, entries_from_records, write_cdx
from .query import (  # re-exported for the original public API
    connect_readonly,
    get_record,
    list_archives,
    list_audits,
    search_records,
)

SCHEMA = """
CREATE TABLE archives (
    id INTEGER PRIMARY KEY,
    file TEXT NOT NULL UNIQUE,
    size INTEGER NOT NULL,
    sha256 TEXT NOT NULL,
    record_count INTEGER NOT NULL,
    response_count INTEGER NOT NULL,
    first_timestamp TEXT NOT NULL,
    last_timestamp TEXT NOT NULL
);
CREATE TABLE records (
    id INTEGER PRIMARY KEY,
    urlkey TEXT NOT NULL,
    url TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    status INTEGER NOT NULL,
    mimetype TEXT NOT NULL,
    digest TEXT NOT NULL,
    offset INTEGER NOT NULL,
    length INTEGER NOT NULL,
    warc_file TEXT NOT NULL,
    redirect TEXT NOT NULL DEFAULT ''
);
CREATE TABLE audits (
    batch_id TEXT PRIMARY KEY,
    conclusion TEXT NOT NULL,
    archives INTEGER NOT NULL,
    records INTEGER NOT NULL,
    issues INTEGER NOT NULL,
    fail_count INTEGER NOT NULL,
    warn_count INTEGER NOT NULL,
    codes_json TEXT NOT NULL,
    report_json TEXT NOT NULL
);
CREATE INDEX idx_records_urlkey ON records(urlkey);
CREATE INDEX idx_records_timestamp ON records(timestamp);
CREATE INDEX idx_records_digest ON records(digest);
CREATE INDEX idx_records_url ON records(url);
CREATE INDEX idx_records_mimetype ON records(mimetype);
"""


@dataclass
class ArchiveData:
    archive: Path
    info: ArchiveInfo
    records: list[WarcRecord]
    entries: list[CdxEntry] = field(default_factory=list)


def build_archive_data(archive: Path | str, *, base_dir: Path | None = None) -> ArchiveData:
    archive = Path(archive)
    result = read_archive(archive)
    if result.errors:
        error = result.errors[0]
        raise WarcReadError(
            getattr(error, "code", "E_MALFORMED_WARC"),
            getattr(error, "detail", str(error)),
            offset=getattr(error, "offset", 0),
        )
    entries = entries_from_records(result.records, archive.name)
    dated = [normalize_timestamp(r.date) for r in result.records if r.date]
    info = ArchiveInfo(
        file=archive.name,
        size=archive.stat().st_size,
        sha256=file_sha256(archive),
        record_count=len(result.records),
        response_count=sum(1 for r in result.records if r.warc_type == "response"),
        first_timestamp=min(dated, default=""),
        last_timestamp=max(dated, default=""),
    )
    del base_dir
    return ArchiveData(archive=archive, info=info, records=result.records, entries=entries)


def discover_archives(root: Path | str) -> list[Path]:
    root = Path(root)
    if root.is_file():
        return [root]
    if not root.is_dir():
        raise FileNotFoundError(root)
    files = [
        path
        for path in root.iterdir()
        if path.is_file() and (path.name.endswith(".warc") or path.name.endswith(".warc.gz"))
    ]
    return sorted(files, key=lambda p: p.name)


def write_archive_index(data: ArchiveData) -> Path:
    return write_cdx(cdx_path_for(data.archive), data.entries)


def create_database(db_path: Path | str, archives: list[ArchiveData]) -> Path:
    """Create a fresh index database atomically."""
    db_path = Path(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = db_path.with_name(db_path.name + ".tmp")
    for stale in (temporary, Path(str(temporary) + "-journal")):
        try:
            stale.unlink()
        except OSError:
            pass
    connection = sqlite3.connect(temporary)
    try:
        connection.executescript(SCHEMA)
        for data in sorted(archives, key=lambda item: item.archive.name):
            connection.execute(
                "INSERT INTO archives(file,size,sha256,record_count,response_count,first_timestamp,last_timestamp) "
                "VALUES(?,?,?,?,?,?,?)",
                (
                    data.info.file,
                    data.info.size,
                    data.info.sha256,
                    data.info.record_count,
                    data.info.response_count,
                    data.info.first_timestamp,
                    data.info.last_timestamp,
                ),
            )
            by_offset = {r.offset: r for r in data.records if r.warc_type == "response"}
            for entry in data.entries:
                record = by_offset.get(entry.offset)
                length = len(record.block) if record else 0
                connection.execute(
                    "INSERT INTO records(urlkey,url,timestamp,status,mimetype,digest,offset,length,warc_file,redirect) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (
                        entry.urlkey,
                        entry.original,
                        entry.timestamp,
                        entry.status,
                        entry.mimetype,
                        entry.digest,
                        entry.offset,
                        length,
                        entry.filename,
                        entry.redirect,
                    ),
                )
        connection.commit()
    finally:
        connection.close()
    os.replace(temporary, db_path)
    return db_path


def index_archives(paths: list[Path], out_dir: Path | str) -> tuple[Path, list[ArchiveData]]:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    data = [build_archive_data(path) for path in paths]
    for item in data:
        write_archive_index(item)
    db_path = create_database(out_dir / "index.sqlite3", data)
    return db_path, data


def record_audit(db_path: Path | str, report: dict) -> None:
    """Persist the summary of one audit report."""
    db_path = Path(db_path)
    if not db_path.is_file():
        return
    batch_id = report["batch_id"]
    codes = json.dumps(report.get("by_code", {}), sort_keys=True, separators=(",", ":"))
    summary = {
        "conclusion": report["conclusion"],
        "archives": len(report.get("archives", [])),
        "records": report.get("records", 0),
        "issues": len(report.get("issues", [])),
        "fail": report.get("fail_count", 0),
        "warn": report.get("warn_count", 0),
    }
    connection = sqlite3.connect(db_path)
    try:
        connection.execute(
            "INSERT OR REPLACE INTO audits VALUES(?,?,?,?,?,?,?,?,?)",
            (
                batch_id,
                summary["conclusion"],
                summary["archives"],
                summary["records"],
                summary["issues"],
                summary["fail"],
                summary["warn"],
                codes,
                json.dumps(report, sort_keys=True, separators=(",", ":")),
            ),
        )
        connection.commit()
    finally:
        connection.close()
