"""End-to-end offline demo built from the repository's synthetic fixtures."""

from __future__ import annotations

from pathlib import Path

from .audit import audit_archives, write_reports
from .index.cdx import cdx_path_for
from .index.sqlite_index import (
    build_archive_data,
    create_database,
    record_audit,
    write_archive_index,
)
from .ingest import load_incoming
from .manifest import build_manifest, write_manifest
from .replay import replay_one
from .warc import read_archive, write_archive


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def run_demo(out_dir: Path | str, *, plain: bool = False) -> dict:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    incoming = _repo_root() / "fixtures" / "incoming"
    loaded = load_incoming(incoming)
    if loaded.errors:
        details = "; ".join(f"{e.source}: {e.code}" for e in loaded.errors)
        raise ValueError(f"demo fixtures failed validation: {details}")
    if not loaded.records:
        raise ValueError("demo fixtures contain no records")
    archive = out_dir / ("archive.warc" if plain else "archive.warc.gz")
    written = write_archive(loaded.records, archive, gzip_compress=not plain)
    data = build_archive_data(archive)
    write_archive_index(data)
    db_path = create_database(out_dir / "index.sqlite3", [data])

    report = audit_archives([archive], [cdx_path_for(archive)])
    report_json, report_md = write_reports(report, out_dir / "audit")
    record_audit(db_path, report.to_dict())
    if report.conclusion == "fail":
        raise ValueError(f"demo archive failed audit: {report_json}")

    first_response = next(r for r in data.records if r.warc_type == "response")
    replay = replay_one(archive, first_response.offset, out_dir / "replay" / "sample")
    manifest = build_manifest([archive])
    manifest_path = write_manifest(out_dir / "manifest.json", manifest)
    read_check = read_archive(archive)
    return {
        "archive": written.path,
        "cdx": cdx_path_for(archive),
        "database": db_path,
        "audit_json": report_json,
        "audit_markdown": report_md,
        "manifest": manifest_path,
        "replay": replay.output,
        "records": len(read_check.records),
        "responses": written.responses,
        "conclusion": report.conclusion,
    }
