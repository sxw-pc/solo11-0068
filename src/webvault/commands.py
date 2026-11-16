"""Implementations of the non-serving CLI subcommands."""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

from .audit import audit_archives, write_reports
from .index.cdx import cdx_path_for
from .index.sqlite_index import (
    build_archive_data,
    create_database,
    discover_archives,
    index_archives,
    record_audit,
    write_archive_index,
)
from .ingest import build_ingest_plan, load_incoming, open_temp_plan_dir
from .manifest import (
    build_manifest,
    diff_manifests,
    load_manifest,
    merge_archives,
    write_manifest,
)
from .replay import replay_one, replay_query
from .warc import write_archive_plan


def log(message: str) -> None:
    print(f"webvault: {message}")


def fail(message: str) -> None:
    print(f"webvault: error: {message}", file=sys.stderr)


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")


def _json_text(value: object) -> str:
    return json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False) + "\n"


def _ingest(root: Path):
    result = load_incoming(root)
    for error in result.errors:
        fail(f"{error.source}: {error.code}: {error.detail}")
    return result


def cmd_import(args) -> int:
    result = _ingest(Path(args.incoming))
    payload = {
        "format": "webvault-import/1",
        "ok": result.ok,
        "counts": {"records": len(result.records), "errors": len(result.errors)},
        "records": [
            {
                "source": record.source,
                "url": record.url,
                "urlkey": record.urlkey,
                "timestamp": record.timestamp,
                "status": record.status,
                "mimetype": record.mime_type,
                "digest": record.digest,
                "bytes": len(record.body),
                "redirect": record.redirect_url or "",
            }
            for record in result.records
        ],
        "errors": [
            {"source": e.source, "code": e.code, "detail": e.detail}
            for e in result.errors
        ],
    }
    text = _json_text(payload)
    if args.out:
        _write_text(Path(args.out), text)
    else:
        sys.stdout.write(text)
    log(f"imported {len(result.records)} records, {len(result.errors)} errors")
    return 0 if result.ok else 2


def cmd_build(args) -> int:
    out_dir = Path(args.out)
    incoming = Path(args.incoming)
    if not incoming.is_dir():
        fail(f"incoming directory not found: {incoming}")
        return 2

    # Bounded-memory snapshot pipeline: bodies are spooled in fixed-size
    # chunks, the ordered plan lives in SQLite and the WARC is streamed back
    # out with per-record digest re-verification, so peak resident response
    # memory stays independent of total batch size.
    workdir = open_temp_plan_dir()
    try:
        plan = build_ingest_plan(incoming, workdir)
        for error in plan.errors:
            fail(f"{error.source}: {error.code}: {error.detail}")
        if not plan.ok:
            return 2
        if plan.count() == 0:
            fail("no valid capture records found")
            return 2
        name = args.archive_name
        if name is None:
            name = "archive.warc.gz" if args.gzip else "archive.warc"
        archive = out_dir / name
        written = write_archive_plan(
            plan,
            archive,
            gzip_compress=args.gzip,
            max_record_bytes=args.max_record_bytes,
        )
    finally:
        # Best-effort cleanup never masks a real failure from the build.
        shutil.rmtree(workdir, ignore_errors=True)

    data = build_archive_data(archive)
    write_archive_index(data)
    create_database(out_dir / "index.sqlite3", [data])
    log(
        f"wrote {written.path.name}: {written.responses} responses, "
        f"{written.records} WARC records, {written.size} bytes"
    )
    log(f"wrote {cdx_path_for(archive).name} and index.sqlite3")
    return 0


def cmd_index(args) -> int:
    source = Path(args.archives)
    paths = discover_archives(source)
    if not paths:
        fail(f"no .warc or .warc.gz archives found under {args.archives}")
        return 2
    out_dir = Path(args.out) if args.out else (source.parent if source.is_file() else source)
    db_path, data = index_archives(paths, out_dir)
    log(f"indexed {len(data)} archives into {db_path.name}")
    for item in data:
        log(f"{item.archive.name}: {len(item.entries)} CDX rows")
    return 0


def _audit_paths(root: Path) -> tuple[list[Path], list[Path]]:
    archives = discover_archives(root)
    cdx_root = root.parent if root.is_file() else root
    cdx_files = sorted(cdx_root.glob("*.cdx"), key=lambda p: p.name)
    return archives, cdx_files


def cmd_audit(args) -> int:
    root = Path(args.archives)
    archives, cdx_files = _audit_paths(root)
    if not archives:
        fail(f"no archives found under {args.archives}")
        return 2
    report = audit_archives(archives, cdx_files)
    out_dir = Path(args.out) if args.out else (root.parent if root.is_file() else root)
    json_path, md_path = write_reports(report, out_dir)
    if args.db:
        if not Path(args.db).is_file():
            fail(f"database not found: {args.db}")
            return 2
        record_audit(args.db, report.to_dict())
    log(f"audit conclusion: {report.conclusion} ({report.fail_count} fatal, {report.warn_count} warnings)")
    log(f"reports: {json_path}, {md_path}")
    return 3 if report.conclusion == "fail" else 0


def cmd_replay(args) -> int:
    out_dir = Path(args.out)
    if args.db and args.archive:
        fail("choose either --db batch replay or --archive single replay")
        return 2
    if args.db:
        filters = {
            "url": args.url,
            "urlkey_prefix": args.urlkey_prefix,
            "start": args.start,
            "end": args.end,
            "mimetype": args.mimetype,
            "status": args.status,
        }
        items, manifest = replay_query(
            args.db,
            out_dir,
            archives_root=args.archives_root,
            limit=args.limit,
            **filters,
        )
        log(f"replayed {len(items)} records; manifest: {manifest}")
        return 0 if items else 2
    if args.archive is None:
        fail("one of --db or --archive is required")
        return 2
    if args.offset is None:
        fail("--offset is required with --archive")
        return 2
    item = replay_one(args.archive, args.offset, out_dir, filename=args.filename)
    log(f"wrote {item.output} ({item.bytes_written} bytes) from offset {args.offset}")
    return 0


def cmd_manifest(args) -> int:
    paths = discover_archives(Path(args.archives))
    if not paths:
        fail(f"no archives found under {args.archives}")
        return 2
    manifest = build_manifest(paths)
    default_out = Path(args.archives)
    default_out = default_out.parent if default_out.is_file() else default_out
    out = Path(args.out) if args.out else default_out / "manifest.json"
    write_manifest(out, manifest)
    log(f"manifest: {out} ({manifest['totals']['unique_urlkey_digest']} unique urlkey/digest)")
    if args.merge_to:
        result = merge_archives(
            paths,
            args.merge_to,
            args.merge_report,
            gzip_compress=args.merge_to.endswith(".gz"),
        )
        log(f"merged archive: {result.output} (kept {result.kept}, dropped {result.dropped})")
        log(f"merge report: {result.report_path}")
    return 0


def cmd_diff(args) -> int:
    result = diff_manifests(load_manifest(args.before), load_manifest(args.after))
    text = _json_text(result)
    if args.out:
        _write_text(Path(args.out), text)
    else:
        sys.stdout.write(text)
    counts = result["counts"]
    log(f"added {counts['added']}, removed {counts['removed']}, changed {counts['changed']}")
    if args.fail_on == "removed" and counts["removed"]:
        fail("removed records detected (--fail-on removed)")
        return 3
    return 0
