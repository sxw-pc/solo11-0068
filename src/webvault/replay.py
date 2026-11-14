"""Extract response records and write byte-faithful offline replay files."""

from __future__ import annotations

import hashlib
import json
import os
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from .index.sqlite_index import search_records
from .model import WarcRecord
from .warc.reader import iter_records


class ReplayError(ValueError):
    def __init__(self, code: str, detail: str):
        self.code = code
        self.detail = detail
        super().__init__(f"{code}: {detail}")


@dataclass
class ReplayItem:
    record: WarcRecord
    output: Path
    relative_output: str
    source_archive: str
    bytes_written: int


def _atomic_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    try:
        temporary.write_bytes(data)
        os.replace(temporary, path)
    except BaseException:
        try:
            temporary.unlink()
        except OSError:
            pass
        raise


def extract_record(archive: Path | str, offset: int) -> WarcRecord:
    """Locate one record by its physical archive offset."""
    archive = Path(archive)
    for record in iter_records(archive):
        if record.offset == offset:
            return record
    raise ReplayError("E_OFFSET_NOT_FOUND", f"no record starts at offset {offset} in {archive.name}")


def replay_one(
    archive: Path | str,
    offset: int,
    out_dir: Path | str,
    *,
    filename: str = "response.http",
) -> ReplayItem:
    archive = Path(archive)
    record = extract_record(archive, offset)
    if record.warc_type != "response":
        raise ReplayError(
            "E_NOT_RESPONSE",
            f"record at offset {offset} is {record.warc_type or 'unknown'}, not response",
        )
    out_dir = Path(out_dir)
    output = out_dir / filename
    _atomic_bytes(output, record.block)
    return ReplayItem(
        record=record,
        output=output,
        relative_output=filename,
        source_archive=archive.name,
        bytes_written=len(record.block),
    )


def _find_archive(root: Path, filename: str) -> Path | None:
    direct = root / filename
    if direct.is_file():
        return direct
    for candidate in sorted(root.rglob(filename)):
        if candidate.is_file():
            return candidate
    return None


def _output_dir(root: Path, row, duplicate_url: bool) -> Path:
    digest = hashlib.sha256(row["url"].encode("utf-8")).hexdigest()[:16]
    if duplicate_url:
        return root / f"{digest}-{row['timestamp']}-{row['offset']}"
    return root / digest


def replay_query(
    db_path: Path | str,
    out_dir: Path | str,
    *,
    archives_root: Path | str | None = None,
    limit: int = 1000,
    **filters,
) -> tuple[list[ReplayItem], Path]:
    """Replay records matching the SQLite filters, plus a deterministic manifest."""
    db_path = Path(db_path)
    out_dir = Path(out_dir)
    root = Path(archives_root) if archives_root else db_path.parent
    rows = []
    page_offset = 0
    while len(rows) < limit:
        page, total = search_records(
            db_path, limit=min(1000, limit - len(rows)), page_offset=page_offset, **filters
        )
        rows.extend(page)
        page_offset += len(page)
        if not page or page_offset >= total:
            break
    counts = Counter(row["url"] for row in rows)
    items: list[ReplayItem] = []
    failures: list[dict] = []
    for row in rows:
        archive = _find_archive(root, row["warc_file"])
        if archive is None:
            failures.append(
                {"warc_file": row["warc_file"], "offset": row["offset"], "error": "E_ARCHIVE_NOT_FOUND"}
            )
            continue
        try:
            output_dir = _output_dir(out_dir, row, counts[row["url"]] > 1)
            item = replay_one(archive, row["offset"], output_dir)
        except ReplayError as exc:
            failures.append(
                {
                    "warc_file": row["warc_file"],
                    "offset": row["offset"],
                    "error": exc.code,
                }
            )
            continue
        item.relative_output = item.output.relative_to(out_dir).as_posix()
        items.append(item)
    manifest = {
        "format": "webvault-replay/1",
        "records": [
            {
                "source_archive": item.source_archive,
                "offset": item.record.offset,
                "digest": item.record.block_digest,
                "output": item.relative_output,
                "bytes": item.bytes_written,
                "url": item.record.target_uri,
                "timestamp": item.record.date,
            }
            for item in sorted(
                items,
                key=lambda i: (i.record.target_uri, i.record.date, i.record.offset),
            )
        ],
        "failures": sorted(
            failures, key=lambda f: (f["warc_file"], f["offset"], f["error"])
        ),
    }
    out_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = out_dir / "replay-manifest.json"
    _atomic_bytes(
        manifest_path,
        (json.dumps(manifest, sort_keys=True, indent=2, ensure_ascii=False) + "\n").encode("utf-8"),
    )
    return items, manifest_path
