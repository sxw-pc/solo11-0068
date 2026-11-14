"""Archive-set manifests, cross-archive merge, and manifest diffing."""

from __future__ import annotations

import json
import os
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from .digest import file_sha256
from .index.cdx import entries_from_records
from .model import CdxEntry, RawRecord, WarcRecord
from .urlnorm import from_cdx_timestamp, to_cdx_timestamp, urlkey as make_urlkey
from .warc.reader import read_archive
from .warc.writer import write_raw_archive

_MANIFEST_FORMAT = "webvault-manifest/1"


@dataclass
class MergeResult:
    output: Path
    report_path: Path
    kept: int
    dropped: int


def _load_archive(path: Path):
    result = read_archive(path)
    if result.errors:
        error = result.errors[0]
        raise ValueError(
            f"cannot manifest {path.name}: {getattr(error, 'code', 'E_MALFORMED_WARC')} "
            f"{getattr(error, 'detail', str(error))}"
        )
    return result.records


def _entry_dict(entry: CdxEntry) -> dict:
    return {
        "file": entry.filename,
        "offset": entry.offset,
        "urlkey": entry.urlkey,
        "url": entry.original,
        "timestamp": entry.timestamp,
        "mimetype": entry.mimetype,
        "status": entry.status,
        "digest": entry.digest,
        "redirect": entry.redirect,
    }


def build_manifest(archives: list[Path]) -> dict:
    """Build a deterministic manifest from an archive set."""
    archive_sections: list[dict] = []
    all_entries: list[CdxEntry] = []
    total_records = 0
    total_responses = 0
    for path in sorted(archives, key=lambda p: p.name):
        records = _load_archive(path)
        entries = entries_from_records(records, path.name)
        all_entries.extend(entries)
        responses = sum(1 for record in records if record.warc_type == "response")
        total_records += len(records)
        total_responses += responses
        dates = [entry.timestamp for entry in entries]
        archive_sections.append(
            {
                "file": path.name,
                "size": path.stat().st_size,
                "sha256": file_sha256(path),
                "records": len(records),
                "responses": responses,
                "first_timestamp": from_cdx_timestamp(min(dates)) if dates else "",
                "last_timestamp": from_cdx_timestamp(max(dates)) if dates else "",
            }
        )
    all_entries.sort(key=lambda e: e.sort_key())
    dates = [entry.timestamp for entry in all_entries]
    mimetypes = dict(sorted(Counter(e.mimetype for e in all_entries).items()))
    statuses = dict(sorted(Counter(str(e.status) for e in all_entries).items()))
    return {
        "format": _MANIFEST_FORMAT,
        "archives": archive_sections,
        "totals": {
            "archives": len(archive_sections),
            "records": total_records,
            "responses": total_responses,
            "unique_urlkey_digest": len({(e.urlkey, e.digest) for e in all_entries}),
            "first_timestamp": from_cdx_timestamp(min(dates)) if dates else "",
            "last_timestamp": from_cdx_timestamp(max(dates)) if dates else "",
        },
        "mimetypes": mimetypes,
        "statuses": statuses,
        "records": [_entry_dict(entry) for entry in all_entries],
    }


def write_manifest(path: Path | str, manifest: dict) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(manifest, sort_keys=True, indent=2, ensure_ascii=False) + "\n"
    temporary = path.with_name(path.name + ".tmp")
    try:
        temporary.write_text(text, encoding="utf-8", newline="\n")
        os.replace(temporary, path)
    except BaseException:
        try:
            temporary.unlink()
        except OSError:
            pass
        raise
    return path


def load_manifest(path: Path | str) -> dict:
    with Path(path).open("r", encoding="utf-8") as handle:
        manifest = json.load(handle)
    if not isinstance(manifest, dict) or manifest.get("format") != _MANIFEST_FORMAT:
        raise ValueError("not a webvault manifest")
    if not isinstance(manifest.get("records"), list):
        raise ValueError("manifest has no records array")
    return manifest


def _record_index(manifest: dict) -> dict[tuple[str, str], list[dict]]:
    index: dict[tuple[str, str], list[dict]] = {}
    for record in manifest["records"]:
        key = (record.get("urlkey", ""), record.get("timestamp", ""))
        index.setdefault(key, []).append(record)
    return index


def diff_manifests(before: dict, after: dict) -> dict:
    left = _record_index(before)
    right = _record_index(after)
    added = [record for key in sorted(set(right) - set(left)) for record in right[key]]
    removed = [record for key in sorted(set(left) - set(right)) for record in left[key]]
    changed = []
    for key in sorted(set(left) & set(right)):
        old_digests = sorted({record.get("digest", "") for record in left[key]})
        new_digests = sorted({record.get("digest", "") for record in right[key]})
        if old_digests != new_digests:
            changed.append(
                {
                    "urlkey": key[0],
                    "timestamp": key[1],
                    "before_digests": old_digests,
                    "after_digests": new_digests,
                }
            )
    return {
        "format": "webvault-diff/1",
        "added": added,
        "removed": removed,
        "changed": changed,
        "counts": {
            "added": len(added),
            "removed": len(removed),
            "changed": len(changed),
        },
    }


def _record_key(record: WarcRecord) -> tuple[str, str]:
    return make_urlkey(record.target_uri), record.block_digest


def merge_archives(
    archives: list[Path],
    out_path: Path | str,
    report_path: Path | str | None = None,
    *,
    gzip_compress: bool | None = None,
) -> MergeResult:
    """Merge archives, deduplicating by (urlkey, digest), earliest wins."""
    out_path = Path(out_path)
    report_path = Path(report_path) if report_path else out_path.with_name("merge-report.json")
    if gzip_compress is None:
        gzip_compress = out_path.name.endswith(".gz")
    candidates: dict[tuple[str, str], list[tuple[Path, WarcRecord, list[WarcRecord]]]] = {}
    archive_meta: list[dict] = []
    for path in sorted(archives, key=lambda p: p.name):
        records = _load_archive(path)
        archive_meta.append(
            {"file": path.name, "sha256": file_sha256(path)}
        )
        metadata: dict[str, list[WarcRecord]] = {}
        for record in records:
            if record.warc_type == "metadata" and record.refers_to:
                metadata.setdefault(record.refers_to, []).append(record)
        for record in records:
            if record.warc_type != "response":
                continue
            try:
                key = _record_key(record)
            except (ValueError, UnicodeError) as exc:
                raise ValueError(f"invalid response target in {path.name}: {record.target_uri}") from exc
            candidates.setdefault(key, []).append(
                (path, record, metadata.get(record.record_id, []))
            )
    kept: list[tuple[Path, WarcRecord, list[WarcRecord]]] = []
    dropped: list[dict] = []
    for key in sorted(candidates):
        group = sorted(
            candidates[key], key=lambda item: (item[1].date, item[0].name, item[1].offset)
        )
        winner = group[0]
        kept.append(winner)
        for loser in group[1:]:
            dropped.append(
                {
                    "source": loser[0].name,
                    "offset": loser[1].offset,
                    "record_id": loser[1].record_id,
                    "url": loser[1].target_uri,
                    "timestamp": loser[1].date,
                    "digest": loser[1].block_digest,
                    "reason": "duplicate_urlkey_digest",
                    "kept_source": winner[0].name,
                }
            )
    if not kept:
        raise ValueError("no response records to merge")
    kept.sort(key=lambda item: (_record_key(item[1])[0], item[1].date, item[1].block_digest))
    raw: list[RawRecord] = []
    for _, record, metadata in kept:
        raw.append(
            RawRecord(
                "response",
                record.record_id,
                record.date,
                record.target_uri,
                record.content_type,
                record.block,
            )
        )
        for item in sorted(metadata, key=lambda r: (r.date, r.offset)):
            raw.append(
                RawRecord(
                    "metadata",
                    item.record_id,
                    item.date,
                    item.target_uri,
                    item.content_type,
                    item.block,
                    refers_to=item.refers_to,
                )
            )
    write_raw_archive(
        out_path,
        raw,
        gzip_compress=gzip_compress,
        warcinfo_date=min(record.date for _, record, _ in kept),
    )
    report = {
        "format": "webvault-merge/1",
        "output": out_path.name,
        "inputs": sorted(archive_meta, key=lambda item: item["file"]),
        "kept": len(kept),
        "dropped": sorted(
            dropped, key=lambda item: (item["source"], item["offset"], item["digest"])
        ),
    }
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(
        json.dumps(report, sort_keys=True, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return MergeResult(out_path, report_path, len(kept), len(dropped))
