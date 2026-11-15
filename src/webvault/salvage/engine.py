"""Read-only WARC salvage: recover independently verifiable records.

Strategy B is implemented: each gzip member is re-located through its own
header and isolated before validation, so records that remain complete after
a damaged member are recovered with a non-contiguous physical-offset mapping.
No source byte is ever modified and every output is deterministic.

A record is retained only when it passes the same record-level rules used by
:mod:`webvault.audit.checks`:

* a present, unique ``WARC-Record-ID`` (and ``WARC-Date``);
* ``Content-Length`` equal to the block length (guaranteed by the physical
  scanner, re-asserted here);
* block digest equal to the recomputed digest;
* a target URI that canonicalises, for record types that require one.

Excluded records are reported with their source physical offset and reason.
"""

from __future__ import annotations

import json
import os
import shutil
from dataclasses import dataclass, field
from pathlib import Path

from ..audit import audit_archives
from ..digest import digest_equal, file_sha256, sha256_digest
from ..index.cdx import cdx_path_for
from ..index.sqlite_index import build_archive_data, create_database, write_archive_index
from ..model import RawRecord, WarcRecord
from ..replay import replay_one
from ..urlnorm import canonicalize_url
from ..warc.writer import write_raw_archive
from .scanner import RejectedFrame, SalvageDamage, SalvageUnit, ScanResult, scan_archive

SALVAGE_STRATEGY = "B-member-relocation"
REPORT_NAME = "recovery-report.json"
# Record types whose records must carry a canonicalisable target URI, matching
# the rule set in webvault.audit.checks._check_records.
URI_REQUIRED_TYPES = {"response", "metadata", "request", "resource", "revisit"}
# Source warcinfo records are dropped deliberately; the writer emits a fresh
# warcinfo describing the derived archive.
WARCINFO_SKIP_CODE = "S_WARCINFO_REPLACED"


@dataclass(frozen=True)
class SalvagedRecord:
    unit: SalvageUnit
    record_id: str
    source_offset: int
    source_end_offset: int
    output_offset: int = -1


@dataclass(frozen=True)
class ExcludedRecord:
    source_offset: int
    source_end_offset: int
    record_id: str
    warc_type: str
    code: str
    reason: str


@dataclass
class SalvageResult:
    source: Path
    out_dir: Path
    archive: Path | None = None
    cdx: Path | None = None
    database: Path | None = None
    report_path: Path | None = None
    retained: list[SalvagedRecord] = field(default_factory=list)
    excluded: list[ExcludedRecord] = field(default_factory=list)
    damage: list[SalvageDamage] = field(default_factory=list)
    rejected: list[RejectedFrame] = field(default_factory=list)
    unread_tail: SalvageDamage | None = None
    compressed: bool = False
    source_sha256: str = ""
    output_sha256: str = ""
    audit_conclusion: str = ""
    recovered_records: int = 0
    recovered_responses: int = 0

    @property
    def ok(self) -> bool:
        return self.archive is not None and self.audit_conclusion == "pass"


def _verify_record(record: WarcRecord, seen_ids: dict[str, int]) -> tuple[str, str] | None:
    """Return ``(code, reason)`` for the first failed audit rule, else None."""
    if not record.record_id or not record.date:
        return (
            "E_MALFORMED_WARC",
            "record is missing WARC-Record-ID or WARC-Date",
        )
    if record.record_id in seen_ids:
        return (
            "E_DUP_RECORD_ID",
            f"record id already used at source offset {seen_ids[record.record_id]}",
        )
    if record.content_length != len(record.block):
        return (
            "E_LENGTH_MISMATCH",
            f"Content-Length {record.content_length} does not match block length {len(record.block)}",
        )
    try:
        matches = digest_equal(record.block_digest, sha256_digest(record.block))
    except ValueError:
        matches = False
    if not matches:
        return (
            "E_DIGEST_MISMATCH",
            f"declared {record.block_digest or '(missing)'} actual {sha256_digest(record.block)}",
        )
    if record.warc_type in URI_REQUIRED_TYPES:
        try:
            canonicalize_url(record.target_uri)
        except ValueError:
            return (
                "E_BAD_TARGET_URI",
                f"target URI cannot be canonicalised: {record.target_uri!r}",
            )
    return None


def _to_raw(record: WarcRecord) -> RawRecord:
    """Rebuild the record for the deterministic writer, preserving its
    identity (record id, date, target, type) and exact block bytes."""
    return RawRecord(
        warc_type=record.warc_type,
        record_id=record.record_id,
        date=record.date,
        target_uri=record.target_uri,
        content_type=record.content_type,
        block=record.block,
        refers_to=record.refers_to,
    )


def derived_archive_path(source: Path, out_dir: Path) -> Path:
    if source.name.endswith(".warc.gz"):
        name = source.name[: -len(".warc.gz")] + ".salvaged.warc.gz"
    elif source.name.endswith(".warc"):
        name = source.name[: -len(".warc")] + ".salvaged.warc"
    else:
        name = source.name + ".salvaged.warc"
    return out_dir / name


def _atomic_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    try:
        temporary.write_text(
            json.dumps(payload, sort_keys=True, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        os.replace(temporary, path)
    except BaseException:
        try:
            temporary.unlink()
        except OSError:
            pass
        raise


def _report_payload(result: SalvageResult, scan: ScanResult) -> dict:
    damaged_codes = sorted({event.code for event in result.damage})
    return {
        "format": "webvault-salvage/1",
        "strategy": SALVAGE_STRATEGY,
        "source": {
            "file": result.source.name,
            "sha256": result.source_sha256,
            "size": result.source.stat().st_size,
            "compressed": result.compressed,
        },
        "derived": {
            "file": result.archive.name if result.archive else "",
            "sha256": result.output_sha256,
            "cdx": result.cdx.name if result.cdx else "",
            "database": result.database.name if result.database else "",
            "audit_conclusion": result.audit_conclusion,
        },
        "totals": {
            "records_recovered": result.recovered_records,
            "responses_recovered": result.recovered_responses,
            "records_excluded": len(result.excluded),
            "frames_rejected": len(result.rejected),
            "damaged_spans": len(result.damage),
            "unread_tail_bytes": (
                result.unread_tail.end - result.unread_tail.start if result.unread_tail else 0
            ),
        },
        "retained": [
            {
                "record_id": item.record_id,
                "source_offset": item.source_offset,
                "source_end_offset": item.source_end_offset,
                "output_offset": item.output_offset,
                "output_file": result.archive.name if result.archive else "",
            }
            for item in result.retained
        ],
        "excluded": [
            {
                "source_offset": item.source_offset,
                "source_end_offset": item.source_end_offset,
                "record_id": item.record_id,
                "warc_type": item.warc_type,
                "code": item.code,
                "reason": item.reason,
            }
            for item in result.excluded
        ],
        "rejected_frames": [
            {
                "source_offset": event.start,
                "source_end_offset": event.end,
                "length": event.end - event.start,
                "code": event.code,
                "reason": event.detail,
            }
            for event in result.rejected
        ],
        "damaged_spans": [
            {
                "source_offset": event.start,
                "source_end_offset": event.end,
                "length": event.end - event.start,
                "code": event.code,
                "reason": event.detail,
            }
            for event in result.damage
        ],
        "unread_tail": (
            {
                "source_offset": result.unread_tail.start,
                "source_end_offset": result.unread_tail.end,
                "length": result.unread_tail.end - result.unread_tail.start,
                "code": result.unread_tail.code,
                "reason": result.unread_tail.detail,
            }
            if result.unread_tail
            else None
        ),
        "damage_codes": damaged_codes,
        "candidate_records": len(scan.units),
    }


def salvage_archive(source: Path | str, out_dir: Path | str) -> SalvageResult:
    """Recover verifiable records from ``source`` into ``out_dir``.

    The source WARC and any sibling CDX are opened read-only; all derived
    files use distinct ``.salvaged`` names so nothing is overwritten.
    """
    source = Path(source)
    out_dir = Path(out_dir)
    if not source.is_file():
        raise FileNotFoundError(source)
    out_dir.mkdir(parents=True, exist_ok=True)
    archive = derived_archive_path(source, out_dir)
    if archive.resolve() == source.resolve():
        raise ValueError("salvage output must not overwrite the source archive")
    cdx = cdx_path_for(archive)
    database = out_dir / "index.sqlite3"
    report_path = out_dir / REPORT_NAME

    source_sha = file_sha256(source)
    scan = scan_archive(source)
    result = SalvageResult(
        source=source,
        out_dir=out_dir,
        damage=list(scan.damage),
        rejected=list(scan.rejected),
        unread_tail=scan.unread_tail(),
        compressed=scan.compressed,
        source_sha256=source_sha,
        report_path=report_path,
    )

    # Walk units and rejected frames together in physical source order so
    # every exclusion is reported at its true position in the archive.
    events = sorted(
        [(unit.record.offset, "unit", unit) for unit in scan.units]
        + [(frame.start, "rejected", frame) for frame in scan.rejected],
        key=lambda item: item[0],
    )

    seen_ids: dict[str, int] = {}
    raw_records: list[RawRecord] = []
    for _, kind, payload in events:
        if kind == "rejected":
            result.excluded.append(
                ExcludedRecord(
                    payload.start,
                    payload.end,
                    "",
                    "unparseable",
                    payload.code,
                    payload.detail,
                )
            )
            continue
        unit = payload
        record = unit.record
        if record.warc_type == "warcinfo":
            result.excluded.append(
                ExcludedRecord(
                    record.offset,
                    record.end_offset,
                    record.record_id,
                    record.warc_type,
                    WARCINFO_SKIP_CODE,
                    "source warcinfo replaced by a derived-archive warcinfo",
                )
            )
            continue
        failure = _verify_record(record, seen_ids)
        if failure is not None:
            result.excluded.append(
                ExcludedRecord(
                    record.offset,
                    record.end_offset,
                    record.record_id,
                    record.warc_type,
                    failure[0],
                    failure[1],
                )
            )
            continue
        seen_ids[record.record_id] = record.offset
        result.retained.append(
            SalvagedRecord(
                unit=unit,
                record_id=record.record_id,
                source_offset=record.offset,
                source_end_offset=record.end_offset,
            )
        )
        raw_records.append(_to_raw(record))

    if not raw_records:
        # No evidence survives: write only the report, never an empty archive.
        _atomic_json(report_path, _report_payload(result, scan))
        return result

    write_raw_archive(archive, raw_records, gzip_compress=scan.compressed)
    data = build_archive_data(archive)
    write_archive_index(data)
    create_database(database, [data])

    # Map every retained record to its new physical offset, then prove the
    # new offsets replay the original response bytes.
    new_records = {r.record_id: r for r in data.records}
    verified: list[SalvagedRecord] = []
    for item in result.retained:
        new_record = new_records[item.record_id]
        if new_record.warc_type == "response":
            replayed = replay_one(archive, new_record.offset, out_dir / "_replay_check")
            if replayed.record.block != item.unit.record.block:
                raise ValueError(
                    f"replay byte mismatch for {item.record_id}; salvage output is not faithful"
                )
        verified.append(
            SalvagedRecord(
                unit=item.unit,
                record_id=item.record_id,
                source_offset=item.source_offset,
                source_end_offset=item.source_end_offset,
                output_offset=new_record.offset,
            )
        )
    result.retained = verified
    shutil.rmtree(out_dir / "_replay_check", ignore_errors=True)

    audit = audit_archives([archive], [cdx])
    if audit.conclusion != "pass":
        raise ValueError(
            "derived archive failed audit: "
            + ", ".join(f"{i.code}@{i.offset}" for i in audit.issues)
        )
    result.archive = archive
    result.cdx = cdx
    result.database = database
    result.output_sha256 = file_sha256(archive)
    result.audit_conclusion = audit.conclusion
    result.recovered_records = len(data.records)
    result.recovered_responses = sum(
        1 for record in data.records if record.warc_type == "response"
    )
    _atomic_json(report_path, _report_payload(result, scan))
    # The source must remain byte-identical after all derived writes.
    if file_sha256(source) != source_sha:
        raise ValueError("source archive changed during salvage")
    return result
