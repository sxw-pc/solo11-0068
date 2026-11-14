"""Record-level archive checks and audit orchestration."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path

from ..digest import digest_equal, file_sha256, sha256_digest
from ..model import ArchiveInfo, WarcRecord
from ..urlnorm import canonicalize_url
from ..warc.reader import read_archive
from .index_checks import check_cdx, load_cdx
from .issues import FATAL_CODES, AuditIssue, add_issue


@dataclass
class AuditReport:
    archives: list[ArchiveInfo] = field(default_factory=list)
    records: int = 0
    issues: list[AuditIssue] = field(default_factory=list)

    @property
    def conclusion(self) -> str:
        if any(issue.severity == "fail" for issue in self.issues):
            return "fail"
        if self.issues:
            return "warn"
        return "pass"

    @property
    def by_code(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for issue in self.issues:
            counts[issue.code] = counts.get(issue.code, 0) + 1
        return dict(sorted(counts.items()))

    @property
    def fail_count(self) -> int:
        return sum(1 for issue in self.issues if issue.severity == "fail")

    @property
    def warn_count(self) -> int:
        return sum(1 for issue in self.issues if issue.severity == "warn")

    @property
    def batch_id(self) -> str:
        material = {
            "archives": [
                {"file": a.file, "sha256": a.sha256, "records": a.record_count}
                for a in self.archives
            ],
            "issues": [issue.to_dict() for issue in self.issues],
            "records": self.records,
        }
        raw = json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return "batch-" + hashlib.sha256(raw).hexdigest()[:16]

    def to_dict(self) -> dict:
        return {
            "format": "webvault-audit/1",
            "batch_id": self.batch_id,
            "conclusion": self.conclusion,
            "records": self.records,
            "archives": [
                {
                    "file": archive.file,
                    "sha256": archive.sha256,
                    "records": archive.record_count,
                    "responses": archive.response_count,
                    "first_timestamp": archive.first_timestamp,
                    "last_timestamp": archive.last_timestamp,
                }
                for archive in self.archives
            ],
            "issues": [issue.to_dict() for issue in self.issues],
            "by_code": self.by_code,
            "fail_count": self.fail_count,
            "warn_count": self.warn_count,
        }


def _info(path: Path, records: list[WarcRecord]) -> ArchiveInfo:
    dates = [record.date for record in records if record.date]
    return ArchiveInfo(
        file=path.name,
        size=path.stat().st_size,
        sha256=file_sha256(path),
        record_count=len(records),
        response_count=sum(1 for record in records if record.warc_type == "response"),
        first_timestamp=min(dates, default=""),
        last_timestamp=max(dates, default=""),
    )


def _check_records(archive: Path, records: list[WarcRecord], issues: list[AuditIssue]) -> None:
    if not records or records[0].warc_type != "warcinfo":
        offset = records[0].offset if records else 0
        add_issue(issues, "E_NO_WARCINFO", archive.name, offset, "", "first record is not warcinfo")
    seen_ids: dict[str, int] = {}
    for record in records:
        if not record.record_id or not record.date:
            add_issue(
                issues,
                "E_MALFORMED_WARC",
                archive.name,
                record.offset,
                record.record_id,
                "record is missing WARC-Record-ID or WARC-Date",
            )
        if record.record_id and record.record_id in seen_ids:
            add_issue(
                issues,
                "E_DUP_RECORD_ID",
                archive.name,
                record.offset,
                record.record_id,
                f"record id already used at offset {seen_ids[record.record_id]}",
            )
        elif record.record_id:
            seen_ids[record.record_id] = record.offset
        try:
            matches = digest_equal(record.block_digest, sha256_digest(record.block))
        except ValueError:
            matches = False
        if not matches:
            add_issue(
                issues,
                "E_DIGEST_MISMATCH",
                archive.name,
                record.offset,
                record.record_id,
                f"declared {record.block_digest or '(missing)'} actual {sha256_digest(record.block)}",
            )
        if record.warc_type in {"response", "metadata", "request", "resource", "revisit"}:
            try:
                target = canonicalize_url(record.target_uri)
            except ValueError:
                target = ""
            if not target:
                add_issue(
                    issues,
                    "E_BAD_TARGET_URI",
                    archive.name,
                    record.offset,
                    record.record_id,
                    f"invalid target URI: {record.target_uri!r}",
                )


def audit_archives(
    archives: list[Path], cdx_files: list[Path] | None = None
) -> AuditReport:
    """Audit archives and their CDX indexes without modifying any archive."""
    unique = sorted({path.resolve(): path for path in archives}.values(), key=lambda p: p.name)
    report = AuditReport()
    cdx_rows = load_cdx(unique, cdx_files, report.issues)
    archive_map: dict[str, list[WarcRecord]] = {}
    for archive in unique:
        result = read_archive(archive)
        report.records += len(result.records)
        archive_map[archive.name] = result.records
        _check_records(archive, result.records, report.issues)
        for error in result.errors:
            code = getattr(error, "code", "E_MALFORMED_WARC")
            if code not in FATAL_CODES:
                code = "E_MALFORMED_WARC"
            add_issue(
                report.issues,
                code,
                archive.name,
                getattr(error, "offset", 0),
                getattr(error, "record_id", ""),
                getattr(error, "detail", str(error)),
            )
        report.archives.append(_info(archive, result.records))
    check_cdx(archive_map, cdx_rows, report.issues)
    report.issues.sort(key=lambda issue: issue.sort_key())
    return report
