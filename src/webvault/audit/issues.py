"""Audit issue types and severity rules."""

from __future__ import annotations

from dataclasses import dataclass

FATAL_CODES = {
    "E_NO_WARCINFO",
    "E_LENGTH_MISMATCH",
    "E_DIGEST_MISMATCH",
    "E_DUP_RECORD_ID",
    "E_OFFSET_DRIFT",
    "E_ORPHAN_CDX",
    "E_MISSING_CDX",
    "E_GZIP_CORRUPT",
    "E_MALFORMED_WARC",
    "E_MALFORMED_CDX",
}
WARN_CODES = {"E_BAD_TARGET_URI"}


@dataclass
class AuditIssue:
    code: str
    warc_file: str
    offset: int
    record_id: str
    detail: str

    @property
    def severity(self) -> str:
        return "warn" if self.code in WARN_CODES else "fail"

    def to_dict(self) -> dict:
        return {
            "code": self.code,
            "warc_file": self.warc_file,
            "offset": self.offset,
            "record_id": self.record_id,
            "detail": self.detail,
            "severity": self.severity,
        }

    def sort_key(self) -> tuple:
        return (self.code, self.warc_file, self.offset, self.record_id, self.detail)


def add_issue(issues, code: str, warc_file: str, offset: int = 0, record_id: str = "", detail: str = "") -> None:
    issues.append(AuditIssue(code, warc_file, offset, record_id, detail))
