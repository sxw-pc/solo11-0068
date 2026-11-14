"""Deterministic JSON and Markdown rendering for audit reports."""

from __future__ import annotations

import json
import os
from pathlib import Path

from .checks import AuditReport


def render_json(report: AuditReport) -> str:
    return json.dumps(
        report.to_dict(), sort_keys=True, indent=2, ensure_ascii=False
    ) + "\n"


def _cell(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def render_markdown(report: AuditReport) -> str:
    lines = [
        "# Archive audit report",
        "",
        f"- Batch: `{report.batch_id}`",
        f"- Conclusion: **{report.conclusion}**",
        f"- Archives: {len(report.archives)}",
        f"- Records parsed: {report.records}",
        f"- Fatal issues: {report.fail_count}",
        f"- Warnings: {report.warn_count}",
        "",
        "## Issues by code",
        "",
    ]
    counts = report.by_code
    if counts:
        lines.extend(["| Code | Count |", "| --- | ---: |"])
        lines.extend(f"| {_cell(code)} | {count} |" for code, count in counts.items())
    else:
        lines.append("No issues detected.")
    lines.extend(["", "## Issues", ""])
    if report.issues:
        lines.extend(
            [
                "| Code | WARC file | Offset | Record ID | Detail |",
                "| --- | --- | ---: | --- | --- |",
            ]
        )
        for issue in report.issues:
            lines.append(
                "| {code} | {file} | {offset} | {record_id} | {detail} |".format(
                    code=_cell(issue.code),
                    file=_cell(issue.warc_file),
                    offset=issue.offset,
                    record_id=_cell(issue.record_id or "-"),
                    detail=_cell(issue.detail),
                )
            )
    else:
        lines.append("No issues detected.")
    lines.extend(
        [
            "",
            "## Archives",
            "",
            "| File | SHA-256 | Records | Responses | First | Last |",
            "| --- | --- | ---: | ---: | --- | --- |",
        ]
    )
    for archive in report.archives:
        lines.append(
            "| {file} | `{sha}` | {records} | {responses} | {first} | {last} |".format(
                file=_cell(archive.file),
                sha=archive.sha256,
                records=archive.record_count,
                responses=archive.response_count,
                first=archive.first_timestamp or "-",
                last=archive.last_timestamp or "-",
            )
        )
    lines.append("")
    return "\n".join(lines)


def _atomic_text(path: Path, text: str) -> None:
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


def write_reports(
    report: AuditReport, out_dir: Path | str, stem: str = "audit-report"
) -> tuple[Path, Path]:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / f"{stem}.json"
    markdown_path = out_dir / f"{stem}.md"
    _atomic_text(json_path, render_json(report))
    _atomic_text(markdown_path, render_markdown(report))
    return json_path, markdown_path
