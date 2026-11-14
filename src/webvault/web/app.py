"""Flask application factory for the loopback-only archive browser."""

from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlsplit

from flask import Flask, abort, redirect, render_template, request, url_for

from ..index.sqlite_index import (
    get_record,
    list_archives,
    list_audits,
    search_records,
)
from ..replay import ReplayError, extract_record
from ..warc.headers import split_http_block

ALLOWED_HOSTS = {"127.0.0.1", "localhost", "::1"}


def _hexdump(data: bytes) -> str:
    lines = []
    for offset in range(0, len(data), 16):
        chunk = data[offset : offset + 16]
        hex_part = " ".join(f"{byte:02x}" for byte in chunk).ljust(47)
        text = "".join(chr(byte) if 32 <= byte < 127 else "." for byte in chunk)
        lines.append(f"{offset:08x}  {hex_part}  |{text}|")
    return "\n".join(lines)


def _host_allowed(raw_host: str) -> bool:
    parsed = urlsplit("//" + raw_host)
    return parsed.hostname in ALLOWED_HOSTS


def _archive_path(db_path: Path, filename: str) -> Path | None:
    direct = db_path.parent / filename
    if direct.is_file():
        return direct
    for candidate in sorted(db_path.parent.rglob(filename)):
        if candidate.is_file():
            return candidate
    return None


def create_app(db_path: Path | str) -> Flask:
    db_path = Path(db_path).resolve()
    if not db_path.is_file():
        raise FileNotFoundError(f"database not found: {db_path}")
    app = Flask(__name__)
    app.config.update(SECRET_KEY=None, JSON_SORT_KEYS=False)

    @app.before_request
    def enforce_loopback_host():
        if not _host_allowed(request.host):
            abort(403)

    @app.context_processor
    def common():
        return {"archive_db": db_path.name}

    @app.get("/")
    def home():
        return redirect(url_for("archives"))

    @app.get("/archives")
    def archives():
        return render_template(
            "archives.html",
            mode="archives",
            page_title="Archives",
            archives=list_archives(db_path),
        )

    @app.get("/audit")
    def audit_page():
        audits = []
        for row in list_audits(db_path):
            try:
                report = json.loads(row["report_json"])
            except (TypeError, json.JSONDecodeError):
                report = {"issues": [], "by_code": {}}
            audits.append({"summary": row, "report": report})
        return render_template(
            "archives.html",
            mode="audit",
            page_title="Audit reports",
            audits=audits,
        )

    @app.get("/records")
    def records():
        status_raw = request.args.get("status", "").strip()
        page = max(1, request.args.get("page", 1, type=int))
        filters = {
            "url": request.args.get("url", "").strip() or None,
            "urlkey_prefix": request.args.get("urlkey", "").strip() or None,
            "start": request.args.get("start", "").strip() or None,
            "end": request.args.get("end", "").strip() or None,
            "mimetype": request.args.get("mimetype", "").strip() or None,
            "status": None,
        }
        error = None
        rows, total = [], 0
        try:
            if status_raw:
                filters["status"] = int(status_raw)
            rows, total = search_records(
                db_path, limit=25, page_offset=(page - 1) * 25, **filters
            )
        except (ValueError, TypeError) as exc:
            error = str(exc)
        pages = max(1, (total + 24) // 25)

        def page_url(number: int) -> str:
            args = request.args.to_dict(flat=True)
            args["page"] = number
            return url_for("records", **args)

        return render_template(
            "records.html",
            mode="search",
            page_title="Records",
            rows=rows,
            total=total,
            page=page,
            pages=pages,
            page_url=page_url,
            error=error,
            filters=filters,
            status_raw=status_raw,
        )

    @app.get("/records/<int:record_id>")
    def record_detail(record_id: int):
        row = get_record(db_path, record_id)
        if row is None:
            abort(404)
        block = b""
        response_headers = ()
        body = b""
        warc_headers = ()
        detail_error = None
        archive = _archive_path(db_path, row["warc_file"])
        if archive is None:
            detail_error = "archive file not found"
        else:
            try:
                record = extract_record(archive, row["offset"])
                if record.warc_type != "response":
                    raise ReplayError("E_NOT_RESPONSE", record.warc_type)
                block = record.block
                warc_headers = record.headers
                _, response_headers, body = split_http_block(record.block)
            except (ReplayError, ValueError) as exc:
                detail_error = str(exc)
        preview = body[:4096]
        return render_template(
            "records.html",
            mode="detail",
            page_title=f"Record {record_id}",
            row=row,
            warc_headers=warc_headers,
            response_headers=response_headers,
            body_size=len(body),
            body_preview_size=len(preview),
            hexdump=_hexdump(preview),
            text_view=preview.decode("utf-8", errors="replace"),
            detail_error=detail_error,
            block_size=len(block),
        )

    @app.errorhandler(403)
    def forbidden(error):
        return "Forbidden: loopback Host required", 403

    return app
