"""Extract response records and write byte-faithful offline replay files."""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urljoin

from .index.sqlite_index import search_records
from .model import WarcRecord
from .urlnorm import (
    canonicalize_url,
    from_cdx_timestamp,
    normalize_timestamp,
    to_cdx_timestamp,
)
from .warc.errors import WarcReadError
from .warc.headers import HeaderError, split_http_block
from .warc.reader import iter_records

REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
CHAIN_MODES = ("exact_capture", "as_of")


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


# ---------------------------------------------------------------------------
# Chain replay: follow redirects that are proven by the archived responses.
# ---------------------------------------------------------------------------


def _query_candidates(
    db_path: Path | str, url: str, end_cdx: str
) -> list:
    """Fetch every index row for *url* at or before *end_cdx* (stable order)."""
    rows: list = []
    page_offset = 0
    while True:
        page, total = search_records(
            db_path,
            url=url,
            end=end_cdx,
            status=None,
            limit=1000,
            page_offset=page_offset,
        )
        rows.extend(page)
        page_offset += len(page)
        if not page or page_offset >= total:
            break
    return rows


def _row_identity(row) -> tuple[str, str, int]:
    return (row["digest"], row["warc_file"], int(row["offset"]))


def _choose_rows(rows: list, mode: str, anchor_timestamp: str | None):
    """Apply the time-selection semantics shared by the first and later hops.

    ``as_of`` keeps the latest capture not later than the manifest time point.
    ``exact_capture`` pins every hop to the start capture's timestamp.
    Returns ``(timestamp, distinct_rows)``; ``distinct_rows`` is deterministically
    ordered and deduplicated by digest/file/offset.
    """
    if not rows:
        return None, []
    if mode == "exact_capture":
        chosen = anchor_timestamp
    else:
        chosen = max(row["timestamp"] for row in rows)
    matching = [row for row in rows if row["timestamp"] == chosen]
    matching.sort(key=lambda row: (row["digest"], row["warc_file"], int(row["offset"])))
    distinct: list = []
    seen: set[tuple[str, str, int]] = set()
    for row in matching:
        identity = _row_identity(row)
        if identity not in seen:
            seen.add(identity)
            distinct.append(row)
    return chosen, distinct


def _location_values(headers) -> list[str]:
    return [value for name, value in headers if name.lower() == "location"]


def _record_target(record: WarcRecord) -> str:
    try:
        return canonicalize_url(record.target_uri)
    except ValueError:
        return ""


def replay_chain(
    db_path: Path | str,
    archives_root: Path | str | None,
    start_url: str,
    at: str,
    mode: str,
    out_dir: Path | str,
    max_hops: int = 20,
) -> tuple[dict, Path]:
    """Walk archived redirects offline and write a provenance-preserving manifest.

    Only responses already present in the SQLite index are considered.  A hop
    is followed only when the WARC response itself carries exactly one parsable
    ``Location`` header and the status is one of 301/302/303/307/308.  No
    network access is performed and no response is substituted for another.
    """
    if mode not in CHAIN_MODES:
        raise ReplayError("E_BAD_MODE", f"mode must be one of {', '.join(CHAIN_MODES)}")
    try:
        max_hops = int(max_hops)
    except (TypeError, ValueError) as exc:
        raise ReplayError("E_BAD_HOP_LIMIT", "max_hops must be an integer") from exc
    if max_hops < 1:
        raise ReplayError("E_BAD_HOP_LIMIT", "max_hops must be at least 1")
    try:
        if re.fullmatch(r"\d{14}", at or ""):
            at_iso = from_cdx_timestamp(at)
        else:
            at_iso = normalize_timestamp(at)
        at_cdx = to_cdx_timestamp(at_iso)
    except ValueError as exc:
        raise ReplayError("E_BAD_TIMESTAMP", str(exc)) from exc
    try:
        start_url = canonicalize_url(start_url)
    except ValueError as exc:
        raise ReplayError("E_BAD_START_URL", str(exc)) from exc

    db_path = Path(db_path)
    out_dir = Path(out_dir)
    root = Path(archives_root) if archives_root else db_path.parent

    hops: list[dict] = []
    ambiguities: list[dict] = []
    visited: dict[str, int] = {start_url: 1}
    anchor_timestamp: str | None = None
    termination: dict | None = None
    current_url = start_url
    hop_number = 1

    while True:
        rows = _query_candidates(db_path, current_url, at_cdx)
        if not rows:
            later = _query_candidates(db_path, current_url, "99991231235959")
            # Distinguish "not archived at all" from "archived, but only after
            # the requested time point" so a partial chain is not misread.
            code = "E_CAPTURE_AFTER_AT" if later else "E_NO_CDX_TARGET"
            detail = (
                f"{current_url} is only captured after {at_iso}; "
                f"earliest is {min(row['timestamp'] for row in later)}"
                if later
                else f"no indexed response for {current_url} at or before {at_iso}"
            )
            termination = {
                "code": code,
                "detail": detail,
                "hop": hop_number,
                "url": current_url,
            }
            break
        if anchor_timestamp is None:
            # The start capture is the latest one not later than ``at``; its
            # timestamp is what ``exact_capture`` pins every later hop to.
            anchor_timestamp = max(row["timestamp"] for row in rows)
        timestamp, candidates = _choose_rows(rows, mode, anchor_timestamp)
        if not candidates:
            termination = {
                "code": "E_EXACT_CAPTURE_MISSING",
                "detail": (
                    f"no response for {current_url} at exact capture timestamp "
                    f"{anchor_timestamp}"
                ),
                "hop": hop_number,
                "url": current_url,
            }
            break
        row = candidates[0]
        if len(candidates) > 1:
            ambiguities.append(
                {
                    "hop": hop_number,
                    "url": current_url,
                    "timestamp": timestamp,
                    "selected": {
                        "digest": row["digest"],
                        "warc_file": row["warc_file"],
                        "offset": int(row["offset"]),
                    },
                    "candidates": [
                        {
                            "digest": item["digest"],
                            "warc_file": item["warc_file"],
                            "offset": int(item["offset"]),
                        }
                        for item in candidates
                    ],
                }
            )

        archive = _find_archive(root, row["warc_file"])
        if archive is None:
            termination = {
                "code": "E_ARCHIVE_NOT_FOUND",
                "detail": f"archive {row['warc_file']} not found under archives root",
                "hop": hop_number,
                "url": current_url,
            }
            break
        try:
            record = extract_record(archive, int(row["offset"]))
        except ReplayError as exc:
            termination = {
                "code": exc.code,
                "detail": exc.detail,
                "hop": hop_number,
                "url": current_url,
            }
            break
        except WarcReadError as exc:
            termination = {
                "code": exc.code,
                "detail": exc.detail,
                "hop": hop_number,
                "url": current_url,
            }
            break
        except OSError as exc:
            termination = {
                "code": "E_ARCHIVE_UNREADABLE",
                "detail": f"cannot read {row['warc_file']}: {exc}",
                "hop": hop_number,
                "url": current_url,
            }
            break
        if record.warc_type != "response":
            termination = {
                "code": "E_NOT_RESPONSE",
                "detail": (
                    f"record at offset {record.offset} is "
                    f"{record.warc_type or 'unknown'}, not response"
                ),
                "hop": hop_number,
                "url": current_url,
            }
            break

        actual_url = _record_target(record)
        if actual_url != current_url:
            termination = {
                "code": "E_TARGET_URI_MISMATCH",
                "detail": (
                    f"index row for {current_url} points at record for "
                    f"{actual_url or '(invalid target URI)'}"
                ),
                "hop": hop_number,
                "url": current_url,
            }
            break

        hop_output = out_dir / "chain" / f"{hop_number:06d}" / "response.http"
        _atomic_bytes(hop_output, record.block)

        hop: dict = {
            "hop": hop_number,
            "url": current_url,
            "timestamp": timestamp,
            "timestamp_iso": from_cdx_timestamp(timestamp),
            "warc_date": record.date,
            "status": None,
            "cdx_status": int(row["status"]),
            "location": None,
            "locations": [],
            "location_target": None,
            "cdx_redirect": row["redirect"] or "",
            "cdx_redirect_matches": None,
            "warc_file": record.warc_file,
            "offset": record.offset,
            "digest": record.block_digest,
            "output": hop_output.relative_to(out_dir).as_posix(),
            "bytes": len(record.block),
            "outcome": "response",
        }
        hops.append(hop)

        try:
            status, headers, _body = split_http_block(record.block)
        except HeaderError as exc:
            hop["outcome"] = "E_BAD_HTTP_BLOCK"
            termination = {
                "code": "E_BAD_HTTP_BLOCK",
                "detail": str(exc),
                "hop": hop_number,
                "url": current_url,
            }
            break

        hop["status"] = status
        locations = _location_values(headers)
        raw_location = locations[0] if len(locations) == 1 else None
        hop["location"] = raw_location
        hop["locations"] = locations
        hop["cdx_status_matches"] = hop["cdx_status"] == status

        if status in REDIRECT_STATUSES:
            if not locations:
                hop["outcome"] = "E_LOCATION_MISSING"
                termination = {
                    "code": "E_LOCATION_MISSING",
                    "detail": f"redirect status {status} has no Location header",
                    "hop": hop_number,
                    "url": current_url,
                }
                break
            if len(locations) > 1:
                hop["outcome"] = "E_LOCATION_MULTIPLE"
                termination = {
                    "code": "E_LOCATION_MULTIPLE",
                    "detail": (
                        f"redirect status {status} has {len(locations)} Location headers"
                    ),
                    "hop": hop_number,
                    "url": current_url,
                }
                break
            raw_location = locations[0]
            if not raw_location.strip():
                hop["outcome"] = "E_LOCATION_INVALID"
                termination = {
                    "code": "E_LOCATION_INVALID",
                    "detail": f"redirect status {status} has an empty Location header",
                    "hop": hop_number,
                    "url": current_url,
                }
                break
            try:
                target = canonicalize_url(urljoin(current_url, raw_location))
            except (ValueError, UnicodeError) as exc:
                hop["outcome"] = "E_LOCATION_INVALID"
                termination = {
                    "code": "E_LOCATION_INVALID",
                    "detail": f"Location {raw_location!r} is not usable: {exc}",
                    "hop": hop_number,
                    "url": current_url,
                }
                break
            hop["location_target"] = target

            cdx_redirect = row["redirect"] or ""
            if cdx_redirect:
                try:
                    cdx_target = canonicalize_url(cdx_redirect)
                except ValueError:
                    # A relative CDX redirect is interpreted like a Location.
                    try:
                        cdx_target = canonicalize_url(urljoin(current_url, cdx_redirect))
                    except ValueError:
                        cdx_target = None
                if cdx_target != target:
                    hop["cdx_redirect_matches"] = False
                    hop["outcome"] = "E_CDX_WARC_LOCATION_MISMATCH"
                    termination = {
                        "code": "E_CDX_WARC_LOCATION_MISMATCH",
                        "detail": (
                            f"CDX redirect {cdx_redirect!r} does not match WARC "
                            f"Location target {target!r}"
                        ),
                        "hop": hop_number,
                        "url": current_url,
                    }
                    break
                hop["cdx_redirect_matches"] = True
            hop["next_url"] = target
            hop["outcome"] = "redirect"

            if target in visited:
                termination = {
                    "code": "E_REDIRECT_LOOP",
                    "detail": (
                        f"redirect target {target} was already visited at hop "
                        f"{visited[target]}"
                    ),
                    "hop": hop_number + 1,
                    "url": target,
                }
                break
            if len(hops) >= max_hops:
                termination = {
                    "code": "E_HOP_LIMIT",
                    "detail": f"stopped after {max_hops} hop(s)",
                    "hop": hop_number + 1,
                    "url": target,
                }
                break
            visited[target] = hop_number + 1
            current_url = target
            hop_number += 1
            continue

        if locations:
            hop["outcome"] = "E_UNEXPECTED_LOCATION"
            termination = {
                "code": "E_UNEXPECTED_LOCATION",
                "detail": f"status {status} carries a Location header",
                "hop": hop_number,
                "url": current_url,
            }
            break

        hop["outcome"] = "CHAIN_COMPLETE"
        termination = {
            "code": "CHAIN_COMPLETE",
            "detail": f"status {status} is not a redirect",
            "hop": hop_number,
            "url": current_url,
        }
        break

    timestamps = [hop["timestamp"] for hop in hops]
    distinct_timestamps = sorted(set(timestamps))
    mixed = len(distinct_timestamps) > 1
    manifest = {
        "format": "webvault-replay-chain/1",
        "start_url": start_url,
        "at": at_iso,
        "mode": mode,
        "max_hops": max_hops,
        "anchor_timestamp": anchor_timestamp,
        "distinct_timestamps": distinct_timestamps,
        "mixed_timestamps": mixed,
        "status": "complete" if termination and termination["code"] == "CHAIN_COMPLETE" else "incomplete",
        "termination": termination,
        "hops": hops,
        "ambiguities": sorted(
            ambiguities, key=lambda item: (item["hop"], item["url"], item["timestamp"])
        ),
    }
    out_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = out_dir / "chain-manifest.json"
    _atomic_bytes(
        manifest_path,
        (json.dumps(manifest, sort_keys=True, indent=2, ensure_ascii=False) + "\n").encode("utf-8"),
    )
    return manifest, manifest_path
