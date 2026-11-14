"""Scan a capture-drop directory and load valid records without aborting."""

from __future__ import annotations

from pathlib import Path

from ..model import IngestError, IngestResult
from .validate import IngestValidationError, parse_capture


def load_incoming(root: Path | str) -> IngestResult:
    """Load all immediate subdirectories of *root* as capture records.

    Errors are aggregated per capture directory; one broken drop never stops
    the rest of the batch.  Record order is deterministic.
    """
    root = Path(root)
    if not root.is_dir():
        raise FileNotFoundError(f"incoming directory not found: {root}")
    result = IngestResult()
    for record_dir in sorted((p for p in root.iterdir() if p.is_dir()), key=lambda p: p.name):
        source = record_dir.name
        try:
            result.records.append(parse_capture(record_dir, source))
        except IngestValidationError as exc:
            result.errors.append(IngestError(source, exc.code, exc.detail))
        except OSError as exc:
            result.errors.append(IngestError(source, "E_IO", str(exc)))
    result.records.sort(key=lambda r: (r.urlkey, r.timestamp, r.digest, r.source))
    result.errors.sort(key=lambda e: (e.source, e.code, e.detail))
    return result
