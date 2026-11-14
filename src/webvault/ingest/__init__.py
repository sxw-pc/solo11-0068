"""Capture-drop ingestion."""

from .loader import load_incoming
from .validate import IngestValidationError

__all__ = ["load_incoming", "IngestValidationError"]
