"""Read-only salvage of independently verifiable records from broken WARCs."""

from .engine import (
    REPORT_NAME,
    SalvageResult,
    SalvagedRecord,
    derived_archive_path,
    salvage_archive,
)
from .scanner import RejectedFrame, SalvageDamage, SalvageUnit, ScanResult, scan_archive

__all__ = [
    "REPORT_NAME",
    "RejectedFrame",
    "SalvageDamage",
    "SalvageResult",
    "SalvageUnit",
    "SalvagedRecord",
    "ScanResult",
    "derived_archive_path",
    "salvage_archive",
    "scan_archive",
]
