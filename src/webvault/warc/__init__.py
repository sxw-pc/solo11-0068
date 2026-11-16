"""WARC/1.0 subset writer and reader."""

from .errors import WarcReadError, WarcSourceChangedError
from .reader import iter_records, read_archive
from .writer import RecordTooLargeError, write_archive, write_archive_plan, write_raw_archive

__all__ = [
    "RecordTooLargeError",
    "WarcReadError",
    "WarcSourceChangedError",
    "iter_records",
    "read_archive",
    "write_archive",
    "write_archive_plan",
    "write_raw_archive",
]
