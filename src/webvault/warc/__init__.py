"""WARC/1.0 subset writer and reader."""

from .reader import WarcReadError, iter_records, read_archive
from .writer import RecordTooLargeError, write_archive, write_raw_archive

__all__ = [
    "RecordTooLargeError",
    "WarcReadError",
    "iter_records",
    "read_archive",
    "write_archive",
    "write_raw_archive",
]
