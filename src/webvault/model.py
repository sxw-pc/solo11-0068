"""Core dataclasses shared by ingestion, archival, indexing and audit."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from uuid import NAMESPACE_URL, uuid5

from .digest import sha256_digest
from .urlnorm import canonicalize_url, to_cdx_timestamp, urlkey

HeaderList = tuple[tuple[str, str], ...]


def capture_record_id(url: str, timestamp: str, digest: str) -> str:
    """Deterministic WARC-Record-ID required by the project contract."""
    return f"<urn:uuid:{uuid5(NAMESPACE_URL, f'{url}|{timestamp}|{digest}')}>"


def metadata_record_id(url: str, timestamp: str, digest: str) -> str:
    seed = f"{url}|{timestamp}|{digest}|metadata"
    return f"<urn:uuid:{uuid5(NAMESPACE_URL, seed)}>"


@dataclass
class CaptureRecord:
    url: str
    timestamp: str
    status: int
    method: str
    headers: HeaderList
    mime_type: str
    body: bytes
    source: str = ""
    redirect_url: str | None = None
    note: str | None = None
    body_file: str = ""

    @property
    def digest(self) -> str:
        return sha256_digest(self.body)

    @property
    def urlkey(self) -> str:
        return urlkey(self.url)

    @property
    def cdx_timestamp(self) -> str:
        return to_cdx_timestamp(self.timestamp)

    @property
    def record_id(self) -> str:
        return capture_record_id(self.url, self.timestamp, self.digest)

    @property
    def metadata_id(self) -> str:
        return metadata_record_id(self.url, self.timestamp, self.digest)

    @property
    def size(self) -> int:
        return len(self.body)

    def canonical(self) -> "CaptureRecord":
        canonical = canonicalize_url(self.url)
        if canonical != self.url:
            self.url = canonical
        return self


@dataclass(frozen=True)
class RawRecord:
    """A fully formed WARC record block ready for deterministic serialisation."""

    warc_type: str
    record_id: str
    date: str
    target_uri: str
    content_type: str
    block: bytes
    refers_to: str | None = None


@dataclass
class WarcRecord:
    warc_type: str
    raw_type: str
    record_id: str
    date: str
    target_uri: str
    content_type: str
    block_digest: str
    content_length: int
    headers: HeaderList
    block: bytes
    offset: int
    end_offset: int
    warc_file: str
    compressed: bool = False
    block_offset: int = 0
    block_end_offset: int = 0
    uncompressed_offset: int = 0
    uncompressed_block_offset: int = 0
    uncompressed_block_end_offset: int = 0
    compressed_offset: int | None = None

    def header(self, name: str) -> str | None:
        lower = name.lower()
        for key, value in self.headers:
            if key.lower() == lower:
                return value
        return None

    @property
    def refers_to(self) -> str | None:
        return self.header("WARC-Refers-To")

    @property
    def declared_digest(self) -> str:
        return self.block_digest

    @property
    def computed_digest(self) -> str:
        return sha256_digest(self.block)


@dataclass(frozen=True)
class CdxEntry:
    urlkey: str
    timestamp: str
    original: str
    mimetype: str
    status: int
    digest: str
    redirect: str
    offset: int
    filename: str

    def line(self) -> str:
        redirect = self.redirect or "-"
        return (
            f"{self.urlkey} {self.timestamp} {self.original} {self.mimetype} "
            f"{self.status} {self.digest} {redirect} {self.offset} {self.filename}\n"
        )

    def sort_key(self) -> tuple[str, str, int, str]:
        return (self.urlkey, self.timestamp, self.offset, self.filename)

    @classmethod
    def parse_line(cls, line: str) -> "CdxEntry":
        fields = line.rstrip("\n").split(" ")
        if len(fields) != 9 or any(field == "" for field in fields):
            raise ValueError("CDX line must have exactly 9 non-empty fields")
        redirect = "" if fields[6] == "-" else fields[6]
        try:
            status = int(fields[4])
            offset = int(fields[7])
        except ValueError as exc:
            raise ValueError("CDX status and offset must be integers") from exc
        return cls(
            fields[0],
            fields[1],
            fields[2],
            fields[3],
            status,
            fields[5],
            redirect,
            offset,
            fields[8],
        )


@dataclass
class ArchiveInfo:
    file: str
    size: int
    sha256: str
    record_count: int = 0
    response_count: int = 0
    first_timestamp: str = ""
    last_timestamp: str = ""


@dataclass
class IngestError:
    source: str
    code: str
    detail: str


@dataclass
class IngestResult:
    records: list[CaptureRecord] = field(default_factory=list)
    errors: list[IngestError] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors


@dataclass
class WriteResult:
    path: Path
    records: int
    responses: int
    size: int
    sha256: str


@dataclass
class ReadResult:
    records: list[WarcRecord] = field(default_factory=list)
    errors: list[object] = field(default_factory=list)
    other_count: int = 0
