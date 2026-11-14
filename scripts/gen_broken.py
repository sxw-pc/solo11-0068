"""Generate deterministic negative archive fixtures under fixtures/broken."""

from __future__ import annotations

import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from webvault.index.sqlite_index import build_archive_data  # noqa: E402
from webvault.ingest import load_incoming  # noqa: E402
from webvault.warc import read_archive, write_archive  # noqa: E402

BROKEN = ROOT / "fixtures" / "broken"


def _last_record(data: bytes) -> tuple[int, int]:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "base.warc"
        path.write_bytes(data)
        records = read_archive(path).records
        return records[-1].offset, records[0].offset


def _increase_last_length(data: bytes) -> bytes:
    last_offset, _ = _last_record(data)
    segment = data[last_offset:]
    marker = b"Content-Length: "
    index = segment.find(marker)
    end = segment.find(b"\r\n", index)
    declared = int(segment[index + len(marker) : end])
    updated = segment[:index] + marker + str(declared + 64).encode("ascii") + segment[end:]
    return data[:last_offset] + updated


def _flip_digest(data: bytes) -> bytes:
    path = _to_temp(data)
    try:
        result = read_archive(path)
    finally:
        path.unlink(missing_ok=True)
    target = next(record for record in result.records if record.warc_type == "response")
    segment = data[target.offset :]
    marker = b"WARC-Block-Digest: sha256:"
    index = segment.find(marker)
    position = index + len(marker)
    replacement = b"B" if segment[position : position + 1] != b"B" else b"C"
    return data[: target.offset] + segment[:position] + replacement + segment[position + 1 :]


def _to_temp(data: bytes) -> Path:
    handle = tempfile.NamedTemporaryFile(delete=False, suffix=".warc")
    handle.write(data)
    handle.close()
    return Path(handle.name)


def _drift_cdx(text: str, filename: str) -> str:
    lines = []
    offsets = []
    for line in text.splitlines():
        fields = line.split(" ")
        if len(fields) == 9:
            offsets.append(int(fields[7]))
    for number, line in enumerate(text.splitlines()):
        fields = line.split(" ")
        if len(fields) == 9:
            if number == 0 and len(offsets) > 1:
                fields[7] = str(offsets[1])
            fields[8] = filename
        lines.append(" ".join(fields))
    return "\n".join(lines) + "\n"


def _without_warcinfo(data: bytes) -> bytes:
    first_segment = data.find(b"WARC/1.0\r\n")
    second = data.find(b"WARC/1.0\r\n", first_segment + 8)
    return data[second:]


def _rewrite_cdx(
    text: str, filename: str, *, offset_delta: int = 0, orphan: bool = False
) -> str:
    lines = []
    for number, line in enumerate(text.splitlines()):
        fields = line.split(" ")
        if len(fields) == 9:
            fields[8] = filename
            fields[7] = str(int(fields[7]) + offset_delta)
        lines.append(" ".join(fields))
    if orphan:
        lines.append("https://site-c.test/orphan 20240301120000 https://site-c.test/orphan text/html 200 sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA - 999 missing.warc")
    return "\n".join(lines) + "\n"


def main() -> int:
    from gen_fixtures import main as fixtures_main

    fixtures_main()
    BROKEN.mkdir(parents=True, exist_ok=True)
    for child in BROKEN.iterdir():
        if child.is_file():
            child.unlink()
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        loaded = load_incoming(ROOT / "fixtures" / "incoming")
        base_path = tmp_path / "base.warc"
        write_archive(loaded.records, base_path)
        data = base_path.read_bytes()
        archive_data = build_archive_data(base_path)
        cdx_text = "".join(entry.line() for entry in archive_data.entries)
    (BROKEN / "bad_digest.warc").write_bytes(_flip_digest(data))
    (BROKEN / "bad_length.warc").write_bytes(_increase_last_length(data))
    (BROKEN / "truncated.warc").write_bytes(data[:-21])
    (BROKEN / "no_warcinfo.warc").write_bytes(_without_warcinfo(data))
    (BROKEN / "bad_offset.warc").write_bytes(data)
    (BROKEN / "bad_offset.cdx").write_text(
        _drift_cdx(cdx_text, "bad_offset.warc"),
        encoding="utf-8",
        newline="\n",
    )
    (BROKEN / "orphan.cdx").write_text(
        _rewrite_cdx(cdx_text, "missing.warc", orphan=True),
        encoding="utf-8",
        newline="\n",
    )
    with tempfile.TemporaryDirectory() as tmp:
        gz_path = Path(tmp) / "base.warc.gz"
        loaded = load_incoming(ROOT / "fixtures" / "incoming")
        write_archive(loaded.records, gz_path, gzip_compress=True)
        (BROKEN / "bad_gzip.warc.gz").write_bytes(gz_path.read_bytes()[:-12])
    print(f"webvault: generated negative fixtures in {BROKEN}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
