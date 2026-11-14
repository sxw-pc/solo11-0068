"""Command-line interface and local read-only server entry point."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from . import __version__
from .commands import (
    fail,
    log,
    cmd_audit,
    cmd_build,
    cmd_diff,
    cmd_import,
    cmd_index,
    cmd_manifest,
    cmd_replay,
)
from .demo import run_demo

LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}


class VaultParser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        print(f"webvault: error: {message}", file=sys.stderr)
        raise SystemExit(2)


def _parser() -> VaultParser:
    parser = VaultParser(prog="webvault", description="Offline WARC archival toolbox")
    parser.add_argument("--version", action="version", version=f"webvault {__version__}")
    sub = parser.add_subparsers(dest="command", required=True, parser_class=VaultParser)

    import_cmd = sub.add_parser("import", help="validate and summarize a capture drop")
    import_cmd.add_argument("--incoming", required=True)
    import_cmd.add_argument("--out", help="write JSON summary (default: stdout)")
    import_cmd.set_defaults(func=cmd_import)

    build = sub.add_parser("build", help="ingest, write WARC, CDX and SQLite in one step")
    build.add_argument("--incoming", required=True)
    build.add_argument("--out", required=True)
    build.add_argument("--gzip", action="store_true", help="gzip each record as its own member")
    build.add_argument("--archive-name", default=None)
    build.add_argument("--max-record-bytes", type=int, default=4 * 1024 * 1024)
    build.set_defaults(func=cmd_build)

    index = sub.add_parser("index", help="build CDX and SQLite for existing archives")
    index.add_argument("--archives", required=True)
    index.add_argument("--out", default=None)
    index.set_defaults(func=cmd_index)

    audit = sub.add_parser("audit", help="audit archives and CDX indexes")
    audit.add_argument("--archives", required=True)
    audit.add_argument("--out", default=None)
    audit.add_argument("--db", default=None, help="record the audit summary in this index")
    audit.set_defaults(func=cmd_audit)

    replay = sub.add_parser("replay", help="extract response bytes for offline review")
    replay.add_argument("--archive", default=None)
    replay.add_argument("--offset", type=int, default=None)
    replay.add_argument("--db", default=None, help="batch replay by index query")
    replay.add_argument("--out", required=True)
    replay.add_argument("--filename", default="response.http")
    replay.add_argument("--archives-root", default=None)
    replay.add_argument("--url", default=None)
    replay.add_argument("--urlkey-prefix", default=None)
    replay.add_argument("--start", default=None)
    replay.add_argument("--end", default=None)
    replay.add_argument("--mimetype", default=None)
    replay.add_argument("--status", type=int, default=None)
    replay.add_argument("--limit", type=int, default=1000)
    replay.set_defaults(func=cmd_replay)

    manifest = sub.add_parser("manifest", help="build a manifest; optionally merge a set")
    manifest.add_argument("--archives", required=True)
    manifest.add_argument("--out", default=None)
    manifest.add_argument("--merge-to", default=None)
    manifest.add_argument("--merge-report", default=None)
    manifest.set_defaults(func=cmd_manifest)

    diff = sub.add_parser("diff", help="compare two manifest files")
    diff.add_argument("before")
    diff.add_argument("after")
    diff.add_argument("--out", default=None)
    diff.add_argument("--fail-on", choices=["removed"], default=None)
    diff.set_defaults(func=cmd_diff)

    serve = sub.add_parser("serve", help="start the loopback-only read-only browser")
    serve.add_argument("--db", required=True)
    serve.add_argument("--host", default="127.0.0.1", choices=sorted(LOOPBACK_HOSTS))
    serve.add_argument("--port", type=int, default=5077)
    serve.set_defaults(func=cmd_serve)

    demo = sub.add_parser("demo", help="run the full fixture pipeline")
    demo.add_argument("--out", default="build/demo")
    demo.add_argument("--plain", action="store_true", help="write a plain WARC instead of .gz")
    demo.set_defaults(func=cmd_demo)
    return parser


def cmd_serve(args) -> int:
    if args.host not in LOOPBACK_HOSTS:
        fail("serve only accepts a loopback host")
        return 2
    if not 1 <= args.port <= 65535:
        fail("port must be between 1 and 65535")
        return 2
    if not Path(args.db).is_file():
        fail(f"database not found: {args.db}")
        return 2
    from .web.app import create_app

    app = create_app(args.db)
    log(f"serving read-only index on http://{args.host}:{args.port}/")
    app.run(host=args.host, port=args.port, debug=False, use_reloader=False)
    return 0


def cmd_demo(args) -> int:
    result = run_demo(Path(args.out), plain=args.plain)
    for key in (
        "archive",
        "cdx",
        "database",
        "manifest",
        "replay",
        "audit_json",
        "audit_markdown",
    ):
        log(f"{key}: {result[key]}")
    log(
        f"demo complete: {result['responses']} responses, "
        f"{result['records']} WARC records, audit {result['conclusion']}"
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except (FileNotFoundError, ValueError, OSError) as exc:
        fail(str(exc))
        return 2
    except KeyboardInterrupt:
        fail("interrupted")
        return 4
    except Exception as exc:
        if os.environ.get("WEBVAULT_DEBUG"):
            raise
        fail(f"internal error: {type(exc).__name__}: {exc}")
        return 4


if __name__ == "__main__":
    raise SystemExit(main())
