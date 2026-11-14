"""Source-checkout launcher; the installed package lives in ``src/webvault``."""

from pathlib import Path

__path__ = [str(Path(__file__).resolve().parent.parent / "src" / "webvault")]
__version__ = "0.1.0"
