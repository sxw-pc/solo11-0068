"""Structured WARC read errors shared by the reader and gzip layer."""


class WarcReadError(ValueError):
    def __init__(
        self,
        code: str,
        detail: str,
        *,
        offset: int = 0,
        declared: int | None = None,
        actual: int | None = None,
        record_id: str = "",
    ):
        self.code = code
        self.detail = detail
        self.offset = offset
        self.declared = declared
        self.actual = actual
        self.record_id = record_id
        super().__init__(f"{code}: {detail}")


class WarcSourceChangedError(ValueError):
    """Streaming write found spool bytes that no longer match the plan digest."""

    code = "E_SOURCE_CHANGED"

    def __init__(self, detail: str):
        self.detail = detail
        super().__init__(f"{self.code}: {detail}")
