# 审计规则

审计读取归档与同名 CDX，**只读**，不修改任何被审计文件。每次审计产生一个 JSON 报告和一个 Markdown 报告，二者内容同源。

## 结论规则

| 结论 | 条件 | CLI 退出码 |
| --- | --- | --- |
| `pass` | 没有任何 issue | `0` |
| `warn` | 只有 warn 级 issue | `0` |
| `fail` | 至少一个 fail 级 issue | `3` |

issue 按 `(code, warc_file, offset, record_id, detail)` 排序。报告中的 `batch_id` 由归档名、归档 SHA-256、记录数、issue 列表与解析记录数确定性计算，不含运行时间。

## 错误码

### `E_NO_WARCINFO`（fail）

归档为空，或第一条记录不是 `warcinfo`。
`offset` 为第一条记录的位置；空归档为 0。

### `E_LENGTH_MISMATCH`（fail）

record 的 `Content-Length` 与可读字节数不一致，常见于截断文件。
报告字段：

- `offset`：record 起始偏移；
- `declared`：头中声明值；
- `actual`：实际可读字节数。

gzip 中 `offset` 是 member 的物理起始位置。

### `E_DIGEST_MISMATCH`（fail）

`WARC-Block-Digest` 缺失、格式非法，或与实际 block 的 SHA-256 不一致。
detail 同时给出声明值与实算值。摘要按 `sha256:` + 大写无填充 base32 比较；算法名大小写不敏感。

### `E_DUP_RECORD_ID`（fail）

同一归档内 `WARC-Record-ID` 重复。错误挂在**后出现**的记录上，detail 指出首次使用的 offset。跨归档重复不算错误。

### `E_OFFSET_DRIFT`（fail）

CDX 的 `offset` 确实指向一条 response 记录，但至少一个索引字段与记录不一致。核对字段：

`urlkey`、`timestamp`、`original`、`mimetype`、`status`、`digest`、`filename`。

注意 `redirect` 不在漂移核对范围内：它是 metadata 的派生信息，单独读取失败不应把整行判为偏移漂移。

### `E_ORPHAN_CDX`（fail）

CDX 行指向的位置没有归档文件、没有记录，或该位置不是 `response`。常见于归档被替换、记录被删除或 offset 写错。

### `E_MISSING_CDX`（fail）

归档中的 response 没有对应索引项。匹配使用 `(urlkey, timestamp, digest)` 三元组，因此同一 URL 的重复采集不会被误报。索引必须覆盖每一条 response 记录。

### `E_BAD_TARGET_URI`（warn）

`WARC-Target-URI` 无法规范化为合法的 http/https URL（空值、非法 scheme、userinfo、控制字符等），但记录本体仍可读取。检查范围为 `response`、`metadata`、`request`、`resource`、`revisit`。

### `E_GZIP_CORRUPT`（fail）

gzip member 头、deflate 流、CRC32 或 ISIZE 校验失败。读取器保留损坏点之前已成功解析的记录（部分成功语义），审计对剩余记录继续做记录级检查，但偏移与索引对应关系可能不完整。

### `E_MALFORMED_WARC`（fail）

record 结构无法解析，例如：

- 缺少 `WARC/1.0` 起始行；
- 头行未使用 CRLF、存在 obs-fold 或空 header 名；
- `Content-Length` 非整数或为负；
- 缺少 `WARC-Record-ID` 或 `WARC-Date`；
- 记录分隔符不符合约定。

读取错误中未列入已知审计码的内部错误也统一归入此码。

### `E_MALFORMED_CDX`（fail）

CDX 无法读取，或某行不是恰好 9 个非空字段，或 `status`/`offset` 不是整数、timestamp 不是 14 位数字。整个 CDX 文件的解析失败只记一条 issue。

## JSON 报告

顶层字段（`sort_keys=True`、2 空格缩进、末尾 LF）：

```json
{
  "archives": [
    {
      "file": "archive.warc.gz",
      "first_timestamp": "2024-03-01T09:00:00Z",
      "last_timestamp": "2024-03-01T10:05:00Z",
      "records": 10,
      "responses": 8,
      "sha256": "<64 位小写十六进制>"
    }
  ],
  "batch_id": "batch-<16 位十六进制>",
  "by_code": {"E_BAD_TARGET_URI": 1},
  "conclusion": "warn",
  "fail_count": 0,
  "format": "webvault-audit/1",
  "issues": [
    {
      "code": "E_BAD_TARGET_URI",
      "detail": "invalid target URI: ''",
      "offset": 1234,
      "record_id": "<urn:uuid:...>",
      "severity": "warn",
      "warc_file": "archive.warc.gz"
    }
  ],
  "records": 10,
  "warn_count": 1
}
```

`archives[].sha256` 是归档文件本身的 SHA-256；`records` 为成功解析的 WARC record 数，`responses` 为其中 response 数。`by_code` 仅包含出现过的错误码，按码排序。

## Markdown 报告

固定章节顺序：

1. 标题与批次信息：`Batch`、`Conclusion`、`Archives`、`Records parsed`、`Fatal issues`、`Warnings`；
2. `## Issues by code`：错误码计数表，无 issue 时写 `No issues detected.`；
3. `## Issues`：逐条 issue 表（Code / WARC file / Offset / Record ID / Detail）；
4. `## Archives`：文件 SHA-256、record 数、response 数、首末时间。

单元格中的 `|`、CR、LF 会被转义或替换为空格，避免破坏表格。

## 负例样例

`fixtures/broken/` 下每个文件针对一个或多个错误码：

| 文件 | 预期 |
| --- | --- |
| `bad_digest.warc` | `E_DIGEST_MISMATCH` |
| `bad_length.warc` | `E_LENGTH_MISMATCH` |
| `truncated.warc` | `E_LENGTH_MISMATCH` / `E_MALFORMED_WARC` |
| `no_warcinfo.warc` | `E_NO_WARCINFO` |
| `bad_gzip.warc.gz` | `E_GZIP_CORRUPT` |
| `bad_offset.warc` + `bad_offset.cdx` | `E_OFFSET_DRIFT` |
| `orphan.cdx` | `E_ORPHAN_CDX` |

审计多个文件时，issue 会跨文件合并并按固定顺序排序，报告同时给出每个归档的 SHA-256，便于比较两次运行是否针对同一批字节。
