# 归档格式：webvault 支持的 WARC/1.0 子集

本文描述本项目的**字节级约定**。`webvault` 写出的是 WARC/1.0 的一个受控子集；读取器可以容忍部分标准内其它 record 类型，但写出器只产生 `warcinfo`、`response`、`metadata` 三种记录。

## 1. 文件与 record 结构

明文归档是一个连续字节流：

```
WARC/1.0\r\n
WARC-Type: response\r\n
WARC-Record-ID: <urn:uuid:...>\r\n
WARC-Date: 2024-03-01T09:00:00Z\r\n
WARC-Target-URI: https://site-a.test/index.html\r\n
Content-Type: text/html\r\n
WARC-Block-Digest: sha256:...\r\n
Content-Length: <block 字节数>\r\n
\r\n
<block 原始字节>
\r\n\r\n
```

- 所有 WARC 头行必须以 **CRLF**（`\r\n`）结束。
- record 头与 block 之间是一个空 CRLF。
- 一个 record 的 block 结束后写两个 CRLF 作为 record 分隔。分隔符不属于 block。
- 读取器严格拒绝仅 LF、孤立 CR、折行头（obs-fold）以及不可解析的 `Content-Length`。
- WARC 头值按 latin-1 原样保存；写出器拒绝含 CR/LF/NUL 或无法以 latin-1 编码的值。
- 本子集不写 WARC 压缩块（`Content-Encoding`），压缩只发生在文件层的 gzip member。

## 2. `Content-Length` 语义

`Content-Length` **只计算 block 的字节数**，不包含第一行 `WARC/1.0`、不包含 WARC 头、不包含头尾空行，也不包含 record 之间的两个 CRLF。

读取器会读取声明的字节数；若实际可用字节不足，报 `E_LENGTH_MISMATCH`，错误字段包含：

- `offset`：record 起始位置（gzip 中为 member 的物理偏移）；
- `declared`：头中声明的长度；
- `actual`：实际读到的字节数。

本项目不静默截断。写出时若单条 record 序列化后超过 `--max-record-bytes`（默认 4 MiB），直接报 `E_RECORD_TOO_LARGE`，不会写入部分文件。

## 3. 记录顺序与 `warcinfo`

每个归档的第一条记录固定为 `warcinfo`。它的 block 是 UTF-8/ASCII 的 `application/warc-fields`：

| 字段 | 值 |
| --- | --- |
| `software` | `webvault/<version>` |
| `format` | `WARC File Format 1.0` |
| `created` | 归档内最早采集时间（UTC，秒精度）；**不是**运行时钟 |
| `records-expected` | 归档内 WARC record 总数（含 warcinfo、metadata） |

warcinfo 的 `WARC-Record-ID` 由 `uuid5(NAMESPACE_URL, "webvault-warcinfo|<created>|<count>")` 派生。响应记录的 record ID 固定为：

```
<urn:uuid:uuid5(uuid.NAMESPACE_URL, "<canonical-url>|<timestamp>|<digest>")>
```

不使用 `uuid4`，因此相同输入总是得到相同 ID。若存在 redirect，额外写出 metadata 记录，ID 使用相同种子加 `|metadata`。

采集记录按 `(urlkey, timestamp, digest, source)` 排序后写出，保证同一输入与配置的字节输出稳定。

## 4. `response` block

response 的 block 是完整 HTTP 响应：

```
HTTP/1.1 <status> <standard-reason>\r\n
<采集头按原顺序，逐行 CRLF>
\r\n
<原始响应体字节>
```

- 状态行使用标准状态码原因短语（例如 `200 OK`），不执行 HTTP 规范化或重新编码。
- 采集头保持 `meta.json.headers` 的顺序。若缺少 `Content-Length`，写出器补一行实际体长度；已存在时**不改写**。
- 响应体不做解码、换行转换、压缩或脱敏，重放时与 body 逐字节一致。
- `Content-Type` 的媒体类型（分号前部分，小写）同时写入 WARC `Content-Type` 和 CDX `mimetype`；完整参数保留在 HTTP 头中。

## 5. `metadata` 记录

redirect 目标非空时为对应 response 增加一条 metadata：

- `WARC-Type: metadata`
- `WARC-Target-URI`: 原 response 的 canonical URL
- `WARC-Refers-To`: 对应 response 的 record ID
- `Content-Type: application/json`
- block：紧凑、`sort_keys=True` 的 JSON，包含 `format`、`note`、`outlink`、`source_url`，以 UTF-8 编码并带一个 LF 结尾。

## 6. 支持的 WARC-Type

| 类型 | 写出 | 读取 |
| --- | --- | --- |
| `warcinfo` | 是 | 是 |
| `response` | 是 | 是 |
| `metadata` | 是（仅 redirect） | 是 |
| `resource` / `request` / `revisit` / `conversion` / `continuation` | 否 | 识别并保留 |
| 其它任何字符串 | 否 | 归为 `other` 并计数，不报错 |

不实现 WACZ、ARC、HAR、MHTML、WACZ 包或对象存储封装。

## 7. gzip member 约定

`--gzip` / `demo` 使用**每 record 一个独立 gzip member**：

- 固定 member 头：`1f 8b 08 00 00 00 00 00 00 ff`
  - `MTIME = 0`；无 FNAME/FCOMMENT/FEXTRA/FHCRC。
- deflate 流使用 zlib level 9、raw deflate。
- trailer 为 CRC32（大端）与 ISIZE（小端）。
- member 之间无额外字节；一个 member 只包含一个 WARC record 及其分隔符。
- 读取器逐个 member 解压并校验 CRC/ISIZE。遇到损坏时停止当前归档的后续读取，但保留此前成功解析的记录，报 `E_GZIP_CORRUPT`。

## 8. 偏移语义

| 字段 | 明文归档 | gzip 归档 |
| --- | --- | --- |
| `offset` / CDX offset | record 起始物理字节 | member 起始物理字节 |
| `compressed_offset` | 无 | member 起始物理字节 |
| `end_offset` | block 结束后的物理位置 | member 结束物理位置（含 trailer） |
| `block_offset` | block 起始物理字节 | block 在解压后逻辑流中的起始字节 |
| `uncompressed_offset` | 与 `offset` 相同 | record 在解压后逻辑流中的起始字节 |

CDX 的 `offset` 始终取第一列语义，回放与审计都用它找回原记录。

## 9. 互操作性边界

本项目保证**自身写出、自身读取、自身审计与回放**的闭环一致：

1. metadata JSON 是本项目自有 schema；
2. gzip 被拆成每个 record 一个 member，并依赖这一约定计算偏移；
3. CDX 使用保守 URL 规范化与固定字段顺序；
4. digest 采用大写、无填充 base32；
5. 审计把本项目 CDX 与记录的对应关系视为完整性的一部分。

因此不承诺与任意第三方 WARC 工具 100% 互操作。WARC 的基本 record 结构尽量保持标准，以便通用工具读取主体，但本项目不会为第三方方言改变上述字节约定。
