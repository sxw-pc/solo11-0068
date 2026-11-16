# 网存档房（webvault）

**把本地落盘的网页采集产物封装成可检索、可审计、可逐字节回放的 WARC/1.0 归档。**

`webvault` 是采集链路的下游归档与存证层，不是抓取器。它读取采集系统已经写好的响应快照目录，产出自洽的 WARC、CDX、SQLite 索引、审计报告和离线回放文件。全链路离线、字节确定，运行期不发起任何网络请求。

## 是 / 不是

**是：**

- 本地采集产物的导入、校验与规范化；
- WARC/1.0 子集的写出与流式读取（明文、每记录一个 gzip member）；
- CDX 索引与 SQLite 检索库；
- 归档完整性审计（长度、digest、偏移、record ID、warcinfo、索引对应关系）；
- 按偏移或查询条件做字节级保真的离线回放；
- 归档集 manifest、跨归档去重合并、manifest 增量比较。

**不是：**

- 爬虫、RPA、robots 判定器或 HTTP 客户端；
- WACZ / ARC / HAR / MHTML 转换器；
- 全文搜索引擎；
- Web 产品：`serve` 只是 `127.0.0.1` 上的只读调试视图；
- 压缩转码、内容改写或脱敏工具。

## 快速上手

要求 Python 3.10+，运行期依赖 Flask，测试依赖 pytest。

```bash
# 1. 安装（在仓库根目录）
python -m pip install -e ".[test]"

# 2. 从自带合成 fixture 跑完整演示
make demo
# 等价：python -m webvault demo --out build/demo

# 3. 查看演示产物
ls build/demo
# archive.warc.gz   archive.cdx   index.sqlite3
# audit/audit-report.{json,md}   manifest.json   replay/sample/response.http

# 4. 启动只读本地浏览服务
make serve
# 等价：python -m webvault serve --db build/demo/index.sqlite3
# 打开 http://127.0.0.1:5077/
```

未安装也可从源码目录直接运行：仓库根目录的 `webvault/` 是一个只负责把 `src/webvault` 放进包路径的源码启动垫片。

```bash
python -m pytest -q     # 全绿；不联网、只写 tmp
```

## CLI

| 命令 | 作用 | 关键参数 |
| --- | --- | --- |
| `import` | 校验采集目录并输出 JSON 摘要 | `--incoming DIR [--out FILE]` |
| `build` | 导入 + 写 WARC + CDX + SQLite | `--incoming DIR --out DIR [--gzip] [--archive-name NAME] [--max-record-bytes N]` |
| `index` | 为已有归档重建 CDX 与 SQLite | `--archives DIR_OR_FILE [--out DIR]` |
| `audit` | 审计归档与 CDX，输出 JSON + Markdown | `--archives DIR_OR_FILE [--out DIR] [--db DB]` |
| `replay` | 单条按偏移或批量按查询离线回放 | `--archive FILE --offset N` 或 `--db DB [过滤条件]`，均需 `--out DIR` |
| `replay-chain` | 沿已归档 response 的 `Location` 逐跳回放重定向链 | `--db DB --url URL --at ISO8601 --mode exact_capture\|as_of --out DIR [--max-hops N] [--archives-root DIR]` |
| `manifest` | 生成 manifest；可选跨归档去重合并 | `--archives DIR [--out FILE] [--merge-to FILE]` |
| `diff` | 比较两个 manifest | `before.json after.json [--fail-on removed]` |
| `serve` | 只读本地浏览服务 | `--db DB [--host LOOPBACK] [--port 5077]` |
| `demo` | 从仓库 fixture 跑完整链路 | `--out DIR [--plain]` |

退出码：`0` 成功（含审计 warn、完整链）、`2` 输入/校验错误、`3` 审计 fail / `diff --fail-on removed` 命中 / 链不完整、`4` 内部错误。所有命令输出统一使用 `webvault:` 前缀。

### 链式回放（`replay-chain`）

`replay-chain` 只读取**已建索引**中的 response，不发起网络请求，也不改写 WARC/CDX/输入归档：

- 每一跳用规范化 URL 查 SQLite response 行，再用 `warc_file` + 物理 `offset` 从归档取出原始 response，原样写到 `chain/<六位 hop>/response.http`；
- 只有 301/302/303/307/308 且原始响应头中恰好一个可解析 `Location` 时才继续；相对 `Location` 以当前响应 URL 为基址；
- 必须从 WARC 响应头读 `Location`，并与 CDX `redirect` 列核对；二者不一致时该跳终止并保留冲突证据；
- `exact_capture`：每跳 timestamp 必须与起始 redirect 相同，否则报 `E_EXACT_CAPTURE_MISSING` 并保留已取得的跳（“证据链不完整”）；
- `as_of`：每跳取不晚于 `--at` 的最近 response，可跨时间闭合，manifest 用 `mixed_timestamps` / `distinct_timestamps` 标明混合时点；
- 终止状态各自独立写入 manifest：`E_LOCATION_MISSING`、`E_LOCATION_MULTIPLE`、`E_LOCATION_INVALID`、`E_UNEXPECTED_LOCATION`、`E_NO_CDX_TARGET`、`E_CAPTURE_AFTER_AT`、`E_ARCHIVE_NOT_FOUND`、`E_ARCHIVE_UNREADABLE`、`E_NOT_RESPONSE`、`E_OFFSET_NOT_FOUND`、`E_BAD_HTTP_BLOCK`、`E_REDIRECT_LOOP`、`E_HOP_LIMIT`、`E_CDX_WARC_LOCATION_MISMATCH`、`E_TARGET_URI_MISMATCH`、`CHAIN_COMPLETE`；
- 同 URL 同时间多行按 `(digest, warc_file, offset)` 稳定排序取首行，并在 `ambiguities` 中记录全部候选。

## 目录

```
src/webvault/      核心包：ingest / warc / index / audit / replay / manifest / web
webvault/          未安装时的源码启动垫片（仅转发到 src/webvault）
scripts/           确定性生成 fixtures/incoming 与 fixtures/broken
fixtures/incoming/ 合成采集落盘样例（site-a.test / site-b.test / site-c.test）
fixtures/broken/   负例：截断、长度不符、digest 不符、gzip 损坏、缺 warcinfo、CDX 漂移
fixtures/expected/ golden CDX、审计摘要、manifest 片段
tests/             pytest 测试（离线，tmp_path）
docs/              格式、CDX、审计、合规说明
```

## 常见问题

**为什么不能抓取？**  
本项目是归档层，不是采集层。抓取涉及目标授权、robots、限速、登录态和访问范围，这些不属于“把已落盘产物封装成证据”的职责。运行期完全不发起网络请求，源码也不包含对外 HTTP 调用路径。

**为什么 digest 用 base32？**  
WARC 常用 `sha256:BASE32` 表示块摘要。本项目按 WARC 习惯输出大写、无填充的 base32，既避免与 URL/查询串中的字符混淆，也让 digest 字段可稳定放进空格分隔的 CDX。比较时算法名不区分大小写，载荷按大写无填充规范化。

**为什么 gzip 每个 record 一个 member？**  
这样一条记录损坏不会破坏后续记录，读取器可以报告“已成功解析 N 条”的部分成功语义；偏移可以指向物理 member 起点，便于 CDX 定位和失败隔离。代价是压缩率略低，归档体积略大。member 头固定 `mtime=0`、无文件名，保证字节确定性。

**为什么回放文件叫 `response.http`？**  
它重建的是可直接交给人工或脚本复核的 HTTP 响应字节：状态行 + 原响应头 + 空行 + 原体。它不是重新抓取的页面，也不执行脚本、不补全子资源。

**为什么审计分 pass / warn / fail？**  
归档自身字节完整性问题的严重性高于索引对应关系。格式/长度/digest/gzip/record ID/偏移/孤儿索引/缺失索引是 fail；目标 URI 不合法但记录本体可读是 warn。规则见 `docs/AUDIT.md`。

## 合规声明

**本项目只处理本人采集或已获书面授权的材料。** 使用者应确保对采集内容拥有合法处理权限，遵守目标站点条款、适用法律与隐私要求。仓库内 fixture 全部为确定性合成的 `*.test` 保留域名数据，不含真实域名、真实凭据、真实个人信息或真实业务数据。详见 `docs/COMPLIANCE.md`。
