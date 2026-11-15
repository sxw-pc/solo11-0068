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
| `salvage` | 只读抢救损坏 WARC 中仍可独立核验的记录 | `--archive FILE --out DIR`（绝不覆盖原 WARC/CDX） |
| `manifest` | 生成 manifest；可选跨归档去重合并 | `--archives DIR [--out FILE] [--merge-to FILE]` |
| `diff` | 比较两个 manifest | `before.json after.json [--fail-on removed]` |
| `serve` | 只读本地浏览服务 | `--db DB [--host LOOPBACK] [--port 5077]` |
| `demo` | 从仓库 fixture 跑完整链路 | `--out DIR [--plain]` |

退出码：`0` 成功（含审计 warn）、`2` 输入/校验错误、`3` 审计 fail 或 `diff --fail-on removed` 命中、`4` 内部错误。所有命令输出统一使用 `webvault:` 前缀。

### salvage 抢救语义

`salvage` 采用方案 B（member 重新定位 + 隔离校验），在 gzip member 或 WARC 记录损坏后仍可恢复其后完整采集，而不是在首个损坏点截断：

- 对 gzip 多 member 归档，逐个依据各自 gzip 头独立定位并用同一 CRC/size 规则校验；某 member 失败后通过扫描下一个 gzip magic 重新同步，绝不“跳过一次异常后盲目继续”。plain WARC 则按 `WARC/1.0` 帧标记重新同步。
- 记录仅在通过与 `audit/checks.py` 相同的规则时入库：record ID 非空且唯一、`Content-Length` 与 block 长度一致、block digest 正确、需要 target URI 的类型其 URI 可规范化。重复 ID、digest 错误、不完整记录一律排除，并在 `recovery-report.json` 写明来源物理 offset 与原因。
- 输出写入 `<stem>.salvaged.warc[.gz]`、同名 `.cdx` 与 `index.sqlite3`，文件名与源归档不同，源 WARC/CDX 字节保持不变，重复运行输出确定。
- 每条保留记录在报告中对齐“源 offset → 输出 record ID → 新 offset”，并实际以新 offset 回放，校验响应字节与源 block 完全一致；未读取尾部以 `unread_tail` 标注。派生归档随后必须通过现有 `audit`（结论 `pass`）。无任何记录通过核验时只写报告、退出码 `2`，不产生空归档。

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
