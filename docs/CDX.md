# CDX 索引格式

`webvault` 为每个归档生成同名 `.cdx` 文件，例如 `archive.warc.gz` → `archive.cdx`。CDX 行使用 **LF** 行尾，字段之间恰好一个 ASCII 空格，共 9 个字段：

```
urlkey timestamp original mimetype status digest redirect offset filename
```

## 字段

| # | 字段 | 规则 |
| ---: | --- | --- |
| 1 | `urlkey` | SURT 风格键，见下 |
| 2 | `timestamp` | 14 位 UTC：`YYYYMMDDhhmmss` |
| 3 | `original` | 规范化后的 canonical URL，不含 fragment |
| 4 | `mimetype` | WARC `Content-Type` 的媒体类型部分，小写，无参数 |
| 5 | `status` | HTTP 状态码十进制整数 |
| 6 | `digest` | `sha256:` + 大写无填充 base32 |
| 7 | `redirect` | metadata 中的 `outlink`；没有时为单个 `-` |
| 8 | `offset` | record 定位偏移；gzip 中为 member 起始物理偏移 |
| 9 | `filename` | 归档文件 basename，不含目录 |

CDX 只收录 `response` 记录；`warcinfo` 与 `metadata` 不单独成行。redirect 信息从同一 response 的 metadata `WARC-Refers-To` 关联取得。

## URL 规范化与 urlkey

规范化是保守的，目标是确定性而不是“猜出”规范形式：

- 仅接受 `http` / `https`；
- scheme 与 host 小写；
- 去掉 fragment；
- 去掉默认端口 80/443，保留非默认端口；
- 空路径补 `/`；
- 百分号转义统一为大写十六进制；非法转义拒绝；
- 路径与 query 做必要字符转义，但**不重排 query 参数**，也不删除重复参数；
- 拒绝 URL 中的 userinfo（用户名/密码）和裸空白或控制字符。

urlkey 形如：

```
scheme://(host 反转,标签,顺序)[:port]/path[?query]
```

示例：

| URL | urlkey |
| --- | --- |
| `https://site-a.test/index.html?b=2&a=1` | `https://(test,site-a)/index.html?b=2&a=1` |
| `http://site-b.test:8080/` | `http://(test,site-b:8080)/` |

非默认端口写在 host 括号内部。默认端口和 fragment 不会出现在 urlkey 中。query 顺序原样保留，因此 `?b=2&a=1` 与 `?a=1&b=2` 是两个不同键。

## 排序与去重

1. 按 `urlkey` 字典序升序；
2. 相同 urlkey 按 `timestamp` 升序；
3. `(urlkey, timestamp, digest)` 完全相同的行去重，保留 `offset` 最小者；若 offset 相同，保留 filename 字典序最小者；
4. 写出前按最终顺序重新排列，行间以单个 `\n` 连接，文件末尾有一个 `\n`。

## 5 行真实输出

以下来自 `python -m webvault demo` 的 `build/demo/archive.cdx`（域名均为保留测试域）：

```
http://(test,site-b)/assets/style.css 20240301100300 http://site-b.test/assets/style.css text/css 200 sha256:S7HXP24ZTCO4CLTQ4XVV4PCRMB4E6RSDRYXF5UR4MIUAADPALHXA - 299 archive.warc.gz
http://(test,site-b)/redirect 20240301100000 http://site-b.test/redirect text/html 301 sha256:WEJMZFUSUP33BLPLJZDG77LUR3LSMFPCHLFE3XBWJZCI7CSJD57A https://site-c.test/landing 655 archive.warc.gz
https://(test,site-a)/about.html 20240301090200 https://site-a.test/about.html text/html 200 sha256:IIBJUF4XK7TNFP5LTVAYYVHACGTC57V6H7OB63U4YZ3CRHALWQQQ - 1407 archive.warc.gz
https://(test,site-a)/data.json 20240301090400 https://site-a.test/data.json application/json 200 sha256:MFYHMYBNDUNAXIL2B476SDIZHMBAMGJEHSOHZN2IJS2DSNB7NDUQ - 1806 archive.warc.gz
https://(test,site-a)/index.html?b=2&a=1 20240301090000 https://site-a.test/index.html?b=2&a=1 text/html 200 sha256:BZ6A74TEEGWZDDYNWICM4O7RUIICJ66KXTOKOC7ZD2QTY55RZSOQ - 2161 archive.warc.gz
```

## 读取与审计

`webvault.index.cdx.read_cdx` 严格校验 9 个非空字段、整数 status/offset 和 14 位数字 timestamp。审计在 `offset` 处查找对应 response，并核对 `urlkey`、时间、原始 URL、MIME、状态、digest 与 filename；任一不一致报 `E_OFFSET_DRIFT`。索引指向不存在的记录报 `E_ORPHAN_CDX`，归档 response 无对应索引键报 `E_MISSING_CDX`。完整错误码见 `docs/AUDIT.md`。

CDX 自身不包含版本头、注释行或时间戳生成信息，因此同一归档的索引输出可逐字节复现。
