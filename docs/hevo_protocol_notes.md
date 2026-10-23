# Hevo / GMS 行情协议逆向整理

> 更新: 2026-10-23  
> 目标: 把 `decompiled/` 中真正影响 `hevo_client` 实现的结论固化下来，避免换机器或客户端升级后重复逆向。  
> 说明: `decompiled/` 是官方 .NET 程序集的反编译产物，已被 `.gitignore` 忽略；本文不记录账号、Passport、Cookie、交易密码等运行凭据。  
> 相关文档: [接口分析报告](接口分析报告.md)、[请求类型表](request_types.md)、[行情字段表](quote_fields.md)。

---

## 1. 反编译产物索引

当前 `decompiled/` 共 22 个程序集，按用途归类如下。这里是“我们从里面找什么”，不是完整 API 清单。

| 程序集 | 主要用途 | 对 Python 实现的价值 |
|---|---|---|
| `CSharpGMS` | `hxsdk` 的 P/Invoke 封装、会话、`SendRequest` | 确认 GMS 高层调用链和请求号入口 |
| `Hevo.Api.Quotes` | 行情 API、请求目录、字段分发、K线/实时/推送 | 核心：请求号、字段号、周期、复权、字段分桶 |
| `Hevo.Core` | 核心模型、服务器信息、协议基础结构 | 服务器组、响应包、连接模型 |
| `Hevo.Core.Common` / `Hevo.Core.DataModel` / `Hevo.Core.Interfaces` | 数据模型、字段枚举、接口 | 字段类型、数据模型、市场/证券结构 |
| `Hevo.Infrastructure.HttpClients` | HTTP 客户端 | 鉴权、云存储等 HTTP 调用 |
| `Hevo.SelfStock` / `Hevo.SelfStock.Common` | 自选股同步 | 自选股代码串格式、同步接口 |
| `Normandy.Identity.Client` | 身份认证 | 登录/Passport 相关流程 |
| `ThsDomainResolver` | 域名/机房解析 | 服务器发现、域名调度 |
| `Hevo.Sdk` | 对外 SDK | 问财、综合接口，非主行情链路 |
| `Hevo.Api.Web` | 云存储/文件接口 | 附件/配置类 HTTP 接口 |
| `Hevo.Cbas` | 行为/硬件数据采集 | 与行情无关，未接入 |
| `HevoNext.B2CApp` / `Glue` / `Page` / `Widgets` / `UI.Avalonia` | CEF + Avalonia 界面 | 确认“界面什么时候刷新”，不是线协议核心 |
| `HevoNext.Util` / `HevoNext.Resources` | 工具/资源 | 辅助定位，未直接接入 |
| `Hevo.Configuration` | 配置读取 | 路径和默认配置 |

### 查看顺序

1. `Hevo.Api.Quotes`：先找请求号、`datatype`、`codelist`、`period`、`fuquan`。
2. `Hevo.Core` / `Hevo.Core.DataModel`：确认服务器组、市场、响应结构。
3. `CSharpGMS`：确认高层调用最终如何落到 native。
4. `HevoNext.*`：只在确认“官方界面何时发请求”时查看，避免陷入 UI 代码。

---

## 2. 分层与数据流

官方客户端不是只有一条链路：

```text
HevoNext UI / CEF
      |
Hevo.Api.Quotes / Hevo.Sdk
      |
CSharpGMS (P/Invoke)
      |
hxsdk (native)
      |
TCP 行情服务器
```

`hevo_client` 没有复刻 C# UI 和 `hxsdk`，而是直接复刻 native 后面的行情 TCP：

```text
HevoClient
  -> 鉴权 HTTP (verify2 / verify3)
  -> Passport64
  -> 行情 TCP 登录包
  -> BinaryPack(id=..., market=..., code=..., datatype=...)
  -> DataResponseV2 / HxFile
```

需要区分两层：

- **C# 高层**：`SessionClient.SendRequest(ushort requestId, string body, ...)`，body 的具体序列化随 API 版本不同（V2 参数串或 V4 JSON）。
- **Python 直连**：复刻当前验证过的 V2 参数串路径，不依赖 `hxsdk`。

---

## 3. 鉴权

### 3.1 固定协议常量

以下值在 `hevo_client/constants.py`：

| 项 | 值 |
|---|---|
| `APP_ID` | `2022021120720687` |
| 鉴权中心 | `http://auth.10jqka.com.cn/verify2` |
| `DEFAULT_QSID` | `800` |
| 产品名 | `同花顺远航版` |
| `SIGN_VERSION` | `3` |
| 默认客户端版本 | `9.60.71` |
| `PRODUCT_VALUE` | Windows `hevo_`，Linux 空串 |

固定加密材料（AES key/IV、加密后的签名 key）不在此重复，见 `hevo_client/constants.py` 和 `hevo_client/salt.py`。

### 3.2 verify2 登录

`hevo_client/auth.py` 的主流程：

1. `GET /verify2?reqtype=do_rsa&type=get_pubkey` 取 RSA 公钥。
2. 账号、密码分别用 RSA PKCS#1 v1.5 加密，再做“同花顺自定义 Base64 + URL encode”。
3. `POST /verify2`，参数含 `reqtype=unified_login`、`ta_appid`、`rsa_version`。
4. 响应取 `userid`、`sessionid`。
5. `POST /verify2`，参数含 `reqtype=verify`、`product=S01`、`imei`、`userid`、`sessionid`、`qsid=800`、`newwgflag=3` 等。
6. 响应取 `passport` 和 `signature`。
7. 生成 `Passport64`，再构造行情 TCP 登录包。

关键点：

- `qsid=800`。
- `securities=同花顺远航版`。
- `version=3`。
- `newwgflag=3` 是必须项。
- 失败时抛 `AuthError`，不打印凭据。

### 3.3 verify3 / Salt 登录

`hevo_client/salt.py` 是另一条登录链：

| 端点 | 用途 |
|---|---|
| `/verify3/gs` | 取 `dsk` / `dsv` / `ssv` |
| `/verify3/pwd_login` | 首次密码登录 |
| `/verify3/pwd_login_again` | `-10002` 时的二次登录 |

请求头：

```text
X-Auth-AppId
X-Auth-Sign
X-Auth-SignV: 3
X-Auth-Time
X-Auth-Crnd
X-Auth-Ext
```

签名计算：

```text
sha256_hex(body).upper()
= arg
message = "X-Auth-SignV3X-Auth-Time" + timestamp + arg
X-Auth-Sign = HMAC-SHA256(message, sign_key).upper()
```

密码链：

```text
key1 = sha256(crnd + dsk)
ssv  -> XOR -> 取 $ 分段里的值 -> HMAC-SHA256(password, value)
key2 = sha256(dsv)
password2 -> XOR -> Base64 -> RSA -> URL encode
```

`-10002` 表示需要二次登录，响应里会带 `dsk/dsv`。不要把 `passport`、`dsv`、`ssv` 写入日志。

### 3.4 Passport64

`Passport64` 不是简单的 Base64(passport)，结构为：

```text
header:  <hBh>  (总长度, 类型=6, 签名长度)
payload: 加密后的 signature + GBK(passport 文本) + 0x00
外层:   标准 Base64
```

`passport` 文本处理：

1. 去掉 `|signlength...` 之后的内容。
2. 把 `|` 替换成 `\r\n`，末尾再补 `\r\n`。
3. 用 GBK 编码。
4. `signature` 先经过 `encode_signature()`（两字符一组还原字节）。
5. 按上面的头部拼包并 Base64。

`Passport` 里的服务器字段：

| 字段 | 含义 |
|---|---|
| `M_hqdns` | V2 行情服务器组 |
| `M_wg` | V3 服务器组 |
| `M_hq` | V1 行情服务器 |
| `M_zx` | 资讯服务器 |
| `sid` | `id,value;id,value` 形式的会话映射 |
| `signvalid` | 过期时间，格式 `YYYYMMDDHH` |

`is_expired` 的判定是“距离过期不足 12 小时”。

### 3.5 行情 TCP 登录包

`make_auth_bytes()` 生成：

```text
'A'
+ uint16(语言长度) + GBK("zh_CN.GBK")
+ uint16(body 长度) + body
```

body 是 INI 文本：

```text
Ask=login
C-Version=hevo_9.60.71
UserName=<userid>
C-Language=zh_CN.GBK
Qsid=800
Passport64=<...>
VerifyType=1
Mac64=<base64(mac)>
```

登录包必须先于行情请求发送；`HevoClient` 在首次 socket/transport 请求时自动补发。

---

## 4. 服务器解析

### 4.1 服务器条目格式

`hevo_client/servers.py` 按以下结构解析 `Passport` 的服务器字段：

```text
host:port:tags;tags:children:tag_string:?:group_name
```

- 多个服务器组用 `,` 分隔。
- `children` 用 `#` 分隔。
- 每个 child 再用 `-` 分隔，至少包含 `host-port`。
- 端口按 `uint16` 校验；非法端口直接报错。
- `priority`：主组 `Primary`，子组 `Secondary`。

### 4.2 主行情组选择

`select_main_quote_group()`：

1. 第一个 `is_main_quote_server == True` 的组。
2. 否则第一个没有 `tag_string` 的组。
3. 都没有则返回 `None`。

主行情服务标签包含 `16`、`32`、`144` 这些 `OldID` 时，优先级最高。`USHI + USZI`、`USH`、`USZ` 也可作为回退判断。

### 4.3 市场映射

`hevo_client/markets.py`：

- 以 `U/u` 开头的字符串直接转大写，作为市场名。
- 纯数字按 `old_id` 查 `MarketData.xml`。
- 查不到时保留原字符串。
- 3 位大写字母视为父市场标签。
- 服务标签优先按 `int16` 解析成 `old_id`，再映射到市场名。
- `INDEX_MARKETS = USHI, USZI, USTI, UZZI, UTII`，这些市场请求 K线时会剔除 `turnover_rate`。

市场定义文件：`hevo_client/data/MarketData.xml`（同时有 `docs/MarketData.xml`）。

---

## 5. 行情线协议

### 5.1 BinaryPack

请求包固定 13 字节头：

```text
fd fd fd fd
8 个 ASCII 十六进制字符（body 长度）
09
body
```

body 是 GBK 参数串：

```text
id=200&market=USHA&codelist=...&datatype=...&zipversion=2&instance=N
```

规则：

- `zipversion=2` 缺省补上。
- `instance` 缺省时使用全局递增计数器。
- `parameter_dictionary_to_string()` 强制 `id` 必须在第一位。
- 登录包不是 `fd fd fd fd`，而是以 `A` 开头。

### 5.2 DataResponseV2

响应头在偏移 13，长度 17，格式 `<HiIHiB`：

| 字段 | 类型 | 含义 |
|---|---|---|
| `rsp_data_length` | uint16 | 响应数据长度 |
| `instance_id` | int32 | 实例号 |
| `biz_rsp_type` | uint32 | 业务响应类型 |
| `format_flag` | uint16 | 低 8 位数据格式，高 8 位压缩方式 |
| `total_records_length` | int32 | 记录区总长度 |
| `record_count` | uint8 | 记录/分段数 |

数据区从偏移 30 开始。每个分段：

```text
uint32 little-endian length
+ length 字节的 HxFile
```

压缩方式：

- `format_flag & 0xFF00 == 0x100`：Snappy。
- `format_flag & 0xFF00 == 0x200`：zlib。
- `0`：不压缩。

### 5.3 HxFile

`hevo_client/hxfile.py` 解析 `hx1.0` / `hx1.1` / `hx1.2` / `hx1.3`：

| 版本 | 压缩 |
|---|---|
| `hx1.0` | 原始字节 |
| `hx1.1` | 3Sharp/自定义 deflate 子集 |
| `hx1.2` / `hx1.3` | Snappy |

头部 `<6sIIHHI` 共 22 字节：

```text
version[6], record_count, size_with_padding,
single_record_length, data_field_count, extra_data_total_length
```

字段描述 `<IBBH`：

```text
field_id, field_type, field_format, value_length
```

字段值类型：

| `field_type` | 解释 |
|---|---|
| 1 | 字符串（默认 GBK；字段 55 在首字节非 0xFF 时按 UTF-8） |
| 2 | `hxlong` 压缩数值 |
| 3 | little-endian double |
| 4 | int32；字段 1/56 按时间解析 |
| 其他 | 原始 bytes |

`hxlong` 的符号、10 的幂、乘除方向都在高位里；字段 1 是时间字段，K线/分时/逐笔的解析方式不同。

---

## 6. K 线

### 6.1 请求串

`request_candle_v2()` 生成：

```text
id=<210|211|212|213>
&market=<USHA...>
&code=<code>
&start=<start>
&end=<end>
&datatype=<逗号分隔字段号>
&period=<真实周期号>
&fuquan=<Q|B|空>
&fuquanopt=V        # 仅 is_volume_exclude=True 且 fuquan 非空
```

- 未指定 `start` 时，`start = -count`。
- 未指定 `end` 时，`end = 0`。
- 分钟周期时间是 32 位 packed 时间（分/时/日/月/年各占位）。
- 日线及以上和秒周期使用 `YYYYMMDD` 字符串。
- `period` 支持别名，最终都转成真实周期号。

### 6.2 周期映射

| 别名/输入 | 真实 period |
|---|---|
| `trend` | 0 |
| `day` / `daily` / `1d` / `50` | 16384 |
| `week` / `1w` | 20480 |
| `month` / `1M` | 24576 |
| `season` / `1q` | 24579 |
| `year` / `1y` | 28672 |
| `1m` / `one_min` | 12288 |
| `3m` | 12291 |
| `5m` / `five_min` | 12293 |
| `15m` | 12303 |
| `30m` | 12318 |
| `60m` | 12348 |
| `5s` | 12549 |
| `10s` | 12554 |
| `15s` | 12559 |
| `30s` | 12574 |

`resolve_period_id()` 对大于 `12288` 的整数直接透传，便于直接使用真实 period。

### 6.3 复权

| 名称 | 协议值 |
|---|---|
| `Forward` | `Q` |
| `Backward` | `B` |
| `Exclude` | 空串 |

`fuquanopt=V` 表示成交量也做复权。

### 6.4 字段分桶

`distribute_candle_fields()` 把字段拆到四个请求：

| 请求 | 字段范围/规则 |
|---|---|
| `210 CandleBase` | `1..300` 的基础字段 |
| `211 CandleFinancial` | `301..2101`（按 `field_id & 0x0FFF` 判断） |
| `212 CandleCaculation` | 其余计算字段 |
| `213 CandleExtra` | `prev_close=6`、`pre_settlement=66` |

特殊规则：

- 每个请求都自动带 `date_time=1`。
- `DQLTG=2097453` 额外走一次 `211`。
- 指数市场剔除 `turnover_rate=1968584`。

常用字段：

| id | 名称 |
|---|---|
| 1 | `date_time` |
| 5 | `full_code` |
| 6 | `prev_close` |
| 7 | `open` |
| 8 | `high` |
| 9 | `low` |
| 10 | `latest` |
| 11 | `close` |
| 13 | `transaction_volume`（总手） |
| 19 | `transaction_amount`（金额） |
| 55 | `security_name` |
| 56 | `trade_time` |
| 66 | `pre_settlement` |
| 199 | `time_stamp` |
| 2561 | `real_turnover_rate` |
| 68295 | `turnover_NewYestodayrate` |
| 199112 | `rise_percentage` |
| 1968584 | `turnover_rate` |
| 2097453 | `DQLTG` |

### 6.5 合并

`merge_candle_responses()`：

1. 请求号最小的响应（通常是 `210`）作为主表。
2. 用 `(full_code, date_time)` 建索引；没有 `full_code` 时只用 `date_time`。
3. 其他请求只补充主表缺失的字段，不覆盖已有值。
4. 返回合并后的 `list[dict[int, value]]`。

### 6.6 已验证结论

- 210–213 的字段分桶、周期、复权参数已按官方客户端实现复刻。
- 请求串与响应解析有离线差分测试（400 例合并/解析一致）。
- 服务器选择与市场映射有 400 例差分测试。
- `query_kline()` 默认前复权、日线、100 根。

---

## 7. 实时行情

### 7.1 请求

`request_realtime_v2()` 生成：

```text
id=<200|201|202>
&market=<market>
&codelist=<code1,code2,...>
&datatype=<字段号>
```

字段分桶：

- `0 < field_id <= 300` -> `200 RealtimeBase`
- `301 <= (field_id & 0x0FFF) <= 2101` -> `201 RealtimeFinancial`
- 其他 -> `202 RealtimeCaculation`

### 7.2 常用字段

| id | 名称 |
|---|---|
| 5 | `full_code` |
| 6 | `prev_close` |
| 10 | `latest` |
| 19 | `transaction_amount` |
| 48 | `rise_five_minutes` / 涨速 |
| 55 | `security_name` |
| 199112 | `rise_percentage` / 涨幅 |
| 264648 | `rise_amount` / 涨跌 |
| 592888 | `DDE` / 主力净量（候选） |
| 592890 | `DDE_MONEY` / 主力净额（候选） |

`DEFAULT_WATCHLIST_FIELDS` 是自选股默认字段集：

```text
full_code, security_name, rise_percentage, latest,
rise_five_minutes, rise_amount, DDE_MONEY, DDE,
transaction_amount
```

### 7.3 计算字段

`REALTIME_CALCULATOR_FIELDS`：

| 计算字段 | 依赖的基础字段 |
|---|---|
| `199112` 涨幅 | `10` 最新价 + `6` 昨收 |
| `264648` 涨跌 | `10` 最新价 + `6` 昨收 |

`calculate_realtime_field()`：

- 涨幅：`(latest - prev_close) / abs(prev_close) * 100`。
- 涨跌：`latest - prev_close`。
- 昨收为 0 时，涨幅返回 `0.0`；涨跌在异常情况下返回 `NaN`。

计算字段不一定会出现在服务端返回里，所以请求时扩展出基础字段，返回后再本地计算。

### 7.4 自选股代码串

`parse_selfstock_securities()` 解析：

```text
code1|code2|...,market1|market2|...
```

- 第一部分按 `|` 拆代码。
- 第二部分按 `|` 拆市场。
- 市场缺失时默认 `USHA`。
- 数字/旧市场 ID 通过 `parse_market()` 转成市场名。

### 7.5 合并

- 首选按 `full_code=5` 合并多请求/多行。
- 如果响应里没有 `full_code`，但返回行数与请求代码数相同，按请求顺序补 `full_code`。
- `query_quotes()` 会先把请求字段初始化为 `None`，返回后删除未请求字段，并补齐计算字段。

### 7.6 待验证

以下语义不是协议层“已证明”，需要实盘/有权限账号对比确认：

- `48` 是否严格等于“5 分钟涨速”。
- `264648` 是否始终是“涨跌额”。
- `592888` / `592890` 是否分别对应“主力净量 / 主力净额”。
- `query_quotes()` 目前只在离线响应/模拟 transport 上验证，未完成真实账号端到端验证。
- 推送订阅（`10001`–`10207`）尚未接入。

---

## 8. Python 实现映射

| 逆向概念 | Python 位置 |
|---|---|
| RSA/Passport64/verify2 | `hevo_client/auth.py` |
| verify3/Salt/签名头 | `hevo_client/salt.py` |
| 服务器组解析 | `hevo_client/servers.py` |
| 市场/old_id 映射 | `hevo_client/markets.py`、`hevo_client/data/MarketData.xml` |
| 请求包/字段分桶/K线合并 | `hevo_client/binarypack.py` |
| HxFile/Snappy/时间/hxlong | `hevo_client/hxfile.py` |
| 高层客户端 | `hevo_client/client.py` |
| 请求/字段常量 | `hevo_client/constants.py` |
| 请求目录 | `docs/request_types.md`、`docs/RequestTypeV2Data.xml` |
| 字段全表 | `docs/quote_fields.md`、`docs/QuoteFieldData.xml` |

---

## 9. 为什么 `decompiled/` 不提交

- 它是官方客户端程序集的反编译产物，属于第三方程序的派生代码，公开仓库直接提交有版权/分发风险。
- 约 9.5MB，且对应特定客户端版本（Windows `9.60.71` / 麒麟 `2.9.1.2`），客户端升级后容易过期。
- Python 包、测试、CI 都不依赖它；真正需要长期保留的是本文件里的结论。
- `.gitignore` 同时排除了 `decompiled/`、`*.exe`、`*.dll`、`captures/`、`local_profile.json`。

### 换机器怎么办

- **只想使用 Python 包**：重新克隆即可，不需要反编译。
- **还要继续逆向**：把原始安装包和 `decompiled/` 单独备份到移动硬盘/私有仓库；不需要重新反编译已经生成的源码。
- **要重新生成**：从官方客户端程序集运行 `ilspycmd`，每个程序集输出一个 `.decompiled.cs`，再放到 `decompiled/<Assembly>/`。
- 抓包文件、`local_profile.json` 含账号/密钥，也要单独备份，不能提交公开仓库。

如果必须让团队共享反编译源码，建议放私有仓库并确认授权/合规要求，不要放进本公开仓库。

---

## 10. 验证状态与已知缺口

### 已验证

- 鉴权中心响应结构、RSA/Salt 密码链、`Passport64` 组包。
- Passport 服务器组解析、主行情组选择、市场 `old_id` 映射。
- `BinaryPack` 13 字节头、`DataResponseV2` 17 字节信息区、HxFile 解析。
- K线 210–213 请求串、字段分桶、周期/复权、响应合并。
- 上述关键路径有离线差分/回归测试；部分鉴权流程对真实鉴权中心做过请求结构验证。

### 未完成/未验证

- 真实账号的 K线/实时行情端到端调用（当前缺少可用账号密码）。
- `query_quotes()` 的真实服务端响应与官方客户端逐字段对比。
- 推送订阅与长连接推送处理。
- `CSharpGMS` 的 V4 JSON 高层接口；Python 目前走 V2 参数串。
- 字段 `48`、`264648`、`592888`、`592890` 的业务语义。
- 客户端升级后的兼容性；请求号/字段号可能变化。

---

## 11. 参考

- [接口分析报告](接口分析报告.md)
- [请求类型表](request_types.md)
- [行情字段表](quote_fields.md)
- [K线/实时请求目录](RequestTypeV2Data.xml)
- [行情字段原始定义](QuoteFieldData.xml)
- [市场定义](MarketData.xml)
- [交易协议逆向进展](下单逆向进展-3.md)
- `hevo_client/`：Python 实现
- `decompiled/`：本地反编译参考，已 gitignore
