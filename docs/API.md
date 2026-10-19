# API 参考 · ths-trade-client

> 与 v0.13.0 实现同步。所有签名均从代码提取，可用 `inspect.signature` 复核。

---

## 1. 快速开始

```python
from ths_client import TradeClient

cli = TradeClient.from_profile()     # 读 local_profile.json
cli.start()                          # connect + login + 启动序列(标准+沪市)
...                                  # 业务调用
cli.close()
```

等价写法：`with TradeClient.from_profile() as cli: cli.start(); ...`

---

## 2. 构造与配置

```python
TradeClient(zjzh, *, gdzh_sh=None, gdzh_sz=None, name='某某某',
            deptid=None, verinfo=None,
            on_push=None,            # 推送回调 fn(dict)
            heartbeat=30.0,          # 心跳间隔秒, 0=关闭
            push_handling=True,      # 启动读线程做应答/推送分流
            auto_reconnect=True,     # 断线自动重连并重试
            host=..., port=8002, timeout=20.0,
            hosts=[...],             # 站点列表(故障切换)
            machine_info=None)       # 设备指纹(缺省自采集)

TradeClient.from_profile(path='local_profile.json', **kw)
```

### local_profile.json 字段

| 字段 | 说明 | 必需 |
|---|---|---|
| `zjzh` | 资金账号 | ✅ |
| `gdzh_sh` / `gdzh_sz` | 沪/深股东号 | 下单/查询对应市场时必需 |
| `name` | 户名(GBK) | 建议 |
| `deptid` / `verinfo` | 营业部 / 券商标记 | 换券商时必需 |
| `host` / `port` | 柜台地址 | 缺省用国泰君安主站 |
| `hosts` | 站点列表(故障切换) | 可选 |
| `machine_info` | 设备指纹 9 项 | 可选(缺省自采集) |

生成：`ths-capture-profile`（券商无关，自动抓取）。

---

## 3. 生命周期

| 方法 | 说明 |
|---|---|
| `connect(bind_port=0, dump_dir=None)` | 建连，按 host→hosts 顺序故障切换 |
| `login() -> dict` | 问候+登录，返回 `{'sess','iv','s2c1'}`；顺带启动读线程/心跳 |
| `bootstrap(include_sh=False) -> list` | 启动序列，返回 `[(wire, 应答dict)]` |
| `bootstrap_sh() -> list` | 沪市扩展启动(0029/0520/0126/0326/0226) |
| `start() -> dict` | connect+login+bootstrap(标准+沪市)，**推荐** |
| `close()` | 关闭连接 |
| `reconnect() -> dict` | 断线重连（重新 start 全流程） |
| `alive() -> bool` | 连接是否健康 |
| `request(fn, *a, **kw)` | 带自动重连的调用：`cli.request(cli.buy_market, '601398', 100)` |

---

## 4. 委托

### 4.1 市价

```python
buy_market(code, qty, sjwt=None, market=None, zxjg=None) -> dict
sell_market(code, qty, sjwt=None, market=None, zxjg=None, bhjg=None) -> dict
```

- `market`：`'2'`=沪 `'1'`=深，缺省按代码前缀推断（`6/9/5x`→沪，`0/2/3`→深；`4/8/920` 前缀**明确拒绝**）
- `sjwt`：市价策略码，缺省 沪=4 / 深=2
- `zxjg`：盘口参考价，缺省用预检应答的 `open=`
- `bhjg`：保护限价（仅沪市卖出有效）

### 4.2 限价

```python
limit_order(code, qty, price, is_sell=False, market=None) -> dict
```

### 4.3 预检 / 行情（只读）

```python
precheck(code, qty=100, market=None) -> dict
quote(code, market=None) -> dict   # 盘中实时快照
```

**盘中预检走推送通道**：交易时段柜台对 0124 的应答以 **0x50 行情推送**返回（不是 0x10），
`precheck()` 已自动兼容（内部同时等两个通道，命中该股票的推送即返回，标 `via_push=True`）。

`quote()` 返回：

```python
{'code': '601398', 'name': '工商银行', 'open': 8.47, 'high': 8.65, 'low': 8.44,
 'last': 8.48, 'volume': 293862980.0, 'amount': 1142580133.0,
 'time': '1509560775', 'via_push': True}
```

| 字段 | 来源 | 说明 |
|---|---|---|
| open/high/low/volume/amount | 推送 k=v 文本 | 当日开盘/最高/最低/成交量/成交额 |
| **last（最新价）** | 推送二进制区 float32 (off=194) | **仅主板沪深验证可靠**（9 只样本） |
| time | `T_JS` | 柜台时间字段 |

⚠️ 创业板(300xxx)/科创板(688xxx) 记录布局不同，取不到 `last`（返回 None，不用未验证的值）；
收盘后柜台改回 0x10 应答，`last` 同样为 None。

### 4.4 各组合实测参数

| 组合 | 报文 | workid | menuid | cdr_type | type | 关键字段 |
|---|---|---|---|---|---|---|
| 沪市市价买 | 0221 | 2 | 471 | 0 | `sjwt` | `wtjg=-1` `bhjg=最新价` |
| 沪市市价卖 | 0321 | 9 | 472 | 0 | `sjwt` | `wtjg=保护限价` `bhjg=保护限价` |
| 深市市价买 | 0221 | 1 | 471 | 22022 | `sjwt` | `wtjg=-1` `bhjg=-1` |
| 深市市价卖 | 0321 | 2 | 472 | 22022 | `sjwt` | `wtjg=最新价` `bhjg=-1` |
| 沪市限价买 | 0221 | 5 | 161 | 0 | `ptwt` | `wtjg=<价6位>` 无 `sjwt` 行 |
| 沪市限价卖 | 0321 | 7 | 162 | 0 | `ptwt` | 同上 |
| 深市限价买 | 0221 | 6 | 161 | 22022 | `ptwt` | 同上 |
| 深市限价卖 | 0321 | 8 | 162 | 22022 | `ptwt` | 同上 |

限价报文长度：沪 592B / 深 600B；市价：沪买 616B / 深买 616B / 沪卖 624B / 深卖 624B。

### 4.5 市价策略码

```python
SJWT_SH = {'五档即成剩撤':4, '五档即成剩转限':5, '对手方最优':2, '本方最优':3}
SJWT_SZ = {'对手方最优':2, '本方最优':3, '即成剩撤':6, '五档即成剩撤':4, '全额成交或撤':7}
```

---

## 5. 查询

```python
query_positions(market=None, date=None, page_roll=None, dataid=None, menuid=None)
query_orders(market=None, ...)        # 0326 委托
query_trades(market=None, ...)        # 0226 成交
query_balance(market=None, date=None, menuid=471, dataid=None, page_roll=1, both_markets=False)
query_all(market=None, date=None)     # 上面四项
cached_query(kind)                    # positions/orders/trades/account/menus —— 读启动缓存, 不发请求
account_info() -> dict                # {'上海A股':股东号, '深圳A股':股东号, 'zjzh':...}
market_options() -> dict              # 柜台支持的委托类型
```

### 返回结构（统一）

```python
{'ok': True,                     # 是否拿到有效表结构
 'columns': ['序号','参考成本',...],   # 列名表(GBK)
 'rows':    ['沪A股','可用',...],     # 行标签
 'fields':  [(0x2836,0,8), ...],   # hd1.0 二进制字段 [(tag,a,b)]
 'count':   19,                   # 记录区字段数
 'stats':   {'SX':'2.0','T_WJR':..., ...},
 'plaintext': b'...', 'text': '...', 'labels': [...], 'from_cache': False}
```

> 数值语义（可用余额/市值/持仓量）需账户有资金或持仓时对比两次查询确认；
> `fields` 已暴露字段原值供 diff。

---

## 6. 推送 / 心跳 / 重连

| 接口 | 说明 |
|---|---|
| `on_push(dict)` | 构造参数。推送 = `type=0x50` zlib 明文 k=v，含 `zqdm/zqmc/zgj/zdj/open/cjje/cjl/ywzt/zrlx/statusflag` |
| `wait_pushes(timeout=1.0) -> list` | 取待处理推送 |
| `cli.pushes` | 最近推送(deque) |
| `cli.conn.send_keepalive()` | 手动发保活 |
| `cli.conn.ack_count` | 保活确认计数（该柜台恒 0，属正常） |
| `cli.conn.start_heartbeat(interval)` / `stop_heartbeat()` | 心跳控制 |
| `cli.conn.start_reader(on_push)` / `stop_reader()` | 读线程控制 |

**分流判据**：应答 `type=0x10`（DES），推送 `type=0x50`（zlib）。

---

## 7. 报文构建（高级）

```python
from ths_client import trade_msg as TM

TM.build_login(*, login_zh, local_ip, localport, server_ip, name=None, deptid=None, verinfo=None)
TM.build_precheck_sh(code, qty, *, sess, zjzh, gdzh, tick=None, seq=None)
TM.build_buy_sh_sjwt(code, qty, *, sess, zjzh, gdzh, zxjg, sjwt=4, ...)
TM.build_sell_sh_sjwt(code, qty, *, sess, zjzh, gdzh, zxjg, bhjg=None, sjwt=4, ...)
TM.build_buy_sz_sjwt(code, qty, *, sess, zjzh, gdzh, zxjg=None, sjwt=2, ...)
TM.build_sell_sz_sjwt(code, qty, *, sess, zjzh, gdzh, zxjg=None, sjwt=2, ...)
TM.build_limit(code, qty, price, *, is_sell, market, sess, zjzh, gdzh, ...)
TM.build_funds_query(*, sess, zjzh, gdzh, market='2', date=None, dataid=None, page_roll=1, menuid=471)
TM.patch_account(pt, zjzh=, gdzh_sh=, gdzh_sz=, name_gbk=)   # 模板占位符注入
TM.patch_broker(pt, deptid=, verinfo=)                          # 券商/营业部字段
TM.guess_market(code) -> '1'|'2'
TM.WIRE_CMD                                           # 命令号表
```

模板均为**脱敏 base64 内嵌**（`_TPL`），仓库不含任何真实账号。

---

## 8. 应答解析

```python
from ths_client import parse as P

P.parse_hd10(pt) -> {'len_a','len_b','count','fields','marker','columns','rows','stats','text'}
P.parse_stats(text) -> dict          # SX=2.0&SXL=... 统计
P.gbk_runs(pt, min_chars=2) -> list  # GBK 文本串
```

---

## 9. 服务端错误对照

| 应答文本 | 含义 |
|---|---|
| `资金不足：fund_account_id[...]` | 可用资金不够（买入检查） |
| `当前账户暂未持仓该证券！` | 卖出无持仓 |
| `该交易时间段不允许市价 OrdType:[1]...` | 该时段不接受此市价类型（柜台规则） |
| `不在引擎接受订单的时间范围！[-013070001]` | 非交易时段 |
| `证券代码 [xxx] 和市场 MarketID [xxx] 在交易信息表中不存在` | 该市场/权限下无此证券（如无北交所权限） |
| `网关开关关闭[100101101]` | 柜台该业务未开 |
| `数据包无效：帐户无效` | 未做启动序列 / dataid 非法 / 账户无效 |
| `无效请求` | 报文不被该上下文接受 |
| `转发错误[88005]` | 柜台日终清算/维护 |
| `客户端确认时间过短` | 连续下单过快 |

---

## 10. 工具

```bash
ths-capture-profile [--out local_profile.json] [--timeout 180]   # 抓配置(券商无关)
ths-capture-orders [--out captures/x] [--timeout 600]           # 抓报文+自动扫IV解密
python -m ths_client.capture_profile|capture_orders              # 等价模块调用
python tests/test_offline.py                                    # 离线回归(12项)
python tools/keysniff.py --timeout 120                          # 嗅探各连接 DES IV
```

---

## 11. 已知限制

- **撤单**：未实现。已锁定命令族（内部 cmd `0x0202`/`0x0302`），柜台返回「功能的服务，敬请谅解」且与报文体无关（服务层拒绝），报文结构需真实挂单后撤单抓包
- **北交所/三板**：代码明确拒绝（需权限 + 抓包）
- **余额/持仓数值**：结构已解析，数值语义待有数据账户确认
- **行情推送**：走 `xiadan-plus` 通道（base64 JSON），不在交易协议内
- **限价单未实盘成交验证**（协议层已到达柜台校验并被受理）
- 模拟盘（trade.10jqka.com.cn）除登录外协议不兼容