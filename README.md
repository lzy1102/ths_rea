# ths-trade-client

同花顺柜台交易协议的**纯 Python 客户端**：登录 → 启动序列 → 预检 → 查询 →
**沪/深 × 买/卖 × 市价/限价（8 种委托组合）**，全链路在实盘服务器上验证通过。

- 不依赖同花顺客户端运行（实测：全部 THS 进程退出后裸登录成功）
- 不需要扫码、不需要密码（柜台协议登录帧本身不含密码字段）
- 跨平台：Windows / Linux / WSL / Docker 均实测通过
- 附带**字段提取工具**：别人一条命令即可生成自己的配置（账号/股东号/设备指纹/站点列表）

> ⚠️ **风险提示**：`buy_market()` / `sell_market()` / `limit_order()` 是**真实委托指令**，会真实占用资金/成交。
> 仅供个人学习与自有账户自动化使用，请自行评估合规与资金风险。协议实现自同花顺 Windows
> 客户端（xiadan.exe）逆向，随客户端版本更新可能失效。

---

## 目录

1. [五分钟上手](#五分钟上手)
2. [安装](#安装)
3. [配置（local_profile.json）](#配置local_profilejson)
4. [抓包工具：自动生成配置](#抓包工具自动生成配置)
5. [券商兼容性（换券商怎么办）](#券商兼容性换券商怎么办)
6. [TradeClient API 详解](#tradeclient-api-详解)
7. [市价策略码](#市价策略码)
8. [站点列表与故障切换](#站点列表与故障切换)
9. [设备信息（机器指纹）](#设备信息机器指纹)
10. [推送回报 / 心跳 / 断线重连](#推送回报--心跳--断线重连)
11. [离线测试](#离线测试)
12. [常见问题 FAQ](#常见问题-faq)
11. [服务端常见应答对照](#服务端常见应答对照)
12. [包结构与开发](#包结构与开发)

---

## 五分钟上手

```bash
# 1) 安装（含抓包工具）
pip install "ths-trade-client[capture]"

# 2) 生成配置：开着 xiadan（同花顺下单程序），运行：
ths-capture-profile
#    → 自动抓取并写出 local_profile.json（账号/股东号/设备信息/站点列表）
```

```python
# 3) 使用
from ths_client import TradeClient

cli = TradeClient.from_profile()   # 读 local_profile.json
cli.start()                        # 连接 + 登录 + 启动序列（一行到位）

print(cli.precheck('601398', qty=100)['text'])      # 只读预检（行情/可买数量）
print(cli.buy_market('601398', 100)['text'])        # 真实市价买入 100 股 (沪)
print(cli.buy_market('000001', 100)['text'])        # 深市市价买入 (自动识别市场)
print(cli.sell_market('601398', 100)['text'])       # 真实市价卖出 100 股
cli.close()
```

---

## 安装

### 方式 1：pip（推荐）

```bash
pip install ths-trade-client              # 仅核心（依赖: pycryptodome）
pip install "ths-trade-client[capture]"   # 核心 + 抓包工具（额外依赖: frida）
pip install "ths-trade-client[legacy]"    # 核心 + 旧版网页登录模块（额外依赖: requests）
```

要求：Python ≥ 3.8。

### 方式 2：wheel 分发

```bash
# 构建
python -m pip wheel . -w dist --no-deps
# 安装（拷到任何机器）
pip install ths_trade_client-0.8.0-py3-none-any.whl
```

### 方式 3：源码开发

```bash
git clone https://github.com/lzy1102/ths_rea.git
cd ths_rea
pip install -e .
```

安装后校验：

```python
import ths_client
print(ths_client.__version__)          # 0.8.0
from ths_client import TradeClient, load_profile, parse_kv, machine
```

---

## 配置（local_profile.json）

账号信息**不写入代码**。通过参数或本地配置文件传入；配置文件**不入库、不外发**。

### 生成方式

- 推荐：用抓包工具自动生成（见下节）
- 或手工创建 `local_profile.json`（复制 `local_profile.example.json` 修改）：

```json
{
  "zjzh": "12345678",
  "gdzh_sh": "A123456789",
  "gdzh_sz": "0123456789",
  "name": "某某某",
  "deptid": "1302",
  "verinfo": "gtja"
}
```

### 字段说明

| 字段 | 必填 | 说明 |
|---|---|---|
| `zjzh` | ✅ | 资金账号（登录唯一凭证） |
| `gdzh_sh` | ✅ | 上海股东号，**A 开头**（如 A123456789） |
| `gdzh_sz` | ✅ | 深圳股东号，**数字**（如 0123456789） |
| `name` | 推荐 | 户名（GBK 1~6 字节，如 3 个汉字） |
| `deptid` | 可选 | 营业部ID（默认 1302） |
| `verinfo` | 可选 | 券商标记（默认 `gtja`=国泰君安/国泰海通） |
| `host` / `port` | 可选 | 主柜台地址（默认 114.141.180.27:8002） |
| `hosts` | 可选 | 站点列表 `[{"ip","port","name","area"}...]`，用于故障切换 |
| `machine` | 可选 | 设备指纹（抓包提取；没有则程序自动采集本机） |

### 配置文件查找顺序

`TradeClient.from_profile(path)` 按以下顺序找：

1. 显式传入的 `path`
2. 环境变量 `THS_PROFILE`
3. 当前目录 `./local_profile.json`
4. `~/.ths_trade_profile.json`

### 换账号 / 换券商

| 场景 | 需要改什么 |
|---|---|
| 同券商其他账号 | 改 `zjzh` / `gdzh_sh` / `gdzh_sz` / `name`（或重跑抓包工具） |
| 同券商其他营业部 | 加 `deptid` |
| 其他券商 | 重新抓包（工具自动提取 `verinfo`/柜台地址/站点表）；模板为同花顺框架，预期可用但未跨券商实测 |

---

## 抓包工具：自动生成配置

`ths-capture-profile` 挂载真实 xiadan 客户端的网络层（ws2_32），
在**你正常登录/打开交易界面**的过程中自动抓取并解密，一次性写出完整配置。

### 使用步骤

```bash
# 1. 安装抓包依赖
pip install "ths-trade-client[capture]"

# 2. 运行工具（xiadan 没开也没关系, 工具会等待其启动）
ths-capture-profile

# 3. 触发一次登录:
#    · 若交易窗口已开着  -> 关闭后重新打开 (或重启 xiadan)
#    · 若刚打开同花顺    -> 直接进入下单程序即可
#    工具自动抓取, 完成后自动退出并写出 local_profile.json
```

### 参数

| 参数 | 默认 | 说明 |
|---|---|---|
| `--pid PID` | 自动查找 | 指定 xiadan.exe 进程ID（多开时用） |
| `--out PATH` | `local_profile.json` | 输出配置路径 |
| `--timeout N` | 180 | 最长等待秒数 |

### 输出内容

```
===== 提取结果 (已写入 local_profile.json) =====
  zjzh     = 12345678          ← 资金账号（登录帧）
  gdzh_sh  = A123456789        ← 上海股东号（启动帧解密+0526账户表）
  gdzh_sz  = 0123456789        ← 深圳股东号
  name     = 某某某            ← 户名（启动帧 gdxm=）
  deptid   = 1302              ← 营业部
  verinfo  = gtja              ← 券商标记
  host     = 114.141.180.27    ← 当前柜台
  port     = 8002
  hosts    = 15 个委托站点 (来源 31_WT_SERVER)   ← 站点列表(按抓到的IP匹配券商)
  machine  = (9项设备指纹)     ← hardwarecode/macinfo/cpuinfo/计算机名/...
```

### 原理（供参考）

- 只挂 `ws2_32` 的 `send/recv/connect`（与客户端版本无关）
- 识别柜台连接（`fdff` 帧）→ 登录帧是 zlib 明文直接解；后续帧用 S2C#1 的会话IV解密
- 站点列表从 xiadan 安装目录 `RES/Zyy/ServerAddress/*_WT_SERVER` 解析（按抓到的柜台IP
  匹配对应券商文件；匹配不到不写入，绝不混并其他券商站点）
- 设备信息从登录帧原样提取（比本机采集更真实，跨平台一致）

### 常见问题

- **"未找到 xiadan.exe"** → 先打开同花顺并进入下单程序，或用 `--pid` 指定
- **一直等待** → 需要在客户端完成一次登录（关掉交易窗口重开，或重启 xiadan）
- **提示未匹配站点文件** → 该券商站点文件尚未缓存到本机（客户端登录过一次后就有了）

---

### 委托报文抓包 (扩展协议用)

`ths-capture-orders (pip 命令) / ths_client/capture_orders.py` — 挂 xiadan.exe 的 ws2_32 全量落盘收发帧，抓完后自动
扫描客户端内存中的密钥描述符 (KEY 特征码 `b181838083888d81` + IV 槽) 恢复会话 IV，
**无需重连也能解密全部柜台帧**，产物为 `dec_*_<cmd>.bin` 明文：

```bash
ths-capture-orders --timeout 600    # 期间在客户端做对应操作(如深市卖出)
# 结束后自动输出: dec_*_0221.bin / dec_*_0321.bin ... (明文模板)
```


## 券商兼容性（换券商怎么办）

**结论：不需要为每家券商做协议适配，只需换一份配置。**

这套协议由同花顺客户端（`xiadan.exe`）实现，而非各家券商自研：

- DES 密钥 `b181838083888d81` **编译在客户端二进制里** → 全券商一致
- 帧格式 / zlib / MD5 签名槽 / 会话 IV 机制 / 命令号(0126/0221/0321…) / workid / menuid
  都是客户端层常量 → 全券商一致
- 每家券商不同的只有 6 项**配置**：资金账号、沪/深股东号、户名、营业部 ID(`deptid`)、
  券商标记(`verinfo`)、站点列表(`hosts`)

### 接入新券商（3 步，不改一行代码）

```bash
# 1) 安装该券商的同花顺下单客户端, 登录一次
# 2) 抓配置（券商无关; 按实际连接的IP自动匹配对应券商的站点文件）
ths-capture-profile            # → local_profile.json
# 3) 直接用
python -c "from ths_client import TradeClient; c=TradeClient.from_profile(); c.start(); print(c.query_positions()['columns'])"
```

`start()`（登录+启动序列+预检）跑通即代表该券商协议完全兼容。

### 券商支持状态

| 券商 | 站点文件 | 状态 |
|---|---|---|
| 国泰君安 / 国泰海通 | `31_WT_SERVER` | ✅ 全链路实测（登录/启动/查询/沪深买卖/限价） |
| 中泰证券 | `100_WT_SERVER` | 站点表已解析，未实测 |
| 平安证券 | `59_WT_SERVER` | 站点表已解析，未实测 |
| 模拟盘 | `356_WT_SERVER` | 站点表已解析，未实测 |

### 什么时候才需要额外适配

1. **券商定制版客户端**：少数券商改过 `xiadan.exe`；若改动了加密 KEY，
   `ths-capture-profile` 会解不开（可立刻发现），需重新提取密钥
2. **独立交易客户端**：券商不用同花顺下单端而自研客户端 → 协议完全不同，需从头逆向
3. **柜台校验更严**：少数柜台会校验机器指纹/时间戳 → 用配置里的真实设备信息
   （`machine.py` 多平台自动采集）应对

---

## TradeClient API 详解

### 创建

```python
from ths_client import TradeClient

# 方式1: 配置文件（推荐）
cli = TradeClient.from_profile()                  # 自动查找
cli = TradeClient.from_profile('D:/my/ths.json')  # 指定路径

# 方式2: 显式传参
cli = TradeClient(
    zjzh='12345678',            # 必填: 资金账号
    gdzh_sh='A123456789',       # 上海股东号(A开头)
    gdzh_sz='0123456789',       # 深圳股东号(数字)
    name='某某某',               # 户名(GBK 1~6字节)
    deptid='1302',              # 可选: 营业部
    verinfo='gtja',             # 可选: 券商标记
    host='114.141.180.27',      # 可选: 柜台地址
    port=8002,                  # 可选: 端口
    timeout=20.0,               # 可选: 网络超时(秒)
    hosts=None,                 # 可选: 备用站点列表(故障切换)
    machine_info=None,          # 可选: 设备信息(默认自动采集)
)
```

### 连接与登录

```python
cli.start()      # 一步到位: connect + login + bootstrap(标准+沪市)
# 返回 {'sess': 4字节会话, 'iv': 8字节, 's2c1': 登录应答明文}

# 或分步（需要精细控制时）:
cli.connect(bind_port=0, dump_dir=None)   # bind_port: 固定本地端口; dump_dir: 落盘收发帧(调试)
cli.login()                                # 问候+登录
cli.bootstrap(include_sh=True)             # 启动序列(沪市交易必须含SH组)
cli.close()                                # 或使用 with 语句
```

> 顺序敏感：`login → bootstrap → 业务消息`。跳过 bootstrap 会回"数据包无效：帐户无效"。

### 预检（只读）

```python
r = cli.precheck('601398', qty=100)
print(r['text'])          # 应答文本(含行情: zgj最高/zdj最低/open开盘/cjl成交量...)
print(r['plaintext'])     # 原始明文 bytes
print(r['type'])          # 帧类型 0x50(zlib)/0x10(加密)
kv = parse_kv(r['text'])  # 提取 key=value → dict
```

### 市价买入（真实委托）

```python
r = cli.buy_market('601398', 100)              # 沪市, 100股, 默认策略(五档即成剩撤)
r = cli.buy_market('000001', 100)              # 深市 (代码前缀自动识别市场)
r = cli.buy_market('000001', 100, sjwt=2)      # 指定策略(见下节; 深市默认2=对手方最优)
r = cli.buy_market('601398', 100, zxjg=8.60)   # 指定盘口参考价(默认自动预检获取)
r = cli.buy_market('000001', 100, market='1')  # 显式指定市场
print(r['text'])   # 成功=委托回报; 失败如"资金不足..."
```

### 市价卖出（真实委托）

```python
r = cli.limit_order('601398', 100, 8.50)              # 限价买入 (沪/深自动识别)
r = cli.limit_order('601398', 100, 8.50, is_sell=True)  # 限价卖出
r = cli.sell_market('601398', 100)                     # 沪市卖出需账户持有该证券
r = cli.sell_market('000001', 100)                     # 深市卖出 (自动识别市场)
r = cli.sell_market('601398', 100, bhjg=7.60)          # 指定保护限价(默认=参考价; 仅沪市)
print(r['text'])   # 失败如"当前账户暂未持仓该证券！"
```

### 查询（持仓/委托/成交）

```python
r = cli.query_positions(market='2')   # 持仓/股票余额 (0126); '1'=深市
r = cli.query_orders(market='2')      # 当日委托 (0326)
r = cli.query_trades(market='2')      # 当日成交 (0226)
b = cli.query_balance(market='2')     # 资金明细/余额 (0226 资金查询模板)
a = cli.account_info()               # 账户信息 (沪/深股东号+资金账号, 取自启动应答)
o = cli.market_options()             # 柜台支持的委托类型
allq = cli.query_all(market='2')      # 一次性拉取上面四项
c = cli.cached_query('orders')        # 读取启动序列缓存的应答(不发请求)

# 全参数形式 (market/date/page_roll/dataid/menuid 均可传)
cli.query_positions(market='1', date='20261016', page_roll=1, dataid='S', menuid=161)
cli.query_balance(both_markets=True, date='20261016')   # 沪深合并

# 每个查询返回:
#   plaintext  原始应答明文        columns  列名表(GBK)
#   rows       行标签(沪A股/本币…)  fields   hd1.0二进制字段[(tag,a,b)...]
#   count      字段区条目数        stats     会话统计(SX/T_WR/…)

print(r['columns'])    # 列名表(GBK): 持仓=['买入成本','总盈亏','浮动盈亏(金额)',...]
print(r['stats'])      # SX=2.0&SXL=... 会话统计
print(r['plaintext'])  # 原始应答明文(记录体为客户端 hd1.0 二进制格式)
```

> **参数说明**：`market` '2'=沪/'1'=深；`date` 交易日期 YYYYMMDD（补 jzrq/qsrq）；
> `page_roll` 分页号；`dataid` 数据标识（H=沪/S=深）；`menuid` 菜单号。
>
> **返回字段**：`ok` / `columns` 列名表 / `rows` 行标签 / `fields` hd1.0 二进制字段
> `[(tag,a,b)…]` / `count` 字段数 / `stats` 会话统计 / `plaintext`+`text` 原始明文。
> 数值语义（可用余额/市值/持仓数量）待账户有资金/持仓后对比两次查询确认字段含义。
>
> **委托/成交查询**：柜台对 0326/0226 有会话状态限制（单独重放回"无效请求"），
> 此时自动回退到 `start()` 启动序列中已收到的完整应答（`from_cache=True`）。

### 低层接口（高级用法）

```python
r = cli.send(wire_cmd, plaintext)   # 发送任意已构造明文(需自行保证签名/字段)
r = cli.recv()                      # 接收一帧
cli.conn                            # 底层 TradeConn(收发帧/启动序列/会话)
```

### 应答格式

所有业务方法返回统一字典：

| 键 | 说明 |
|---|---|
| `type` | 帧类型：`0x50`=zlib明文应答；`0x10`=DES加密应答 |
| `plaintext` | 解密解压后的明文 bytes |
| `text` | 明文按 GBK 解码的文本（方便正则/打印） |

---

## 市价策略码

沪市（界面 4 项，来自服务器账户表）：

| 界面选项 | 含义 | `sjwt` |
|---|---|---|
| **1-五档即成剩撤**（默认） | 对手五档连续成交，剩余即撤 | **4** |
| 2-五档即成剩转限 | 剩余转限价挂单 | 5 |
| 3-对手方最优 | 对手方最优价成交 | 2 |
| 4-本方最优 | 本方最优价委托 | 3 |

深市（`trade_msg.SJWT_SZ`）：1-对手方最优→2 / 2-本方最优→3 / 3-即成剩撤→6 / 4-五档即成剩撤→4 / 5-全额成交或撤→7

```python
from ths_client.trade_msg import SJWT_SH, SJWT_SZ
r = cli.buy_market('601398', 100, sjwt=SJWT_SH['五档即成剩转限'])
```

---

## 站点列表与故障切换

柜台有多个站点（主站/南方站点等）。配置里有 `hosts` 时，`connect()` 自动依次尝试：

```python
cli = TradeClient.from_profile()
cli.connect()
print(cli.host_used)     # 实际连上的站点 (ip, port)
```

- 抓包工具自动提取（15 个站点，当前站排第一）
- 主站不可用时自动切换到备用站（实测：切到南方站点 59.36.20.67:18001 登录成功）
- 也可手工指定：`TradeClient(..., hosts=[{'ip':'59.36.20.67','port':18001}])`

---

## 设备信息（机器指纹）

登录/启动帧中包含设备信息（hardwarecode/macinfo/cpuinfo/计算机名/卷序列号/GUID 等）。
服务端**实测不校验**这些字段（占位值也能登录），但真实值更自然（避免被风控关注）。

优先级：

1. **配置里的 `machine`**（抓包提取的真客户端指纹——跨平台最一致）✅ 优先
2. 没有配置时 → **程序自动采集本机**（`ths_client.machine.collect()`，Windows/Linux 均支持；
   容器内缺项自动降级占位值，不阻断登录）

```python
from ths_client import machine
print(machine.collect())   # 查看本机采集结果
```

---

## 推送回报 / 心跳 / 断线重连

客户端启动后即启用**后台读线程**，把柜台的下行帧按类型分流（实测判据）：

| 帧类型 | 含义 | 处理 |
|---|---|---|
| `0x10` | 请求应答（DES 加密） | 交给等待中的调用 |
| `0x50` | **推送**（zlib 明文 k=v） | 进 `pushes` 队列 + `on_push` 回调 |

推送内容为明文键值对，常见字段（实测）：

```
zqdm=600398   zqmc=海澜之家   s_typename=上证Ａ股
zgj=6.0500    zdj=5.9100      open=5.9500     # 最高/最低/开盘
cjje=...      cjl=...                         # 成交金额/成交量
ywzt=E110     zrlx=E  statusflag=D F N       # 业务状态/转让类型/状态标志
```

```python
def on_push(p):
    kv = p['kv']
    print(kv.get('zqdm'), kv.get('zqmc'), kv.get('cjje'))

cli = TradeClient.from_profile(on_push=on_push)
cli.start()

for p in cli.wait_pushes(timeout=5):    # 取待处理推送（成交回报等）
    print(p['kv'])
print(len(cli.pushes), '条历史推送')
```

**心跳**：默认每 30 秒发一个 3 字节保活帧（与真客户端一致），`heartbeat=0` 关闭。

**断线重连**：`auto_reconnect=True`（默认）时，业务请求遇连接错误会自动
`reconnect()`（重新 connect+login+bootstrap）并重试一次：

```python
cli.conn.sock.close()                  # 模拟断线
r = cli.request(cli.buy_market, '601398', 100)   # 自动重连后下单
```

或手动：`cli.reconnect()` / `cli.alive()`。

---

## 离线测试

不连柜台，用抓包脱敏样本做回归（12 项）：

```bash
python tests/test_offline.py       # 或 pytest tests/test_offline.py
```

覆盖：帧组帧/拆帧、DES-CBC+zlib、S2C 解密、md5 签名槽、限价/市价模板逐字节复现、
市价限价字段语义、hd1.0 应答解析、账号占位符补丁、市场推断、组帧长度字段。

---

## 常见问题 FAQ

**Q: 需要先登录同花顺（扫码）吗？**
不需要。柜台登录只认资金账号（协议里没有同花顺凭证）。实测：hexin/xiadan/xiadan-plus
全部退出后，裸登录成功（会话分配+账户数据+行情预检均正常）。

**Q: 单独打开 xiadan 报"检测到还不是同花顺注册用户"？**
那是 xiadan.exe **客户端自己的本地门禁**（THS 商业策略，强制从主程序进入），与券商柜台
协议无关。本客户端直接和柜台通信，不经过 xiadan.exe。

**Q: 提示"资金不足"？**
账户可用资金不够。这是服务器业务拒绝，说明**协议层已完全通过**。入金后即可成交。

**Q: 提示"当前账户暂未持仓该证券！"？**
卖出需要账户先持有该证券。

**Q: 提示"不在引擎接受订单的时间范围 / 网关开关关闭"？**
A股交易时间外（9:30-11:30 / 13:00-15:00）柜台不接单。盘后登录/查询不受影响。

**Q: 为什么市价委托只支持沪市？**
- 市价买入: 沪/深均已实测验证 (深市模板由真客户端操作抓包+逐字节复现)。
  深市实测要点: workid=1(沪2)、bhjg=-1(沪=最新价)、cdr_type=22022(沪0)、默认sjwt=2(对手方最优)。
  注: 柜台对深市市价可能返回 `该交易时间段不允许市价` (业务规则, 与真客户端行为一致)。
- 市价卖出: 沪/深均已实测验证。深市实测要点: workid=2(买1)、menuid=472(买471)、
  wtjg=<最新价6位小数>(买-1)、bhjg=-1、cdr_type=22022、默认sjwt=2。
- 限价委托: 沪/深 × 买/卖 **四组合已实测** (`cli.limit_order`)。实测要点:
  `type=ptwt`(市价=sjwt)、无 `sjwt=` 行、`wtjg=<价6位小数>`、float@0x113=限价正数、
  menuid=买161/卖162(市价471/472)、workid=沪买5/沪卖7/深买6/深卖8。
- 撤单/北交所: 尚未支持。北交所/三板代码 (43/83/87/88/920 前缀) 会明确拒绝,
  不会误发到错误市场。(扩展北交所需: 账户开通北交所权限 + 抓包一次北交所委托)
（需要扩展时用 `ths-capture-orders (pip 命令) / ths_client/capture_orders.py` 抓一次真客户端对应操作即可。）

**Q: 换一台机器/换账号要改什么？**
重跑 `ths-capture-profile` 生成新配置即可（或手改 `local_profile.json`）。

**Q: 登录模板是作者机器的，会有问题吗？**
模板中的账号/股东号/户名/营业部/设备指纹在运行时会被你的配置替换；
其余字段（客户端版本等）为协议公共值。实测跨机器（含 Docker）登录正常。

**Q: 报错/无响应怎么办？**
用 `cli.connect(dump_dir='dump')` 落盘全部收发帧排查；或检查网络能否访问柜台
（`host`/`hosts` 里的地址）。

---

## 服务端常见应答对照

| 应答文本（截取） | 含义 | 处理 |
|---|---|---|
| `资金不足：fund_account_id[...]` | 可用资金不足 | 入金；协议已通过 |
| `当前账户暂未持仓该证券！` | 卖出无持仓 | 先买入/换股 |
| `股票代码<999998>不存在` | 代码不存在 | 用真实代码 |
| `不在引擎接受订单的时间范围！` | 非交易时段 | 交易时段下单 |
| `网关开关关闭[100101101]` | 柜台网关关闭(盘后) | 交易时段下单 |
| `数据包无效：帐户无效` | 未做启动序列 | 调用 `bootstrap()`/`start()` |
| `数据包无效：验证签名错` | 报文被拒(签名/字段问题) | 检查构造参数 |

---

## 包结构与开发

```
ths_client/
├── client.py            # TradeClient 高层 API（推荐入口）
├── trade_conn.py        # 柜台TCP: 问候/登录/会话/收发帧/启动序列
├── trade_msg.py         # 报文构造: 登录/0124预检/0221买入/0321卖出 (模板+MD5签名)
├── machine.py           # 设备信息采集与注入 (Windows/Linux)
├── capture_profile.py   # ths-capture-profile 抓包提取工具
├── trade_crypt/         # DES-CBC + zlib 编解码 (收发双向)
├── data/                # 运行必需模板: hello.bin + startup/ + startup_sh/
└── examples/            # 示例脚本
```

开发工具（仓库内 `tools/`，不随包分发）：`login_watch.py`（登录抓包）、
`deep_capture.py`（报文构建/密钥捕获）等。

```bash
# 离线自测（无网络）
python -c "
from ths_client import trade_msg as TM
from ths_client.trade_crypt.body_codec import body_encrypt, body_decrypt
import hashlib
pt = TM.build_buy_sh_sjwt('601398', 100, sess=bytes(4), zjzh='12345678',
                          gdzh='A123456789', zxjg=8.5, seq=TM.MsgSeq(2), tick=1)
assert hashlib.md5(pt[:8]+bytes(16)+pt[24:]).digest() == pt[8:24]
b, _ = body_encrypt(pt, bytes(8)); assert body_decrypt(b, bytes(8)) == pt
print('OK')
"

# 构建 wheel
python -m pip wheel . -w dist --no-deps
```

协议逆向记录与工作计划：`docs/下单逆向进展-3.md`、`docs/工作计划.md`。

---

## License

MIT
