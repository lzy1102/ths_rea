# ths-trade-client

同花顺柜台交易协议的**纯 Python 客户端**：登录 → 启动序列 → 预检 → **沪市市价委托（买/卖）**，
全链路在实盘服务器上验证通过。

- 不依赖同花顺客户端运行（实测：全部 THS 进程退出后裸登录成功）
- 不需要扫码、不需要密码（柜台协议登录帧本身不含密码字段）
- 跨平台：Windows / Linux / WSL / Docker 均实测通过
- 附带**字段提取工具**：别人一条命令即可生成自己的配置（账号/股东号/设备指纹/站点列表）

> ⚠️ **风险提示**：`buy_market()` / `sell_market()` 是**真实委托指令**，会真实占用资金/成交。
> 仅供个人学习与自有账户自动化使用，请自行评估合规与资金风险。协议实现自同花顺 Windows
> 客户端（xiadan.exe）逆向，随客户端版本更新可能失效。

---

## 目录

1. [五分钟上手](#五分钟上手)
2. [安装](#安装)
3. [配置（local_profile.json）](#配置local_profilejson)
4. [抓包工具：自动生成配置](#抓包工具自动生成配置)
5. [TradeClient API 详解](#tradeclient-api-详解)
6. [市价策略码](#市价策略码)
7. [站点列表与故障切换](#站点列表与故障切换)
8. [设备信息（机器指纹）](#设备信息机器指纹)
9. [常见问题 FAQ](#常见问题-faq)
10. [服务端常见应答对照](#服务端常见应答对照)
11. [包结构与开发](#包结构与开发)

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
print(cli.buy_market('601398', 100)['text'])        # 真实市价买入 100 股
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

# 2. 打开同花顺 → 进入下单程序（xiadan）

# 3. 运行工具（自动查找 xiadan.exe）
ths-capture-profile

#    挂载成功后，在客户端里正常操作（登录/打开交易界面）即可
#    抓全后自动退出并写出 local_profile.json
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
r = cli.buy_market('601398', 100)              # 100股, 默认策略(五档即成剩撤)
r = cli.buy_market('601398', 100, sjwt=5)      # 指定策略(见下节)
r = cli.buy_market('601398', 100, zxjg=8.60)   # 指定盘口参考价(默认自动预检获取)
print(r['text'])   # 成功=委托回报; 失败如"资金不足..."
```

### 市价卖出（真实委托）

```python
r = cli.sell_market('601398', 100)                     # 卖出需账户持有该证券
r = cli.sell_market('601398', 100, bhjg=7.60)          # 指定保护限价(默认=参考价)
print(r['text'])   # 失败如"当前账户暂未持仓该证券！"
```

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
深市市价模板尚未抓取验证。代码会明确报 `NotImplementedError`，不会误发。
（需要深市/限价/撤单支持时，用 `tools/` 抓一次真客户端对应操作即可扩展。）

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
