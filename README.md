# ths-trade-client

同花顺柜台交易协议的**纯 Python 客户端**：登录 → 启动序列 → 预检 → 委托，全链路实测验证。

> ⚠️ **风险提示**：`buy_market()` 是**真实委托指令**，会真实占用资金/成交。仅供个人学习与自有账户自动化使用，请自行评估合规与资金风险。协议实现自同花顺 Windows 客户端（xiadan.exe）逆向，随版本更新可能失效。

## 安装

```bash
# 方式1: 源码安装 (开发)
pip install -e .

# 方式2: 构建 wheel 后分发
python -m pip wheel . -w dist --no-deps
pip install dist/ths_trade_client-0.2.0-py3-none-any.whl
```

依赖：`pycryptodome`、`requests`（Python ≥ 3.8）

## 账号配置（不提交仓库）

账号信息**不写入代码**，通过参数或本地配置文件传入。仓库内模板为脱敏占位符，
运行时自动用你的配置替换（`local_profile.json` 已加入 .gitignore）。

```bash
# 复制示例并填入自己的账号
cp local_profile.example.json local_profile.json
```

```json
{
  "zjzh": "你的资金账号",
  "gdzh_sh": "你的上海股东号(A开头)",
  "gdzh_sz": "你的深圳股东号(数字)",
  "name": "户名(3个汉字)"
}
```

> 本协议登录**不含密码字段**（客户端靠账号+设备信息登录），配置中无需密码。

### 换账号 / 换券商

| 场景 | 需要改什么 |
|---|---|
| 同券商（国泰海通）的其他账号 | 只改 `local_profile.json` 的 `zjzh` / `gdzh_sh` / `gdzh_sz` / `name` |
| 同券商其他营业部 | 可选加 `deptid`（营业部ID，默认 `1302`） |
| 其他券商 | 需用 `tools/` 重新抓包该券商的登录/启动报文；改 `verinfo`（券商标记，默认 `gtja`）与柜台地址 `host` 参数 |

模板中除账号/股东号/户名/营业部外无任何个人字段；同券商换账号预期直接可用
（尚未用第二账号实测，如需可验证）。

## 字段提取工具（分发给别人用）

别人不需要手抄账号——装好后运行一条命令，工具自动挂载他的 xiadan 客户端，
等他登录/打开交易界面，自动抓取并解密，输出现成的 `local_profile.json`：

```bash
pip install "ths-trade-client[capture]"    # 含 frida
ths-capture-profile                        # 自动找 xiadan.exe
# 输出: local_profile.json (zjzh/gdzh_sh/gdzh_sz/name/deptid/verinfo/host)

ths-capture-profile --pid 1234 --out my.json --timeout 180   # 可选参数
```

原理：只挂 ws2_32 的 send/recv/connect（与客户端版本无关），识别柜台连接(fdff帧)，
登录帧为 zlib 明文、后续帧用 S2C#1 的会话IV解密，提取账号/股东号/户名/营业部/券商标记/柜台地址。

## 快速开始

```python
from ths_client import TradeClient

# 方式1: 从本地配置读取 (推荐)
cli = TradeClient.from_profile()          # 或 from_profile('D:/my/ths.json')

# 方式2: 显式传参
cli = TradeClient(zjzh='12345678', gdzh_sh='A123456789', gdzh_sz='0123456789',
                  name='某某某')

cli.connect()
cli.login()                    # 问候+登录 (自动会话/IV)
cli.bootstrap(include_sh=True) # 启动序列 (必须; 沪市必须含SH组)

# 只读预检 (返回行情/可买数量等)
r = cli.precheck('601398', qty=100)
print(r['text'])

# 真实市价委托 (100股 工商银行, 五档即成剩撤)
r = cli.buy_market('601398', 100, sjwt=4)
print(r['text'])               # 成功=委托回报; 失败如"资金不足..."

# 真实市价卖出 (需账户持有该证券)
r = cli.sell_market('601398', 100, sjwt=4)
print(r['text'])               # 失败如"当前账户暂未持仓该证券！"
```

### 市价策略码（沪市）

| 界面选项 | 含义 | sjwt |
|---|---|---|
| 1-五档即成剩撤（默认） | 对手五档连续成交，剩余即撤 | 4 |
| 2-五档即成剩转限 | 剩余转限价挂单 | 5 |
| 3-对手方最优 | 对手方最优价成交 | 2 |
| 4-本方最优 | 本方最优价委托 | 3 |

（`trade_msg.SJWT_SH` / `SJWT_SZ` 内置完整映射表）

## API 摘要

```python
TradeClient(zjzh, gdzh_sh=..., gdzh_sz=..., name='某某某', host=..., port=..., timeout=...)
  .connect(bind_port=0, dump_dir=None)   # dump_dir 落盘全部收发帧(调试)
  .login() -> {'sess','iv','s2c1'}
  .bootstrap(include_sh=False) -> [应答...]
  .bootstrap_sh() -> [应答...]
  .precheck(code, qty=100, market=None) -> {'type','plaintext','text'}
  .buy_market(code, qty, sjwt=4, market=None, zxjg=None) -> {...}
  .sell_market(code, qty, sjwt=4, market=None, zxjg=None, bhjg=None) -> {...}
  .send(wire_cmd, plaintext) / .recv()   # 低层逃生口
  .close()                               # 支持 with 语句

parse_kv(text) -> dict                   # 提取应答 key=value
```

低层模块（`trade_conn.TradeConn` / `trade_msg` / `trade_crypt.body_codec`）亦可直接使用。

## 协议要点

- 帧：`fdfdfdfd + 8字符hex长度 + mode + content`
- C2S content：`fdff + 会话4字节 + cmd + 00001000 + len1 + len2 + body`
- body：`DES-CBC(zlib(明文), KEY, IV)`；明文 `[8:24]` = MD5 签名槽（槽清零后对整条明文求 md5）
- 会话 4 字节：登录帧全零，登录后回显服务器分配值
- 市场：`'2'`=上海（股东号 A 开头）、`'1'`=深圳（股东号数字）
- 市价单：价格 float `-1.0` + 文本 `wtjg=-1` + `sjwt=<策略码>` + `type=sjwt`
- 顺序敏感：`login → 标准启动 → 沪市启动 → 预检 → 委托`（顺序错误会回"帐户无效"甚至被 RST）

完整逆向记录：`docs/下单逆向进展-3.md`
工作计划/路线图：`docs/工作计划.md`

## 已知限制

- 委托目前支持**沪市市价买/卖**（买入实测到达资金检查; 卖出到达持仓/时间检查）
- 深市、限价委托、撤单尚未捕获验证（见 docs/工作计划.md 阶段1）
- 限价委托、撤单、查询类报文可按 `bootstrap`/`precheck` 同法扩展（模板+补丁+签名）
- 机器信息（MAC/CPU/磁盘序列号/计算机名/卷序列号）在运行时**自动采集真实值**注入报文；
  **Windows/Linux 均支持**（Linux 从 /sys、/proc、machine-id 等读取，缺项自动降级；
  实测服务端不校验这些字段，占位值也能登录；仅账号/股东号必须正确）
- **Linux / Docker 已实测**：WSL Ubuntu 与 python:3.12-slim 容器内登录/启动序列/预检全链路通过
  （协议层为纯 Python，无平台依赖；容器内机器信息自动读取宿主/容器可用项）
- 柜台地址默认 `114.141.180.27:8002`（可 `host=` 覆盖；实际会随券商调度变化）
