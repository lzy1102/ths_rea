# -*- coding: utf-8 -*-
"""本地私密校验: 交易密码散列是否与客户端内存中的摘要吻合

两种用法:
  A. 直接运行(交互式):  python check_md5.py     → 密码输入不回显
  B. 非交互: 把密码保存到本目录 secret_tmp.txt → 运行后自动删除该文件,
     结果只打印散列命中情况, 绝不回显密码原文。

目的: 验证交易登录报文里的 md5=00000000000000000000000000000000
      是否为"交易密码 + 各种组合"的散列。纯本地计算, 不联网, 不写盘。
"""
import getpass
import hashlib
import sys
from pathlib import Path

TARGET = "00000000000000000000000000000000"
HERE = Path(__file__).resolve().parent
secrets_file = HERE / "secret_tmp.txt"

non_interactive = False
if secrets_file.exists():
    raw = secrets_file.read_bytes()
    for enc in ("utf-8-sig", "utf-8", "gbk", "ansi"):
        try:
            pw = raw.decode(enc).strip()
            break
        except (UnicodeDecodeError, LookupError):
            continue
    else:
        pw = raw.decode("utf-8", "replace").strip()
    non_interactive = True
    print("[模式] 从 secret_tmp.txt 读取 (完成后自动删除)")
else:
    pw = getpass.getpass("请输入你的交易密码 (不回显, 本地计算): ")

if not pw:
    print("密码为空, 退出")
    sys.exit(1)

CONSTS = {
    "": "",
    "dlzh100000000": "100000000",
    "zjzh12345678": "12345678",
    "broker8888": "8888",
    "yybrid1542": "1542",
    "qsid31": "31",
}

cands = {}
for enc in ("utf-8", "gbk"):
    try:
        raw = pw.encode(enc)
    except UnicodeEncodeError:
        continue
    m1 = hashlib.md5(raw).hexdigest()
    base = {
        f"md5(pwd)[{enc}]": m1,
        f"md5(PWD大写)[{enc}]": hashlib.md5(raw.upper()).hexdigest(),
        f"md5(pwd小写)[{enc}]": hashlib.md5(raw.lower()).hexdigest(),
        f"md5(md5小写)[{enc}]": hashlib.md5(m1.encode()).hexdigest(),
        f"md5(md5大写)[{enc}]": hashlib.md5(m1.upper().encode()).hexdigest(),
    }
    for cname, cval in CONSTS.items():
        if not cname:
            continue
        for pat in (f"{pw}{cval}", f"{cval}{pw}"):
            base[f"md5({cname} 前/后缀)[{enc}]"] = \
                hashlib.md5(pat.encode(enc)).hexdigest()
    cands.update(base)

print()
hit = False
for k, v in cands.items():
    v = v.upper()
    if v == TARGET:
        hit = True
        print(f"[命中!!!] {k}  {v}")
print(f"共测试 {len(cands)} 种组合")

if non_interactive:
    try:
        secrets_file.unlink()
        print("secret_tmp.txt 已自动删除")
    except OSError:
        pass

print()
if hit:
    print(">>> 结论: 命中! md5 与交易密码的该种组合完全一致 <<<")
else:
    print(">>> 结论: 未命中 (md5 可能是会话派生签名/带未知盐, 等抓包结果) <<<")

if not non_interactive:
    input("按回车退出 (只告诉我命中没有即可, 别发密码)")
