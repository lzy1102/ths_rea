#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""开源/发版前敏感信息审计。

    python tools/prepublish_audit.py            # 扫当前 HEAD 的全部跟踪文件
    python tools/prepublish_audit.py --history  # 连同 git 历史一起扫

规则:
  - 命中即视为"可能泄露", 需人工确认后处理
  - 已知占位符/产品常量自动放行(白名单)
退出码: 0=干净  1=发现风险
"""
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# ---------- 规则 ----------
RULES = [
    # (规则名, 正则, 说明)
    ('资金账号-8位', rb'(?<!\d)[1-9]\d{7}(?!\d)', '疑似资金账号'),
    ('沪股东号', rb'(?<![A-Za-z0-9])A\d{9}(?!\d)', '沪市股东号 A+9位'),
    ('深股东号', rb'(?<![A-Za-z0-9])0\d{9}(?!\d)', '深市股东号 0+9位'),
    ('交易密码散列', rb'\b[A-F0-9]{32}\b', '32位大写HEX, 可能是密码/设备标识散列'),
    ('MAC地址', rb'(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}', '物理网卡地址'),
    ('GUID', rb'[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}', '设备/应用GUID'),
    ('电脑名', rb'DESKTOP-[A-Z0-9]{7}', 'Windows 主机名'),
    ('本机用户路径', rb'[A-Z]:[\\/]Users[\\/][a-z]+', '本机用户名(泄露系统账户名)'),
    ('内网IP', rb'(?:192\.168|10\.(?!0\.0\.0\.99)\d{1,3}|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}', '内网地址'),
    ('IMEI/DID', rb'\b[0-9A-Fa-f]{32}\b', '设备标识'),
]

# ---------- 白名单: 明确的安全值 ----------
ALLOW = {
    '00000000-0000-0000-0000-000000000000', '11111111-1111-1111-1111-111111111111',
    '12345678', '11111111', '0123456789', 'A123456789', 'A111111111', '0111111111',
    '1000000000', '00000000', '0000000000', '1357758012', '94029500', '94030343',
    '94032015', '3050729056', '199000', '00001000', '00001004', '01010400', '33333333',
    '00000000000000000000000000000000',
}
ALLOW_SUB = {'12345678', '0123456789', '00000000', '1000000000', '0000000000',
             '1234567890', '0123456789', '00001000'}
ALLOW_PREF = ('DESKTOP-XXXXXXX',)
# 行情字段ID/偏移量/日期等"数字巧合", 非账号 (docs/quote_fields.md 等)
ALLOW_FILES_NOISE = ('docs/quote_fields.md', 'docs/QuoteFieldData.xml',
                     'docs/下单逆向进展-3.md', 'docs/接口分析报告.md', 'README.md')
ALLOW_PATHS = {
    'ths_client/machine.py',      # 采集逻辑, 只有占位符
    'ths_client/data/hello.bin',  # 协议问候, 已零值化
    'docs/ApiConfig.xml',         # 同花顺产品接口定义(非个人)
    'docs/RequestTypeV2Data.xml',
    'docs/RequestTypeV3Data.xml',
    'docs/MarketData.xml',        # 同上
    'docs/QuoteFieldData.xml',    # 行情字段表(数字是字段ID/偏移)
    '.gitignore', 'MANIFEST.in', 'pyproject.toml', 'LICENSE',
}
SKIP_EXT = {'.png', '.jpg', '.ico', '.gif', '.whl', '.gz', '.exe', '.dll', '.bin'}


import os
DATE_RE = re.compile(r'^20\d{6}$')          # 20261016 -> 日期
FIELD_RE = re.compile(r'^(?:1[0-9]|2[0-9])\d{6}$|^\d{8}$')  # 字段ID/偏移


def ok(value: str, path: str) -> bool:
    if value in ALLOW or value in ALLOW_SUB:
        return True
    if os.path.basename(path) in ALLOW_FILES_NOISE and (DATE_RE.match(value) or FIELD_RE.match(value)):
        return True
    if any(value.startswith(p) for p in ALLOW_PREF):
        return True
    if path in ALLOW_PATHS:
        return True
    return False


def scan(data: bytes, path: str, out: list):
    for name, pat, why in RULES:
        for m in re.findall(pat, data):
            try:
                v = m.decode('utf-8') if isinstance(m, bytes) else str(m)
            except Exception:
                continue
            if ok(v, path):
                continue
            # MD5/散列类: 需要人工判断
            out.append((name, path, v, why))


def tracked_files():
    out = subprocess.run(['git', 'ls-files', '-z'], capture_output=True, cwd=ROOT)
    return [x.decode('utf-8', 'replace') for x in out.stdout.split(b'\0') if x]


def main() -> int:
    history = '--history' in sys.argv
    findings = []
    files = tracked_files()
    for f in files:
        if Path(f).suffix.lower() in SKIP_EXT:
            continue
        data = subprocess.run(['git', 'show', f'HEAD:{f}'], capture_output=True, cwd=ROOT).stdout
        if data:
            scan(data, f, findings)

    if history:
        commits = subprocess.run(['git', 'rev-list', '--all'], capture_output=True,
                                 cwd=ROOT).stdout.split()
        for c in commits:
            c = c.decode()
            for f in subprocess.run(['git', 'ls-tree', '-r', '--name-only', c],
                                    capture_output=True, cwd=ROOT).stdout.split(b'\n'):
                if not f:
                    continue
                p = f.decode('utf-8', 'replace')
                if Path(p).suffix.lower() in SKIP_EXT:
                    continue
                d = subprocess.run(['git', 'show', f'{c}:{p}'], capture_output=True, cwd=ROOT).stdout
                if d:
                    scan(d, f'@{c[:8]}/{p}', findings)

    # 去重
    uniq = sorted(set(findings))
    if not uniq:
        print('✅ 未发现敏感信息' + ('（含 git 历史）' if history else ''))
        return 0
    print(f'⚠️  发现 {len(uniq)} 处待确认:')
    for name, path, val, why in uniq:
        shown = val if len(val) < 40 else val[:16] + '...' + val[-8:]
        print(f'   [{name}] {path}\n        {shown}   ({why})')
    print('\n处理: 替换为占位符后重新提交; 若已进历史, 需重写历史'
          '(git filter-branch --tree-filter ...) 后强制推送。')
    return 1


if __name__ == '__main__':
    sys.exit(main())