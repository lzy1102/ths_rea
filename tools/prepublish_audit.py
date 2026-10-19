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
    # 明确的占位符
    '12345678', '11111111', '0123456789', 'A123456789', 'A111111111', '0111111111',
    '00000000', '0000000000', '1000000000', '00001000', '00001004', '01010400',
    '33333333', '94029500', '94030343', '94032015', '3050729056', '199000',
    '1234567890', '1357758012',
    '00000000000000000000000000000000',
    '00000000-0000-0000-0000-000000000000',
    # 零值化网卡地址
    '00:00:00:00:00:00', '00:00:00:00:00:01', '00:00:00:00:00:02',
    '00:00:00:00:00:03', 'AC:00:00:00:00:00',
    # 示例地址 / 产品常量
    '192.168.0.1', '10.0.0.99', '2020063035285685',
}
ALLOW_SUB = {'12345678', '0123456789', '00000000', '1000000000', '0000000000'}
ALLOW_PREF = ('DESKTOP-XXXXXXX',)
# 产品级配置文件(非个人): 同花顺接口/行情字段定义
ALLOW_BASENAMES = {
    'prepublish_audit.py',        # 审计脚本自身的示例值
    'ApiConfig.xml', 'RequestTypeV2Data.xml', 'RequestTypeV3Data.xml',
    'MarketData.xml', 'QuoteFieldData.xml', 'quote_fields.md', 'request_types.md',
    'machine.py', 'hello.bin', 'audit_artifacts.py', '开源与安全.md',
    'pyproject.toml', 'LICENSE', 'MANIFEST.in', '.gitignore',
}
# 数字"巧合"放行: 行情字段ID/偏移量/日期, 非账号
DATE_RE = re.compile(r'^20[0-9]{6}$')
FIELD_RE = re.compile(r'^(?:1[0-9]|2[0-9])[0-9]{6}$|^[0-9]{8}$')
NOISE_BASENAMES = {'quote_fields.md', 'QuoteFieldData.xml', '下单逆向进展-3.md',
                   '接口分析报告.md', 'README.md', 'ApiConfig.xml',
                   'RequestTypeV2Data.xml', 'RequestTypeV3Data.xml'}


SKIP_EXT = {'.png', '.jpg', '.ico', '.gif', '.whl', '.gz', '.exe', '.dll', '.bin'}


import os
DATE_RE = re.compile(r'^20[0-9]{6}$')                       # 20261016 -> 日期
FIELD_RE = re.compile(r'^(?:1[0-9]|2[0-9])[0-9]{6}$|^[0-9]{8}$')  # 行情字段ID/偏移


def ok(value: str, path: str) -> bool:
    base = os.path.basename(path)
    if value in ALLOW or value in ALLOW_SUB:
        return True
    if any(value.startswith(p) for p in ALLOW_PREF):
        return True
    if base in ALLOW_BASENAMES:
        return True
    if base in NOISE_BASENAMES and (DATE_RE.match(value) or FIELD_RE.match(value)):
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