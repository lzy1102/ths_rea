#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""构建产物敏感信息审计 (whl / sdist)。

    python tools/audit_artifacts.py [dist/ 或具体产物路径...]

重点: wheel 的 METADATA 会内嵌整份 README (long_description), sdist 会带上 docs/ 与
测试样本 —— 这是最容易"代码已脱敏但产物仍泄露"的地方。

!!! 重要: 本文件**只保存敏感值的 SHA-256 指纹, 不保存原文**。
    早先版本把真实账号/设备ID 写成明文黑名单, 等于把刚清掉的数据又写回仓库,
    而且审计脚本会把自己判为泄露、永久阻断 CI。改指纹时务必只加哈希。
退出码: 0=干净 1=发现风险
"""
import hashlib
import re
import sys
import tarfile
import zipfile
from pathlib import Path

# 已泄露过的敏感值的 SHA-256(小写归一后的原文) —— 只存指纹, 绝不存原文
SECRET_DIGESTS = {
    '74178258ae6bb8d33937ee1b7d735605a6e9e69e2beb947f60605c0259979f95',
    '56a764f53354660cc03225f2e3bd13eac51102b55e74dee23958c4e092d7bcb0',
    '15ac5b799c30886f07d8bb49b4e5ca0abaa6f755f7366d3f44fc2a2a5d38de83',
    '4eaa84759b23baa199a55812bc35bd4c4320ac745e0302bd9d5ba4982b4d380b',
    '22a3f5172d494539b2bdf47ecd2df166080d23019c066952a9956f6370af8d20',
    '9d017dd7bf2eae327d4f554c178005fbceebe43cf25d65842d1f3a92a0d6d231',
    'bbc4a7c631b1f5da68b03bce7351b5edeb6f693b604e15998a7174274160cae2',
    'c7d0b89e2f42e265e3684f60d14ae0946eef4aaf646a8d551e7225e1f2c85328',
    'a3cfdca6d76034ee900859f904ec7780c4188111e78d825b13c388e9cf7aaa4d',
    'b11484e109f1b677c7dda2e8488af188bfd04fbd8cd77bda16e6785e5e1d3c23',
    '9985ba33bcb88fbad8c3efdde267833ccb3a7b0c926a54a0ffdd562de007b17a',
    '884b96bfdd00294e5dc4709043c6659a4e4db841226e6d1d7324190e2c6ff07c',
    'cb8a008a516039a6614b0bb968458b57b5cd7da8de2df0f54d91443a938c07f6',
    '8868de6969f4734ae96db69bd80f73d5bb2dc8dd36a57aed9b12f45161d78f99',
    'fb7e54d0b26543c9bbda85646059a597312ff70e4a55311cc482aa8a9214a818',
    '62ce48ac502902fb7999eb4fe97d0e83f0355ed19d239a3c12b081031816b0a5',
    '8ba0d58c7d7d50ab18c32933c4c158ade4ff82d39be87bb351747d26dec08e13',
    'c3eb0cd2b9a40f54e86c275436074d1b23f4ec3f198896421b455c2c1157e132',
    '1cd94322b82616c0e4b01b419f679572c41b4be580fb32b911c1bf2a71917ac6',
}

# 真实网卡前缀(零值占位放行)
MAC_RE = re.compile(rb'(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}')
ZERO_MACS = {b'00:00:00:00:00:00', b'00:00:00:00:00:01', b'00:00:00:00:00:02',
             b'00:00:00:00:00:03', b'ac:00:00:00:00:00'}


def _digest(value: str) -> str:
    return hashlib.sha256(value.strip().lower().encode('utf-8')).hexdigest()


def scan_bytes(data: bytes, where: str, hits: list):
    # 1) 指纹匹配: 扫描所有"像凭据"的片段, 命中已知指纹即报告
    for cand in CAND_RE.finditer(data.decode('latin-1')):
        v = cand.group()
        if len(v) < 6:
            continue
        if _digest(v) in SECRET_DIGESTS:
            hits.append((where, f'已知泄露值的指纹命中 (长度{len(v)}): {v[:2]}***{v[-2:]}'))
    # 2) MAC: 零值占位放行
    for m in MAC_RE.findall(data):
        if m.lower() not in ZERO_MACS:
            hits.append((where, 'MAC ' + m.decode()))


# 候选凭据形态: 连续可打印字符(够长即可覆盖账号/散列/路径), 上限避免整块文件
CAND_RE = re.compile(r'[0-9A-Za-z_:.\\/\\\\-]{6,64}')


def audit_wheel(path: Path, hits: list):
    with zipfile.ZipFile(path) as z:
        for n in z.namelist():
            if n.endswith('/'):
                continue
            scan_bytes(z.read(n), f'{path.name}:{n}', hits)


def audit_sdist(path: Path, hits: list):
    with tarfile.open(path) as t:
        for m in t.getmembers():
            if not m.isfile() or m.size > 5_000_000:
                continue
            fh = t.extractfile(m)
            if fh:
                scan_bytes(fh.read(), f'{path.name}:{m.name}', hits)


def main() -> int:
    args = [Path(p) for p in sys.argv[1:]] or [Path('dist')]
    targets: list = []
    for a in args:
        candidates = sorted(a.glob('*')) if a.is_dir() else [a]
        targets += [c for c in candidates
                    if c.suffix in ('.whl', '.gz', '.zip', '.tar')]
    if not targets:
        print('没有待审计的产物')
        return 0
    hits: list = []
    for p in targets:
        if p.suffix == '.whl' or p.name.endswith('.zip'):
            audit_wheel(p, hits)
        else:
            audit_sdist(p, hits)
    if not hits:
        print(f'✅ 产物干净: {", ".join(t.name for t in targets)}')
        return 0
    print(f'⚠️  产物中发现 {len(hits)} 处敏感信息:')
    for where, what in sorted(set(hits))[:30]:
        print(f'   {where}\n        {what}')
    print('\n产物不可发布! 请先清理源码(tools/prepublish_audit.py)再重新构建。')
    return 1


if __name__ == '__main__':
    sys.exit(main())