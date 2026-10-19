# -*- coding: utf-8 -*-
"""后台密钥嗅探启动器(Windows)。

    python tools/keysniff_bg.py --timeout 900 --log captures/keysniff.log

以 DETACHED_PROCESS 方式拉起 tools/keysniff.py, 立即返回, 日志写文件。
用途: 让分析端在后台等用户去客户端里触发新连接。
"""
import argparse
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

DETACHED = 0x00000008 | 0x00000200   # DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--timeout', type=int, default=900)
    ap.add_argument('--log', default='captures/keysniff.log')
    a = ap.parse_args()
    log = (ROOT / a.log).resolve()
    log.parent.mkdir(parents=True, exist_ok=True)
    fh = open(log, 'wb')
    p = subprocess.Popen(
        [sys.executable, '-u', str(ROOT / 'tools' / 'keysniff.py'),
         '--timeout', str(a.timeout)],
        cwd=str(ROOT), stdout=fh, stderr=subprocess.STDOUT,
        creationflags=DETACHED, close_fds=True,
    )
    print(f'后台嗅探已启动 PID={p.pid}  日志={log}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
