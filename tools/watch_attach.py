# -*- coding: utf-8 -*-
"""守望者: 轮询等待新的 xiadan.exe 进程, 出现即自动挂载 deep_capture (赶在登录握手前)"""
import subprocess
import time
import re

OLD_PID = 16660
print(f"守望中... 关闭并重开 xiadan.exe (当前PID {OLD_PID})", flush=True)

while True:
    try:
        out = subprocess.check_output('tasklist /FI "IMAGENAME eq xiadan.exe" /FO CSV /NH',
                                      shell=True).decode('gbk', 'replace')
        m = re.search(r'xiadan\.exe","(\d+)"', out)
        if not m:
            print("xiadan 已关闭, 等待重新打开...", flush=True)
        else:
            pid = int(m.group(1))
            if pid != OLD_PID:
                print(f"发现新进程 PID={pid}, 立即挂载!", flush=True)
                p = subprocess.Popen(
                    ['D:/Program Files/Python312/python.exe', 'tools/login_watch.py', str(pid), '600'],
                    stdout=open('captures/login_watch_console.txt', 'w'),
                    stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                    creationflags=0x00000008 | 0x00000200,
                    cwd=r'D:\project\python\ths_rea')
                print(f"login_watch detached pid = {p.pid}", flush=True)
                break
    except Exception as e:
        print("poll err:", e, flush=True)
    time.sleep(0.5)
