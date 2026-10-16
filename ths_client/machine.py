# -*- coding: utf-8 -*-
"""真实机器信息采集与注入。

登录帧/0030校验股东帧中的 hardwarecode/macinfo/cpuinfo 等字段服务端实测
不校验(占位值也能登录), 但采集真实值更自然(避免全零指纹)。

采集项 (Windows 优先, 其他平台降级为占位值):
    hardwarecode = BIOS:<md5(bios序列号)>,HDD:<md5(磁盘序列号)>,MAC:<mac1>,
                   PI:C^<文件系统>^<容量G>G,VOL:<卷序列号>,VOLNAME:<卷标>
    macinfo      = MAC1^MAC2^MAC3^MAC4
    cpuinfo / computername / hddinfo / guid / vol / virtual / bios_date
"""
import ctypes
import hashlib
import os
import platform
import re
import socket
import subprocess
import sys
from functools import lru_cache

__all__ = ['collect', 'patch', 'FIELDS']

# 会被注入的文本字段 (模板内为脱敏占位值)
FIELDS = ('hardwarecode', 'macinfo', 'cpuinfo', 'computername', 'hddinfo',
          'guid', 'vol', 'virtual', 'bios_date')

_NO_WINDOW = 0x08000000 if os.name == 'nt' else 0


def _run(cmd, timeout=8):
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL,
                                      creationflags=_NO_WINDOW, timeout=timeout)
        return out.decode('utf-8', 'replace').strip()
    except Exception:
        return ''


def _macs():
    """全部网卡MAC (Windows: getmac; 其他: uuid.getnode 单个)。"""
    macs = []
    out = _run(['getmac', '/fo', 'csv', '/nh'])
    for line in out.splitlines():
        m = re.search(r'"([0-9A-Fa-f]{2}(?:-[0-9A-Fa-f]{2}){5})"', line)
        if m:
            mac = m.group(1).replace('-', ':').upper()
            if mac not in macs:
                macs.append(mac)
    if not macs:
        import uuid
        n = uuid.getnode()
        if (n >> 40) % 2 == 0:  # 非随机节点
            macs.append(':'.join('%02X' % ((n >> (8 * i)) & 0xFF) for i in range(5, -1, -1)))
    return macs


def _win_reg(path, name):
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path) as k:
            return str(winreg.QueryValueEx(k, name)[0])
    except Exception:
        return ''


def _volume_info(drive='C:\\'):
    """卷序列号/卷标/文件系统 (ctypes, 无需子进程)。"""
    try:
        vol_ser = ctypes.c_ulong(0)
        fs = ctypes.create_unicode_buffer(261)
        label = ctypes.create_unicode_buffer(261)
        ok = ctypes.windll.kernel32.GetVolumeInformationW(
            drive, label, 261, ctypes.byref(vol_ser), None, None, fs, 261)
        if ok:
            ser = '%08x' % vol_ser.value
            return ser[:4] + '-' + ser[4:], label.value, fs.value
    except Exception:
        pass
    return '', '', ''


def _wmic(cls, prop):
    """wmic 快速查询 (Win10/11 多数仍可用); 返回首行值。"""
    out = _run(['wmic', 'path', 'Win32_' + cls, 'get', prop, '/value'])
    for line in out.splitlines():
        if '=' in line:
            return line.split('=', 1)[1].strip()
    return ''


@lru_cache(maxsize=1)
def collect() -> dict:
    """采集本机信息 (缓存)。失败项为通用占位值, 不影响登录。"""
    info = {
        'hardwarecode': '', 'macinfo': '', 'cpuinfo': '', 'computername': '',
        'hddinfo': '', 'guid': '', 'vol': '', 'virtual': '', 'bios_date': '',
    }
    # --- BIOS序列号 / 磁盘序列号 / CPU名称 (wmic 快, 失败退 PowerShell CIM) ---
    bios_sn = disk_sn = cpu_name = ''
    if os.name == 'nt':
        bios_sn = _wmic('BIOS', 'SerialNumber')
        disk_sn = _wmic('DiskDrive', 'SerialNumber')
        cpu_name = _wmic('Processor', 'Name')
        if not (bios_sn or disk_sn or cpu_name):
            out = _run(['powershell', '-NoProfile', '-Command',
                        "$b=Get-CimInstance Win32_BIOS;$d=Get-CimInstance Win32_DiskDrive|"
                        "Select-Object -First 1;$c=Get-CimInstance Win32_Processor|"
                        "Select-Object -First 1;Write-Output "
                        "($b.SerialNumber+'|'+$d.SerialNumber+'|'+$c.Name)"])
            parts = out.split('|')
            if len(parts) == 3:
                bios_sn, disk_sn, cpu_name = (p.strip() for p in parts)

    info['cpuinfo'] = cpu_name or platform.processor() or 'Intel(R) Core(TM) CPU'
    info['computername'] = socket.gethostname()
    info['hddinfo'] = disk_sn
    macs = _macs()
    info['macinfo'] = '^'.join(macs) if macs else '00:00:00:00:00:00'

    # GUID / 厂商 / BIOS日期 (注册表)
    if os.name == 'nt':
        guid = _win_reg(r'SOFTWARE\Microsoft\Cryptography', 'MachineGuid')
        if guid:
            info['guid'] = '{' + guid.upper() + '}'
        info['virtual'] = _win_reg(r'HARDWARE\DESCRIPTION\System\BIOS', 'SystemManufacturer')
        d = _win_reg(r'HARDWARE\DESCRIPTION\System\BIOS', 'BIOSReleaseDate')  # 05/21/2015
        m = re.match(r'(\d{2})/(\d{2})/(\d{4})', d)
        if m:
            info['bios_date'] = m.group(3) + m.group(1) + m.group(2)

    # 卷序列号/卷标/文件系统/容量
    volser, vollabel, fs = _volume_info('C:\\' if os.name == 'nt' else '/')
    info['vol'] = volser
    try:
        import shutil
        total_g = int(shutil.disk_usage('C:\\' if os.name == 'nt' else '/').total // (1 << 30))
    except Exception:
        total_g = 0

    def md5u(s):
        return hashlib.md5(s.encode()).hexdigest().upper() if s else '0' * 32

    info['hardwarecode'] = (
        'BIOS:%s,HDD:%s,MAC:%s,PI:%s^%s^%dG,VOL:%s,VOLNAME:%s' % (
            md5u(bios_sn), md5u(disk_sn), macs[0] if macs else '00:00:00:00:00:00',
            'C' if os.name == 'nt' else '/', fs or 'NTFS', total_g, volser, vollabel))
    return info


def patch(pt: bytearray, info: dict = None) -> bytearray:
    """把真实机器信息写入明文文本区 (原地修改, 返回同一对象)。

    替换文本表行 `key=<占位值>` → `key=<真实值>` (0x12b 起的文本区)。
    须在 _sign()/加密之前调用。
    """
    if info is None:
        info = collect()
    if len(pt) <= 0x12b:
        return pt
    tail = bytes(pt[0x12b:])
    for key in FIELDS:
        val = info.get(key)
        if not val:
            continue
        pat = re.compile(re.escape(key.encode()) + rb'=[^\n\x00]*')
        tail = pat.sub(lambda m: key.encode() + b'=' + val.encode(), tail)
    pt[0x12b:] = tail
    return pt
