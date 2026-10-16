# -*- coding: utf-8 -*-
"""真实机器信息采集与注入 (Windows / Linux)。

登录帧/0030校验股东帧中的 hardwarecode/macinfo/cpuinfo 等字段服务端实测
不校验(占位值也能登录), 但采集真实值更自然(避免全零指纹)。

采集项:
    hardwarecode = BIOS:<md5(bios序列号)>,HDD:<md5(磁盘序列号)>,MAC:<mac1>,
                   PI:<盘>^<文件系统>^<容量G>G,VOL:<卷序列号>,VOLNAME:<卷标>
    macinfo      = MAC1^MAC2^...
    cpuinfo / computername / hddinfo / guid / vol / virtual / bios_date

Windows: wmic(快)/PowerShell CIM(兜底)/注册表/GetVolumeInformationW
Linux:   /sys/class/dmi/id、/proc/cpuinfo、/sys/class/net、/etc/machine-id、
         lsblk、/dev/disk/by-uuid (无需root; 缺项自动降级, 不阻断登录)
"""
import ctypes
import glob as _glob
import hashlib
import os
import platform
import re
import socket
import subprocess
from functools import lru_cache

__all__ = ['collect', 'patch', 'FIELDS']

# 会被注入的文本字段 (模板内为脱敏占位值)
FIELDS = ('hardwarecode', 'macinfo', 'cpuinfo', 'computername', 'hddinfo',
          'guid', 'vol', 'virtual', 'bios_date')

_NO_WINDOW = 0x08000000 if os.name == 'nt' else 0
_IS_WIN = os.name == 'nt'


def _run(cmd, timeout=8):
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL,
                                      creationflags=_NO_WINDOW, timeout=timeout)
        return out.decode('utf-8', 'replace').strip()
    except Exception:
        return ''


def _read(path):
    try:
        with open(path, encoding='utf-8', errors='replace') as f:
            return f.read().strip()
    except OSError:
        return ''


def _macs():
    """全部网卡MAC (Win: getmac; Linux: /sys/class/net; 兜底 uuid.getnode)。"""
    macs = []
    if _IS_WIN:
        out = _run(['getmac', '/fo', 'csv', '/nh'])
        for line in out.splitlines():
            m = re.search(r'"([0-9A-Fa-f]{2}(?:-[0-9A-Fa-f]{2}){5})"', line)
            if m:
                mac = m.group(1).replace('-', ':').upper()
                if mac not in macs:
                    macs.append(mac)
    else:
        try:
            for d in sorted(os.listdir('/sys/class/net')):
                if d == 'lo':
                    continue
                a = _read('/sys/class/net/%s/address' % d).upper()
                if a and a != '00:00:00:00:00:00' and a not in macs:
                    macs.append(a)
        except OSError:
            pass
    if not macs:
        import uuid
        n = uuid.getnode()
        if (n >> 40) % 2 == 0:  # 非随机节点
            macs.append(':'.join('%02X' % ((n >> (8 * i)) & 0xFF) for i in range(5, -1, -1)))
    return macs


# ---------------- Windows ----------------
def _win_reg(path, name):
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path) as k:
            return str(winreg.QueryValueEx(k, name)[0])
    except Exception:
        return ''


def _win_volume(drive='C:\\'):
    """卷序列号/卷标/文件系统 (ctypes)。"""
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


def _win_wmic(cls, prop):
    out = _run(['wmic', 'path', 'Win32_' + cls, 'get', prop, '/value'])
    for line in out.splitlines():
        if '=' in line:
            return line.split('=', 1)[1].strip()
    return ''


def _win_collect(info):
    bios_sn = _win_wmic('BIOS', 'SerialNumber')
    disk_sn = _win_wmic('DiskDrive', 'SerialNumber')
    cpu_name = _win_wmic('Processor', 'Name')
    if not (bios_sn or disk_sn or cpu_name):   # Win11 新版无wmic, 用CIM
        out = _run(['powershell', '-NoProfile', '-Command',
                    "$b=Get-CimInstance Win32_BIOS;$d=Get-CimInstance Win32_DiskDrive|"
                    "Select-Object -First 1;$c=Get-CimInstance Win32_Processor|"
                    "Select-Object -First 1;Write-Output "
                    "($b.SerialNumber+'|'+$d.SerialNumber+'|'+$c.Name)"])
        parts = out.split('|')
        if len(parts) == 3:
            bios_sn, disk_sn, cpu_name = (p.strip() for p in parts)
    guid = _win_reg(r'SOFTWARE\Microsoft\Cryptography', 'MachineGuid')
    if guid:
        info['guid'] = '{' + guid.upper() + '}'
    info['virtual'] = _win_reg(r'HARDWARE\DESCRIPTION\System\BIOS', 'SystemManufacturer')
    d = _win_reg(r'HARDWARE\DESCRIPTION\System\BIOS', 'BIOSReleaseDate')  # 05/21/2015
    m = re.match(r'(\d{2})/(\d{2})/(\d{4})', d)
    if m:
        info['bios_date'] = m.group(3) + m.group(1) + m.group(2)
    volser, label, fs = _win_volume('C:\\')
    return bios_sn, disk_sn, cpu_name, volser, label, fs or 'NTFS', 'C'


# ---------------- Linux ----------------
def _linux_collect(info):
    bios_sn = _read('/sys/class/dmi/id/product_serial') or _read('/sys/class/dmi/id/board_serial')
    info['virtual'] = _read('/sys/class/dmi/id/sys_vendor')
    d = _read('/sys/class/dmi/id/bios_date')   # MM/DD/YYYY
    m = re.match(r'(\d{2})/(\d{2})/(\d{4})', d)
    if m:
        info['bios_date'] = m.group(3) + m.group(1) + m.group(2)
    cpu_name = ''
    try:
        with open('/proc/cpuinfo', encoding='utf-8', errors='replace') as f:
            for line in f:
                if line.lower().startswith('model name'):
                    cpu_name = line.split(':', 1)[1].strip()
                    break
    except OSError:
        pass
    disk_sn = ''
    for line in _run(['lsblk', '-dno', 'SERIAL']).splitlines():
        if line.strip():
            disk_sn = line.strip()
            break
    mid = _read('/etc/machine-id') or _read('/var/lib/dbus/machine-id')
    if len(mid) >= 32:
        mid = mid[:32].upper()
        info['guid'] = '{%s-%s-%s-%s-%s}' % (mid[:8], mid[8:12], mid[12:16], mid[16:20], mid[20:32])
    # 根文件系统 UUID 作为"卷序列号"
    volser = ''
    try:
        rootdev = None
        with open('/proc/mounts', encoding='utf-8', errors='replace') as f:
            for line in f:
                p = line.split()
                if len(p) >= 3 and p[1] == '/' and p[0].startswith('/dev/'):
                    rootdev = p[0]
                    break
        if rootdev:
            rp = os.path.realpath(rootdev)
            for link in sorted(_glob.glob('/dev/disk/by-uuid/*')):
                if os.path.realpath(link) == rp:
                    u = os.path.basename(link).replace('-', '')[:8]
                    volser = u[:4] + '-' + u[4:8]
                    break
    except OSError:
        pass
    fs = ''
    try:
        with open('/proc/mounts', encoding='utf-8', errors='replace') as f:
            for line in f:
                p = line.split()
                if len(p) >= 3 and p[1] == '/':
                    fs = p[2]
                    break
    except OSError:
        pass
    label = _run(['findmnt', '-no', 'LABEL', '/'])
    return bios_sn, disk_sn, cpu_name, volser, label, fs or 'ext4', '/'


@lru_cache(maxsize=1)
def collect() -> dict:
    """采集本机信息 (缓存)。失败项为通用占位值, 不影响登录。"""
    info = {
        'hardwarecode': '', 'macinfo': '', 'cpuinfo': '', 'computername': '',
        'hddinfo': '', 'guid': '', 'vol': '', 'virtual': '', 'bios_date': '',
    }
    if _IS_WIN:
        bios_sn, disk_sn, cpu_name, volser, label, fs, drive = _win_collect(info)
    else:
        bios_sn, disk_sn, cpu_name, volser, label, fs, drive = _linux_collect(info)

    info['cpuinfo'] = cpu_name or platform.processor() or 'Intel(R) Core(TM) CPU'
    info['computername'] = socket.gethostname()
    info['hddinfo'] = disk_sn
    info['vol'] = volser
    macs = _macs()
    info['macinfo'] = '^'.join(macs) if macs else '00:00:00:00:00:00'
    try:
        import shutil
        total_g = int(shutil.disk_usage('/').total // (1 << 30))
    except Exception:
        total_g = 0

    def md5u(s):
        return hashlib.md5(s.encode()).hexdigest().upper() if s else '0' * 32

    info['hardwarecode'] = (
        'BIOS:%s,HDD:%s,MAC:%s,PI:%s^%s^%dG,VOL:%s,VOLNAME:%s' % (
            md5u(bios_sn), md5u(disk_sn), macs[0] if macs else '00:00:00:00:00:00',
            drive, fs, total_g, volser, label))
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
