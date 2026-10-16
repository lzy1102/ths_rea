import ctypes, ctypes.wintypes as w, sys
from pathlib import Path

PID = int(sys.argv[1])
OUT = Path(sys.argv[2])
OUT.mkdir(parents=True, exist_ok=True)

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
MEM_COMMIT = 0x1000
PAGE_GUARD = 0x100
PAGE_NOACCESS = 0x01

class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", w.LPVOID),
        ("AllocationBase", w.LPVOID),
        ("AllocationProtect", w.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", w.DWORD),
        ("Protect", w.DWORD),
        ("Type", w.DWORD),
    ]

h = k32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, PID)
if not h:
    print("OpenProcess failed", ctypes.get_last_error())
    sys.exit(1)
print(f"opened pid={PID}")

addr = 0
MAX_ADDR = 0x7FFFFFFF if sys.maxsize < 2**32 else 0xFFFFFFFF
mbi = MEMORY_BASIC_INFORMATION()
count = 0
dumped = 0
total = 0
while addr < MAX_ADDR:
    r = k32.VirtualQueryEx(h, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi))
    if not r:
        break
    base = int(mbi.BaseAddress or 0)
    size = int(mbi.RegionSize)
    prot = int(mbi.Protect)
    state = int(mbi.State)
    typ = int(mbi.Type)
    if state == MEM_COMMIT and size >= 1024 and not (prot & PAGE_NOACCESS) and not (prot & PAGE_GUARD):
        buf = ctypes.create_string_buffer(size)
        read = ctypes.c_size_t(0)
        ok = k32.ReadProcessMemory(h, ctypes.c_void_p(base), buf, size, ctypes.byref(read))
        n = int(read.value)
        if ok and n > 0:
            fn = OUT / f"region_{base:08x}_{size:08x}_p{prot:02x}_t{typ:04x}.bin"
            with open(fn, "wb") as f:
                f.write(buf.raw[:n])
            dumped += 1
            total += n
    addr = base + size if size else addr + 0x1000
    count += 1
k32.CloseHandle(h)
print(f"regions scanned={count} dumped={dumped} bytes={total/1048576:.1f}MB")
