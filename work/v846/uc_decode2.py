#!/usr/bin/env python3
"""Unicorn emulation of the 0x923c0 custom-B64 decoder (v3: full PLT shim dispatch, struct output)."""
import sys, json, struct
sys.path.insert(0, 'work/v846')
from elf_dump import elf64
e = elf64('work/v846/extract/lib/arm64-v8a/libtopfollow.so')
raw = e['raw']
from unicorn import Uc, UcError, UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN, UC_PROT_ALL, UC_HOOK_CODE
from unicorn.arm64_const import *
import capstone
DEC = 0x923c0
TP = 0x60000000      # tpidr page + bump allocator state
SRC = 0x70000000     # encoded input
STRUCT = 0x70010000  # output string struct
STACK = 0x7f000000
HEAP = 0x80000000
CLOCK_VAL = 1700000000

stubs = json.load(open('work/v846/notes/v846_plt_stubs.json'))
STUB2IMP = {int(k, 16): v for k, v in stubs.items()}

class VM:
    def __init__(self, counters=None):
        self.uc = Uc(UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN)
        uc = self.uc
        uc.mem_map(0x0, 0x200000, UC_PROT_ALL); uc.mem_write(0, raw)
        for a, n in ((TP, 0x10000), (SRC, 0x1000), (STRUCT, 0x1000), (STACK, 0x20000), (HEAP, 0x100000)):
            uc.mem_map(a, n, UC_PROT_ALL)
        uc.mem_write(TP + 0x28, struct.pack('<Q', 0xdeadbeefcafe1234))
        uc.reg_write(UC_ARM64_REG_TPIDR_EL0, TP)
        self.bump = [HEAP]
        if counters:
            for slot, val in counters.items():
                uc.mem_write(slot, struct.pack('<I', val & 0xffffffff))
        for stub, imp in STUB2IMP.items():
            def mk(imp=imp):
                def h(uc, addr, size, ud):
                    self._shim(uc, imp)
                return h
            uc.hook_add(UC_HOOK_CODE, mk(), begin=stub, end=stub + 0x10)

    def _shim(self, uc, imp):
        x0 = uc.reg_read(UC_ARM64_REG_X0)
        x1 = uc.reg_read(UC_ARM64_REG_X1)
        x2 = uc.reg_read(UC_ARM64_REG_X2)
        if imp == 'clock':
            r = CLOCK_VAL
        elif imp in ('__stack_chk_fail', 'abort', 'exit'):
            r = 1
        elif imp == 'strlen':
            b = uc.mem_read(x0, 0x400)
            i = b.find(b'\x00')
            r = i if i >= 0 else 0x400
        elif imp == 'memcpy':
            if x2 < 0x10000:
                uc.mem_write(x0, uc.mem_read(x1, x2))
            r = x0
        elif imp == 'memmove':
            if x2 < 0x10000:
                uc.mem_write(x0, uc.mem_read(x1, x2))
            r = x0
        elif imp == 'memset':
            if 0 < x2 < 0x10000:
                uc.mem_write(x0, bytes([x1 & 0xFF]) * x2)
            r = x0
        elif imp in ('malloc', 'calloc'):
            size = x0 if imp == 'malloc' else (x0 * x1 if x0 else 0)
            size = min(size, 0x100000)
            p = self.bump[0]
            need = ((size + 15) // 16) * 16 or 16
            self.bump[0] = p + need
            if imp == 'calloc':
                uc.mem_write(p, b'\x00' * need)
            r = p
        elif imp == 'realloc':
            size = min(x1, 0x100000)
            p = self.bump[0]
            need = ((size + 15) // 16) * 16 or 16
            if x0 and HEAP <= x0 < self.bump[0] and size:
                uc.mem_write(p, uc.mem_read(x0, min(size, self.bump[0] - x0)))
            self.bump[0] = p + need
            r = p
        elif imp == 'free':
            r = 0
        elif imp == 'printf':
            r = 0
        else:
            r = 0  # default: pretend success/zero
        uc.reg_write(UC_ARM64_REG_X0, r & 0xFFFFFFFFFFFFFFFF)
        lr = uc.reg_read(UC_ARM64_REG_X30)
        uc.reg_write(UC_ARM64_REG_PC, lr)

def read_cstr(uc, addr, maxn=0x400):
    b = uc.mem_read(addr, maxn)
    i = b.find(b'\x00')
    return bytes(b[:i if i >= 0 else maxn])

def read_string_struct(uc, addr):
    hdr = struct.unpack('<Q', uc.mem_read(addr, 8))[0]
    if hdr & 1:
        ln = struct.unpack('<Q', uc.mem_read(addr + 8, 8))[0]
        ptr = struct.unpack('<Q', uc.mem_read(addr + 16, 8))[0]
        if ln >= 0x1000: return None
        return read_cstr(uc, ptr, ln + 2)
    ln = hdr >> 1
    if ln > 22: return None
    return read_cstr(uc, addr + 1, ln + 2)

def decode(vm, enc: bytes, out_struct=STRUCT):
    uc = vm.uc
    uc.mem_write(SRC, enc + b'\x00' * 0x100)
    uc.mem_write(out_struct, b'\x00' * 0x40)
    sp = STACK + 0x10000
    uc.reg_write(UC_ARM64_REG_SP, sp)
    uc.reg_write(UC_ARM64_REG_X29, sp)
    uc.reg_write(UC_ARM64_REG_X0, SRC)
    uc.reg_write(UC_ARM64_REG_W1, len(enc))
    uc.reg_write(UC_ARM64_REG_X8, out_struct)
    uc.reg_write(UC_ARM64_REG_X30, sp + 0x80)
    try:
        uc.emu_start(DEC, 0, timeout=0, count=2_000_000)
    except UcError as ex:
        return None, f"err={ex} pc={hex(uc.reg_read(UC_ARM64_REG_PC))}"
    pc = uc.reg_read(UC_ARM64_REG_PC)
    s = read_string_struct(uc, out_struct)
    return s, f"pc={pc:#x}"

if __name__ == '__main__':
    SLOTS = [0x10ec28, 0x10f330, 0x10f480, 0x10f490, 0x10f4a0, 0x10f4b0]
    enc = raw[0x16ed0:0x16ed0+36]
    found = None
    for A in range(0, 8):
        for B in range(0, 16):
            cnt = {}
            for s in SLOTS:
                cnt[s] = A
                cnt[s + 8] = B
            vm = VM(cnt)
            s, info = decode(vm, enc)
            if s:
                print(f"A={A} B={B} -> {s!r} ({info})")
                found = (A, B, s)
                break
            if A == 0 and B == 0:
                print("diag A0B0:", info)
        if found:
            break
    if not found:
        print("FAILED: no uniform counter combo")
