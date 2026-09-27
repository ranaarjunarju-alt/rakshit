#!/usr/bin/env python3
"""Recover all custom-B64 decoded strings: static staging tracking + Unicorn decode of 0x923c0."""
import sys, json, re
sys.path.insert(0, 'work/v846')
from elf_dump import elf64
import capstone
e = elf64('work/v846/extract/lib/arm64-v8a/libtopfollow.so')
raw = e['raw']
md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
DEC = 0x923c0
def rostr(addr, maxlen=256):
    end = addr
    while end < len(raw) and raw[end] != 0 and end - addr < maxlen: end += 1
    s = raw[addr:end]
    try: return s.decode('ascii')
    except: return None

# Unicorn decoder
from unicorn import *
from unicorn.arm64_const import *
import struct
CLOCK_STUB = 0x106040
CHKFAIL_STUBS = set()
stubs = json.load(open('work/v846/notes/v846_plt_stubs.json'))
imp2stub = {v: int(k,16) for k,v in stubs.items()}
BASE = 0x1000000000  # map file here? off==RVA so map at 0 is fine; use 0
OUT = 0x20000000
def make_decoder():
    uc = Uc(UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN)
    uc.mem_map(0x0, 0x200000, UC_PROT_ALL)
    uc.mem_write(0x0, raw)
    uc.mem_map(OUT-0x1000, 0x2000, UC_PROT_ALL)
    uc.mem_map(0x7f000000, 0x20000, UC_PROT_ALL)  # stack
    def ret_shim(uc, addr, size, user):
        if addr == CLOCK_STUB:
            uc.reg_write(UC_ARM64_REG_X0, 1700000000)
            pc = uc.reg_read(UC_ARM64_REG_X30)
            uc.reg_write(UC_ARM64_REG_PC, pc)
            uc.emu_stop()
        elif addr in (imp2stub.get('__stack_chk_fail',0),):
            uc.reg_write(UC_ARM64_REG_X0, 1)
            pc = uc.reg_read(UC_ARM64_REG_X30)
            uc.reg_write(UC_ARM64_REG_PC, pc)
            uc.emu_stop()
    uc.hook_add(UC_HOOK_CODE, ret_shim, begin=CLOCK_STUB, end=CLOCK_STUB+0x10)
    if imp2stub.get('__stack_chk_fail'):
        sf = imp2stub['__stack_chk_fail']
        uc.hook_add(UC_HOOK_CODE, ret_shim, begin=sf, end=sf+0x10)
    return uc
def decode923c0(uc, enc: bytes, out_addr=OUT):
    uc.mem_write(out_addr, b'\x00'*0x1000)
    uc.mem_write(OUT-0x400, enc + b'\x00'*64)
    src = OUT-0x400
    sp = 0x7f010000
    uc.reg_write(UC_ARM64_REG_SP, sp)
    uc.reg_write(UC_ARM64_REG_X29, sp)
    uc.reg_write(UC_ARM64_REG_X0, src)
    uc.reg_write(UC_ARM64_REG_W1, len(enc))
    uc.reg_write(UC_ARM64_REG_X8, out_addr)
    uc.reg_write(UC_ARM64_REG_X30, 0x7f01ff00)
    try:
        uc.emu_start(DEC, 0, timeout=0, count=200000)
    except UcError as ex:
        return None
    b = uc.mem_read(out_addr, 512)
    i = b.find(b'\x00')
    s = b[:i if i>=0 else 512]
    try: return s.decode('utf-8')
    except: return None

if __name__ == '__main__':
    # quick self-test: decode the 0x16ed0 "nivafollower" encoding? find its encoded source
    uc = make_decoder()
    # test with 0x17208 (59B) — expect something
    enc = raw[0x17208:0x17208+59]
    print("0x17208 decoded:", repr(decode923c0(uc, enc)))
    for a, l in [(0x1721b, 13), (0x17227, 11), (0x14854, 15), (0x14a48, 7), (0x1675b, 6), (0x16ed0, 12)]:
        print(f"{a:#x} len{l} decoded:", repr(decode923c0(uc, raw[a:a+l])))
