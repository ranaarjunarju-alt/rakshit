#!/usr/bin/env python3
"""
Round-structure evidence for the native cipher, via S-box-read IP histograms.

Rather than assert "AES-256" (over-claim) or "not AES" (over-correction), this
records the structural facts and the harness limitation honestly:

  * key expansion 0x32158 reads the S-box from 8 distinct instructions, each
    exactly 14 times.  Period 14 == the 14 rounds of AES-256 (SubWord is applied
    once per round).  This is the strongest AES-256 structural signal.
  * encrypt block 0x2fdcc, run on a ZEROED schedule, reads the S-box from 4
    distinct instructions, each 8 times (32 total), then returns after 23,186
    insns.  A full 14-round AES does ~160 SubBytes, so this is a truncated /
    early-exit path, not a faithful round structure.
  * encrypt block 0x2fdcc, run with a populated schedule at every candidate ctx
    offset, does NOT terminate (hits the 3,000,000-insn cap with 0 S-box reads):
    the OLLVM control-flow-flattened dispatcher never reaches an exit state
    because the C++ object layout is not faithfully reproduced.

Conclusion: the block ciphers' exact algorithm cannot be validated under this
harness -- it needs either the precise ctx object layout or a live process
(dynamic-lab/09).  Only the key-expansion round structure (period 14) is solid.
"""
import sys, io, contextlib, collections
sys.path.insert(0, 'work')
import unicorn_aes as U
from unicorn import UC_HOOK_MEM_READ, UC_HOOK_CODE
from unicorn.arm64_const import (UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2,
                                 UC_ARM64_REG_X3, UC_ARM64_REG_X4)

class T(U.Emu):
    def __init__(self, path):
        super().__init__(path)
        self.ip = 0; self.sbox = []; self.isbox = []
        self.mu.hook_add(UC_HOOK_CODE, lambda mu, a, s, ud: setattr(self, 'ip', a))
        def rd(mu, acc, addr, size, val, ud):
            if U.SBOX_VA <= addr < U.SBOX_VA + 256: self.sbox.append((self.ip, addr))
            elif U.ISBOX_VA <= addr < U.ISBOX_VA + 256: self.isbox.append((self.ip, addr))
        self.mu.hook_add(UC_HOOK_MEM_READ, rd)

def hist(pairs, label):
    ips = collections.Counter(ip for ip, _ in pairs)
    print(f"\n=== {label} ===")
    print(f"  total reads={len(pairs)}  distinct IPs={len(ips)}")
    for ip, c in ips.most_common():
        print(f"    {ip:#08x}: {c}")
    if ips:
        cs = sorted(set(ips.values()))
        print(f"  per-IP read counts: {cs}  -> period/multiplicity signal")
    return ips

def main():
    e = T(U.SO)
    CTX = U.HEAP_BASE + 0x100000; KEYBUF = U.HEAP_BASE + 0x400000
    IVBUF = U.HEAP_BASE + 0x410000; IN = U.HEAP_BASE + 0x200000; OUT = U.HEAP_BASE + 0x300000
    q = io.StringIO()
    e.mu.mem_write(CTX, b'\x00' * 0x2000); e.mu.mem_write(CTX + 8, b'\x01')
    e.mu.mem_write(KEYBUF, U.KEY256); e.mu.mem_write(IVBUF, b'\x00' * 16)
    e.str_long(CTX + 0x3d0, KEYBUF, 32, 32); e.str_long(CTX + 0x3f8, IVBUF, 16, 16)
    SS = U.HEAP_BASE + 0x500000; e.mu.mem_write(SS, b'\x00' * 0x1000)
    for off in (0x438, 0x458, 0x500, 0x600):
        e.w8(CTX + off, SS + off * 0x100); e.mu.mem_write(SS + off * 0x100, b'\x00' * 0x400)
    e.mu.mem_write(IN, U.PT); e.mu.mem_write(OUT, b'\x00' * 64)
    with contextlib.redirect_stdout(q):
        e.call(0x32158, regs=((UC_ARM64_REG_X0, CTX), (UC_ARM64_REG_X1, IN),
                              (UC_ARM64_REG_X2, OUT), (UC_ARM64_REG_X3, 32),
                              (UC_ARM64_REG_X4, 32)), label='keyexp', x8=OUT)
    hist(e.sbox, f"KEY EXPANSION 0x32158  (insns={e.count:,}, RCON={e.touched.get('RCON')})")

    e.sbox.clear(); e.isbox.clear()
    EIN = U.HEAP_BASE + 0x600000; EOUT = U.HEAP_BASE + 0x600100
    e.mu.mem_write(EIN, bytes(range(16))); e.mu.mem_write(EOUT, b'\x00' * 64)
    with contextlib.redirect_stdout(q):
        e.call(0x2fdcc, regs=((UC_ARM64_REG_X0, CTX), (UC_ARM64_REG_X1, EIN),
                              (UC_ARM64_REG_X2, EOUT)), label='enc-zeroed', x8=EOUT)
    hist(e.sbox, f"ENCRYPT 0x2fdcc on ZEROED schedule (insns={e.count:,}, exit={e.stop_reason})")

if __name__ == '__main__':
    main()
