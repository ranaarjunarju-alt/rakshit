#!/usr/bin/env python3
"""
v846 Unicorn harness — emulates libtopfollow.so (arm64) functions in isolation.
File offset == RVA for this ELF (single 0x10c488-byte load + tail).
Usage:
    from unicorn_v846 import setup, run
    uc = setup()
    steps = run(uc, 0x31260, {UC_ARM64_REG_X0: ctx, ...})
"""
import struct, json, os
from unicorn import *
from unicorn.arm64_const import *

SO = os.path.join(os.path.dirname(__file__), 'extract/lib/arm64-v8a/libtopfollow.so')
GOTPLT = os.path.join(os.path.dirname(__file__), 'notes/v846_gotplt.json')

class Stop(Exception): pass

def setup():
    with open(SO, 'rb') as f:
        raw = f.read()
    ST = 0x800000000000
    uc = Uc(UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN)
    uc.mem_map(0, 0x400000)                      # image (0..0x400000)
    uc.mem_map(ST - 0x100000, 0x200000)          # stack + test buffers
    # load: file 0..0x1064b0 @ VA 0 ; 0x1064b0..0x10c2a8 @ same ; 0x10c488..0x10ce28 @ 0x114488 (.bss head w/ file data)
    for off, va, fsz in [(0, 0, 0x1064b0), (0x1064b0, 0x10a4b0, 0x5fd8), (0x10c488, 0x114488, 0x68)]:
        uc.mem_write(va, raw[off:off + fsz])
    uc.reg_write(UC_ARM64_REG_SP, ST - 0x1000)
    # IRELATIVE pair used by guard-counter prologues
    uc.mem_write(0x10ead0, struct.pack('<Q', 0x116704))
    uc.mem_write(0x10ead8, struct.pack('<Q', 0x11670c))
    # resolve ALL IRELATIVE relocs (addend IS final pointer for this build)
    for i in range(0xfbe8 // 24):
        o = 0x10e0 + 24 * i
        r_off, r_info, r_add = struct.unpack_from('<QQq', raw, o)
        if (r_info & 0xffffffff) == 1027:
            uc.mem_write(r_off, struct.pack('<Q', r_add))
    # RETZERO trampoline for all PLT/GOT slots
    TZ = 0x330000
    uc.mem_write(TZ, struct.pack('<II', 0xd2800000, 0xd65f03c0))  # mov x0,#0 ; ret
    got2imp = {int(k, 10): v for k, v in json.load(open(GOTPLT)).items()}
    for slot in got2imp:
        uc.mem_write(slot, struct.pack('<Q', TZ))
    return uc

def runctors(uc):
    """Run the two .init_array constructors (populate .bss registry)."""
    st = [0]
    def cb(uc_, a, s, ud):
        st[0] += 1
        if st[0] > 300_000: raise Stop
    uc.hook_add(UC_HOOK_CODE, cb)
    for ctor in (0x37550, 0xcc4c8):
        try:
            uc.emu_start(ctor, 0, timeout=0, count=300_000)
        except (UcError, Stop): pass
    return st[0]

def run(uc, start, regs, count=500_000):
    """Emulate from start until it returns (until=0) or count steps; returns step count."""
    st = [0]
    def cb(uc_, a, s, ud):
        st[0] += 1
        if st[0] > count: raise Stop
    uc.hook_add(UC_HOOK_CODE, cb)
    for r, v in regs.items():
        uc.reg_write(r, v)
    try:
        uc.emu_start(start, 0, timeout=0, count=count)
    except (UcError, Stop): pass
    return st[0]

# --- verified helpers -------------------------------------------------
CTX, KEY, SRC, DST = 0x300000, 0x320000, 0x331000, 0x332000

def init_keyexp(uc, key: bytes, iv: bytes = b'\x00' * 16):
    uc.mem_write(CTX, b'\x00' * 0x1000)
    uc.mem_write(KEY, key)
    uc.mem_write(0x321000, iv)
    run(uc, 0x31260, {UC_ARM64_REG_X0: CTX, UC_ARM64_REG_X1: KEY, UC_ARM64_REG_X2: 0x321000,
                      UC_ARM64_REG_X3: len(key), UC_ARM64_REG_X4: 16})

def block_enc(uc, src, dst):
    run(uc, 0x2edf8, {UC_ARM64_REG_X0: CTX, UC_ARM64_REG_X1: src, UC_ARM64_REG_X2: dst})
    return bytes(uc.mem_read(dst, 16))

def block_dec(uc, src, dst):
    run(uc, 0x2fdcc, {UC_ARM64_REG_X0: CTX, UC_ARM64_REG_X1: src, UC_ARM64_REG_X2: dst})
    return bytes(uc.mem_read(dst, 16))

def stream_enc(uc, data: bytes, mode: int, dst=0x332000):
    """0x33260 (ctx, in, out, len, mode) — data must be %16==0."""
    u_src = 0x331000
    uc.mem_write(u_src, data)
    uc.mem_write(dst, b'\x00' * (len(data) + 0x40))
    run(uc, 0x33260, {UC_ARM64_REG_X0: CTX, UC_ARM64_REG_X1: u_src, UC_ARM64_REG_X2: dst,
                      UC_ARM64_REG_X3: len(data), UC_ARM64_REG_X4: mode})
    return bytes(uc.mem_read(dst, len(data)))

def stream_dec(uc, data: bytes, mode: int = 0, dst=0x332000):
    """0x33aa8 (ctx, in, out, len, mode)."""
    u_src = 0x331000
    uc.mem_write(u_src, data)
    uc.mem_write(dst, b'\x00' * (len(data) + 0x40))
    run(uc, 0x33aa8, {UC_ARM64_REG_X0: CTX, UC_ARM64_REG_X1: u_src, UC_ARM64_REG_X2: dst,
                      UC_ARM64_REG_X3: len(data), UC_ARM64_REG_X4: mode})
    return bytes(uc.mem_read(dst, len(data)))

if __name__ == '__main__':
    # self-test: FIPS-197 vectors
    pt = bytes.fromhex('00112233445566778899aabbccddeeff')
    vectors = {
        16: (bytes(range(16)), '69c4e0d86a7b0430d8cdb78070b4c55a'),
        24: (bytes(range(24)), 'dda97ca4864cdfe06eaf70a0ec0d7191'),
        32: (bytes(range(32)), '8ea2b7ca516745bfeafc49904b496089'),
    }
    ok = 0
    for n, (key, cth) in vectors.items():
        uc = setup()
        init_keyexp(uc, key)
        uc.mem_write(0x334000, pt); ct = block_enc(uc, 0x334000, 0x335000)
        pt2 = block_dec(uc, 0x334000, 0x336000) if False else None
        uc.mem_write(0x334000, bytes.fromhex(cth)); rt = block_dec(uc, 0x334000, 0x336000)
        good = (ct.hex() == cth) and (rt == pt)
        ok += good
        print(f"AES-{n*8}: {'MATCH' if good else 'FAIL'}")
    print(f"{ok}/3 passed")
