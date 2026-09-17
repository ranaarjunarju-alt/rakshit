#!/usr/bin/env python3
"""Which opcode table walks stock methods cleanly (exactly to end, no unknowns)?"""
import struct

B = open('work/repack/orig_dex/classes.dex', 'rb').read()
CODE_OFF = 0x9eae0
CODE_END = 0x2eb38a

def plausible(h):
    regs = struct.unpack_from('<H', B, h)[0]
    if not (1 <= regs <= 64): return None
    ins = struct.unpack_from('<H', B, h+2)[0]
    outs = struct.unpack_from('<H', B, h+4)[0]
    ntry = struct.unpack_from('<H', B, h+6)[0]
    dbg = struct.unpack_from('<I', B, h+8)[0]
    insns = struct.unpack_from('<I', B, h+12)[0]
    if ins > regs or outs > regs - ins: return None
    if not (1 <= insns <= 60000): return None
    if not (CODE_END <= dbg < 0x300000): return None
    return insns

items = []
h = CODE_OFF
while h < CODE_END - 16:
    p = plausible(h)
    if p: items.append((h, p))
    h += 4

# ---------------- candidate tables ----------------
def mk(one, two, three, four):
    t = {}
    for o in one: t[o] = 1
    for o in two: t[o] = 2
    for o in three: t[o] = 3
    for o in four: t[o] = 4
    return t

def R(a,b): return set(range(a,b+1))
# Table A: dex_core dialect
A = mk(
    one=R(0x0a, 0x13) | {0x16, 0x1d, 0x1e, 0x27, 0x28},
    two=R(0x01, 0x0a) | {0x13, 0x15, 0x1a} | R(0x20, 0x25) | R(0x29, 0x3e) |
        R(0x40, 0x70) | R(0x78, 0xfb) | {0xfb},
    three={0x14, 0x17, 0x18, 0x1b} | R(0x70, 0x78) | {0xfb, 0xfc, 0xfd},
    four={0x19},
)
# Table B: standard Dalvik
Bt = mk(
    one=R(0x0a, 0x13) | {0x16, 0x1d, 0x1e, 0x1f, 0x23, 0x28},
    two=R(0x01, 0x0a) | {0x13, 0x15, 0x17, 0x1a} | R(0x20, 0x23) | R(0x24, 0x27) |
        R(0x29, 0x3e) | R(0x40, 0x62) | {0x63, 0x65} | R(0x6a, 0x70) | R(0x78, 0xfb),
    three={0x14, 0x18, 0x1b} | {0x62} | R(0x70, 0x78) | {0xfb, 0xfc, 0xfd},
    four={0x19, 0x64},
)

def walk(units, t):
    i = 0
    while i < len(units):
        sz = t.get(units[i] & 0xFF)
        if sz is None: return None
        i += sz
    return True

for name, t in (('A=dexcore', A), ('B=standard', Bt)):
    clean = 0
    first_fail = []
    for h, insns in items[:6000]:
        units = struct.unpack_from(f'<{insns}H', B, h + 16)
        if walk(units, t):
            clean += 1
        elif len(first_fail) < 5:
            # find first unknown op
            i = 0
            while i < len(units):
                sz = t.get(units[i] & 0xFF)
                if sz is None:
                    first_fail.append((hex(h), i, hex(units[i] & 0xFF)))
                    break
                i += sz
    print(f'{name}: clean {clean}/6000   first-fails: {first_fail}')
