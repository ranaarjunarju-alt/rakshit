#!/usr/bin/env python3
"""Decisive branch-offset convention test + full clean-walk with official sizes."""
import struct
from collections import defaultdict

B = open('work/repack/orig_dex/classes.dex', 'rb').read()
CODE_OFF = 0x9eae0
CODE_END = 0x2eb38a

# ---- official Dalvik sizes (from android-4.2.2 DexOpcodes.h + instruction formats) ----
SZ = {}
def S(ops, n):
    for o in ops: SZ[o] = n
S([0x00], 1)                            # NOP
for o in (0x0e,0x0f,0x10,0x11,0x12,0x1d,0x1e,0x21,0x27,0x28): S([o], 1)
S([0x01,0x04,0x07], 1)              # 12x move family (1 unit)
S([0x02,0x03,0x05,0x06,0x08,0x09], 2)  # 125x move family (2 units)
S([0x0a,0x0b,0x0c,0x0d], 2)          # 11n move-result family (2 units)
S([0x13,0x15,0x16,0x19,0x1a,0x1c,0x1f], 2)  # const16/high16/wide16/widehigh16, const-string/class, check-cast
S([0x20,0x22,0x23,0x24,0x25,0x26], 2)   # instance-of..fill-array-data
S(list(range(0x29,0x3e)), 2)            # goto/16..if-lez
S(list(range(0x2d,0x32)), 2)            # cmp family
S(list(range(0x44,0x6e)), 2)            # aget/aput/iget/iput/sget/sput
S(list(range(0x6e,0x79)), 3)            # invokes (35C + range)
S(list(range(0x7b,0xd0)), 2)            # neg/not/converts + 22x/23x arith
S([0xd0], 3)                            # add-int/lit16 (22t)
S(list(range(0xd1,0xe3)), 2)            # lit arith
S(list(range(0xe3,0xf8)), 2)            # volatile + inline + quick (all 2u)
S([0x14,0x17,0x18,0x1b], 3)             # const, const-wide/32, const-wide, const-string/jumbo
S([0xf8,0xf9,0xfa,0xfb], 3)             # invoke-*-quick (35C)

BR2 = set(range(0x29,0x3e)) | {0x2b, 0x2c}   # 2-unit branches/switches

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

clean = 0
unk = defaultdict(int)
nA = nB = nBoth = nNeither = 0
exA, exB = [], []
for h, insns in items:
    units = struct.unpack_from(f'<{insns}H', B, h + 16)
    # walk, collecting instruction-start set
    starts = set()
    i = 0
    ok = True
    while i < insns:
        op = units[i] & 0xFF
        sz = SZ.get(op)
        if sz is None:
            unk[op] += 1
            ok = False
            break
        starts.add(i)
        if op in BR2:
            off = units[i+1]
            off = off - 0x10000 if off & 0x8000 else off
            tA = i + off          # relative to insn start
            tB = (i + 1) + off    # relative to offset unit
            inA = tA in starts
            inB = tB in starts
            if inA and inB: nBoth += 1
            elif inA:
                nA += 1
                if len(exA) < 6: exA.append((hex(h), i, hex(off), tA))
            elif inB:
                nB += 1
                if len(exB) < 6: exB.append((hex(h), i, hex(off), tB))
            else: nNeither += 1
        i += sz
    if ok: clean += 1

print(f'clean walks: {clean}/{len(items)}')
print('unknown opcodes:', {hex(k): v for k, v in sorted(unk.items())[:20]})
print(f'\nbranch targets (only among branches whose target lies in the decoded prefix):')
print(f'  convention A (insn-start based): {nA}')
print(f'  convention B (offset-unit based): {nB}')
print(f'  both: {nBoth}   neither: {nNeither}')
print('  A-only examples:', exA)
print('  B-only examples:', exB)
