#!/usr/bin/env python3
"""Full-region opcode histogram + arg analysis on stock, to identify the
dialect's actual instruction set (esp. sget/sput/iget/iput family)."""
import struct
from collections import defaultdict

B = open('work/repack/orig_dex/classes.dex', 'rb').read()
CODE_OFF = 0x9eae0
CODE_END = 0x2eb38a

# confident 1-unit opcodes (return/const4/goto8 family — verified vs stock)
ONE = set(range(0x0e, 0x13)) | {0x16, 0x1d, 0x1e, 0x1f, 0x27, 0x28}
# 3-unit: const(0x14) const-wide/32(0x18) const-string/jumbo(0x1b) invokes 0x70-0x77
THREE = {0x14, 0x18, 0x1b} | set(range(0x70, 0x78))
FOUR = {0x19, 0x64}            # const-wide, lookup-switch
# everything else: treat as 2-unit while histogramming (report unknowns)
TWO_MAX_ARG = 0xFFFF

hist = defaultdict(int)
argmax = defaultdict(int)
argmin = defaultdict(lambda: 1 << 30)
stopped = 0
total = 0
walked_methods = 0

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
    return regs, ins, insns

# all plausible headers (from earlier scan technique)
items = []
h = CODE_OFF
while h < CODE_END - 16:
    p = plausible(h)
    if p: items.append((h, p))
    h += 4

for h, (regs, ins, insns) in items:
    total += 1
    units = struct.unpack_from(f'<{insns}H', B, h + 16)
    i = 0
    ok = True
    while i < insns:
        u = units[i]
        op = u & 0xFF
        if op in ONE:
            sz = 1
        elif op in THREE:
            sz = 3
        elif op in FOUR:
            sz = 4
        else:
            sz = 2
        hist[op] += 1
        if sz >= 2 and i + 1 < insns:
            a = units[i+1]
            argmax[op] = max(argmax[op], a)
            argmin[op] = min(argmin[op], a)
        i += sz
    walked_methods += 1

print(f'methods walked: {walked_methods}')
print(f'{"op":>5} {"count":>8} {"argmin":>8} {"argmax":>8}')
for op in sorted(hist):
    print(f'0x{op:02x}  {hist[op]:>8}  '
          f'{argmin[op] if argmin[op] < (1<<30) else "-":>8}  {argmax[op]:>8}')
