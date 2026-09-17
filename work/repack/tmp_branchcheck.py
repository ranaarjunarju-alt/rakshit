#!/usr/bin/env python3
"""Verify the 11n/12x branch-offset convention against stock dialect bytecode.

For every 2-unit branch in a decoded stock method, test both conventions:
  A: target = insn_start_unit + off      (Dalvik spec: relative to first unit)
  B: target = offset_unit (insn_start+1) + off   (what our emitter does)
and check which one lands on a valid instruction start.
"""
import struct

B = open('work/repack/orig_dex/classes.dex', 'rb').read()
CODE_OFF = 0x9eae0
CODE_END = 0x2eb38a  # debug_off start

# ---- reuse scan: find all plausible code item headers ----
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
    return dict(h=h, regs=regs, ins=ins, insns=insns, ntry=ntry, dbg=dbg)

items = []
h = CODE_OFF
while h < CODE_END - 16:
    p = plausible(h)
    if p:
        items.append(p)
    h += 4

# keep only items that chain to the next found item (contiguous walk OK)
found = {p['h'] for p in items}
chain = []
for p in items:
    # next plausible header must be reachable: h + 16 + 2*insns + even
    rem = (CODE_END - p['h'])
    sz_base = 16 + 2*p['insns']
    # find candidate next item header
    nxt = None
    for q in items:
        if q['h'] > p['h']:
            gap = q['h'] - p['h']
            if gap >= sz_base and (gap - sz_base) % 2 == 0 and gap - sz_base < 200:
                nxt = q['h']; break
            if q['h'] - p['h'] > sz_base + 200: break
    p['nxt'] = nxt
    if nxt is not None and nxt in found:
        chain.append(p)

print(f'items: {len(items)}, chained: {len(chain)}')

# ---- decode helper: 35C style units ----
VALID_OP1 = set(range(0x00, 0x28)) | set(range(0x29, 0x40))  # 1-unit ops (0x28=goto/8 handled separately)
# branch opcodes (2-unit 11n): 0x2a..0x2f (goto/16, if-*z), 0x30..0x3f (if-*)
BR2 = set(range(0x2a, 0x40))
# 12x: 0x00..0x1f?  no: 12x = 0x00-0x0e? Dalvik 12x = moves (0x00-0x0e), 0x10-0x11? ...
# For boundary validity we mainly need: does unit t look like an instruction start?
# Heuristic: t is on an instruction boundary if decoding from it yields a valid stream
# through at least 3 instructions.

def dec_ok_from(units, t, maxins=4):
    """Try to decode maxins instructions starting at unit t. True if all valid."""
    n = len(units)
    i = t
    done = 0
    while i < n and done < maxins:
        op = units[i] & 0xFF
        if op == 0x28:                       # goto/8 (1 unit)
            i += 1
        elif op in BR2:                      # 11n (2 units)
            i += 2
        elif op in (0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f):  # 21s/22s/23x? no—21s is 0x1a-0x1f? 
            # 21s: 0x1a-0x1f (const/4? no). Use: 0x1a-0x1f = 21s (2 units)
            i += 2
        elif op == 0x20:                      # const/4 (1)
            i += 1
        elif op == 0x21:                      # const/16 (2)
            i += 2
        elif op == 0x22:                      # const (3)
            i += 3
        elif op == 0x23:                      # const/high16 (2)
            i += 2
        elif op == 0x24:                      # const-wide/4 (1)
            i += 1
        elif op == 0x25:                      # const-wide/16 (2)
            i += 2
        elif op == 0x26:                      # const-wide/32 (3)
            i += 3
        elif op == 0x27:                      # const-wide (4)
            i += 4
        elif 0x40 <= op <= 0x4f:              # cmove etc (2)
            i += 2
        elif 0x50 <= op <= 0x5f:              # cmove-wide etc? actually 0x50-0x5f cmove... (2)
            i += 2
        elif 0x60 <= op <= 0x6b:              # packed-switch etc (3+)
            i += 3
        elif op in (0x6e, 0x6f):              # throw, monitor... (1)
            i += 1
        elif op in (0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78,
                    0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f):
            i += 3                            # 35C invoke (3 units)
        elif op in (0x5b, 0x5c):              # iget/put etc? (2)
            i += 2
        elif op >= 0x100:                     # already-encoded wide form? treat as 2
            i += 2
        else:
            return False
        done += 1
    return True

results = {'A': 0, 'B': 0, 'both': 0, 'neither': 0, 'checked': 0}
examples = []
for p in chain[:400]:
    h = p['h']
    units = struct.unpack_from(f'<{p["insns"]}H', B, h + 16)
    i = 0
    while i < len(units) - 1:
        op = units[i] & 0xFF
        if op in BR2:
            off = struct.unpack_from('<h', bytes([units[i+1] & 0xFF, units[i+1] >> 8]))[0]
            # units are little-endian u16 already; offset = signed u16
            off = units[i+1] if units[i+1] < 0x8000 else units[i+1] - 0x10000
            tA = i + off          # convention A: relative to insn start
            tB = (i + 1) + off    # convention B: relative to offset unit
            okA = 0 < tA < len(units) and dec_ok_from(units, tA)
            okB = 0 < tB < len(units) and dec_ok_from(units, tB)
            results['checked'] += 1
            if okA and okB: results['both'] += 1
            elif okA: results['A'] += 1
            elif okB: results['B'] += 1
            else: results['neither'] += 1
            if (okA != okB) and len(examples) < 8:
                examples.append((hex(h), i, hex(off), 'A' if okA else 'B',
                                  'A-ok' if okA else '', 'B-ok' if okB else ''))
            i += 2
        elif op == 0x28:
            i += 1
        elif op >= 0x70 and op <= 0x7f:
            i += 3
        elif op in (0x21, 0x23, 0x25, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45,
                    0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
                    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59,
                    0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x60, 0x61, 0x62,
                    0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a):
            i += 2
        elif op in (0x22,):
            i += 3
        elif op == 0x27:
            i += 4
        else:
            i += 1

print(results)
for e in examples:
    print(e)
