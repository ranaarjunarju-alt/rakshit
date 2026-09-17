#!/usr/bin/env python3
"""ROM-semantics gate: standard 035 structure + dialect bytecode semantics.
- dialect insn widths (stock-validated; 0x0a-0x0d = 1u per stock walk)
- dialect branch convention A: target = insn_unit_start + off
- 8-byte try items [start u32][cnt u16][hoff u16] + uleb handler section
Usage: python3 tmp_verify_rom.py classes2.dex
"""
import struct, sys
d = open(sys.argv[1] if len(sys.argv) > 1 else 'classes2.dex','rb').read()
def u32(o): return struct.unpack_from('<I', d, o)[0]
def uleb(p):
    r=s=0
    while True:
        x=d[p];p+=1;r|=(x&0x7f)<<s;s+=7
        if not x&0x80: return r,p
str_size, str_off = struct.unpack_from('<II', d, 0x38)
typ_size, typ_off = struct.unpack_from('<II', d, 0x40)
mtd_size, mtd_off = struct.unpack_from('<II', d, 0x58)
cls_size, cls_off = struct.unpack_from('<II', d, 0x60)
def str_at(i):
    p = u32(str_off+4*i); ln, p2 = uleb(p); return d[p2:p2+ln].decode('utf-8','replace')
def typ_at(i): return str_at(u32(typ_off+4*i))
methods = []
for i in range(mtd_size):
    c, pr, nm = struct.unpack_from('<HHI', d, mtd_off+8*i)
    methods.append((c, pr, nm))
SZ = {}
for o in [0x00,0x01,0x04,0x07,0x0e,0x0f,0x10,0x11,0x12,0x1d,0x1e,0x21,0x27,0x28,0x3e]: SZ[o]=1
for o in [0x02,0x03,0x05,0x06,0x08,0x09,0x0a,0x0b,0x0c,0x0d]: SZ[o]=1
for o in [0x13,0x15,0x16,0x19,0x1a,0x1c,0x1f,0x20,0x22,0x23,0x24,0x25,0x26]: SZ[o]=2
for o in range(0x29,0x3e): SZ[o]=2
for o in [0x3f,0x40,0x41,0x42,0x43,0x4f]: SZ[o]=2
for o in range(0x44,0x6e): SZ[o]=2
for o in range(0x6e,0x79): SZ[o]=3
for o in range(0x7b,0xd0): SZ[o]=2
SZ[0xd0]=3
for o in range(0xd1,0xe3): SZ[o]=2
for o in range(0xe3,0xf8): SZ[o]=2
SZ[0xfc]=SZ[0xfd]=2
for o in [0x14,0x17,0x18,0x1b]: SZ[o]=3
for o in [0xf8,0xf9,0xfa,0xfb]: SZ[o]=3
BR2 = set(range(0x32,0x3e)) | set(range(0x29,0x2d))
G8 = {0x28}
errors = []
n_methods = 0
def check_code(co, label):
    global n_methods
    regs, ins, outs, ntry, dbg, sz = struct.unpack_from('<HHHHII', d, co)
    base = co + 16
    units = struct.unpack_from('<%dH' % sz, d, base)
    starts = set(); i = 0
    while i < sz:
        u = units[i]; op = u & 0xFF
        w = SZ.get(op)
        if w is None:
            errors.append('%s: unknown opcode 0x%02x at u%d' % (label, op, i)); return
        if i + w > sz:
            errors.append('%s: insn at u%d overruns' % (label, i)); return
        starts.add(i)
        i += w
    i = 0
    while i < sz:
        u = units[i]; op = u & 0xFF
        w = SZ.get(op, 1)
        if op in BR2:
            off = units[i+1] - 0x10000 if units[i+1] & 0x8000 else units[i+1]
            t = i + off
            if not (0 <= t < sz):
                errors.append('%s: branch 0x%02x at u%d off %d -> t=%d OUT OF RANGE (sz=%d)' % (label, op, i, off, t, sz))
            elif t not in starts:
                errors.append('%s: branch 0x%02x at u%d off %d -> t=%d NOT AT INSTRUCTION START (dex pc 0x%x)' % (label, op, i, off, t, t))
        elif op in G8:
            o8 = (u >> 8) & 0xFF
            o8 -= 0x100 if o8 & 0x80 else 0
            t = i + o8
            if not (0 <= t < sz):
                errors.append('%s: goto/8 at u%d off %d -> t=%d OUT OF RANGE' % (label, i, o8, t))
            elif t not in starts:
                errors.append('%s: goto/8 at u%d off %d -> t=%d NOT AT INSTRUCTION START (dex pc 0x%x)' % (label, i, o8, t, t))
        i += w
    hp = base + 2*sz
    for t in range(ntry):
        s2, c2, hoff = struct.unpack_from('<IHH', d, hp + 8*t)
        if s2 + c2 > sz or s2 >= sz:
            errors.append('%s: try [%d,%d) bad (sz=%d)' % (label, s2, c2, sz))
        if hoff >= 8*ntry + 64:
            errors.append('%s: try handler off %d implausible' % (label, hoff))
    if ntry:
        q = hp + 8*ntry
        n, q = uleb(q)
        if n != ntry:
            errors.append('%s: handler count %d != ntry %d' % (label, n, ntry))
        for k in range(n):
            size, q = uleb(q)
            for _ in range(size):
                ti, q = uleb(q)
                if ti >= typ_size:
                    errors.append('%s: handler type %d oob' % (label, ti))
            h, q = uleb(q)
            if h not in starts:
                errors.append('%s: handler %d -> u%d NOT AT INSTRUCTION START' % (label, k, h))
    n_methods += 1
for ci in range(cls_size):
    o = cls_off + 32*ci
    cls_idx, access, sup, ifc, src, ann, cdo, par = struct.unpack_from('<8I', d, o)
    if cdo == 0: continue
    p = cdo
    ns, p = uleb(p); ni, p = uleb(p); nd, p = uleb(p); nv, p = uleb(p)
    for _ in range(ns+ni):
        df, p = uleb(p); fl, p = uleb(p)
    for sec_n in (nd, nv):
        prev = 0
        for _ in range(sec_n):
            df, p = uleb(p); prev += df
            fl, p = uleb(p)
            co, p = uleb(p)
            if co:
                c, pr, nm = methods[prev]
                check_code(co, '%s.%s' % (typ_at(c), str_at(nm)))
print('methods checked: %d' % n_methods)
print('ERRORS: %d' % len(errors))
for e in errors:
    print('  !!', e)
sys.exit(1 if errors else 0)
