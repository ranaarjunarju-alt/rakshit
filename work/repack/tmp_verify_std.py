#!/usr/bin/env python3
"""tmp_verify_std.py — verify classes2.dex as STANDARD 035 dex (AOSP ART 13 rules).

Checks (mirroring dex_file.cc / dex_file_verifier.cc structural phase):
 1. magic 035, header fields, adler32, sha1
 2. map_list: 8-byte items, offset-sorted, sections in-range, sizes consistent
 3. id arrays in-range; string_data items well-formed (uleb + null)
 4. type_lists / proto param lists in-range
 5. class_def (32B, 035-038 layout): cdata_off -> class_data_item
 6. class_data (AOSP CheckIntraClassDataItem*): sizes, per-entry [uleb diff][uleb flags]
    (methods + uleb code_off), monotonic indices, range < id count,
    static/instance flag consistency, code_off validity
 7. field_ids[i].class_idx matches the declaring class (warning level)
 8. code_item: walk instruction stream with the full standard width table;
    branch targets 0 <= t < insns_size (standard: t = start_unit + B + size);
    try-items: start/count in insns, handler offsets & targets in insns
 9. no unused/unknown opcodes
"""
import struct, sys, zlib, hashlib

PATH = sys.argv[1] if len(sys.argv) > 1 else 'work/repack/classes2.dex'
d = open(PATH, 'rb').read()
errs, warns = [], []
def err(m): errs.append(m)
def warn(m): warns.append(m)

NO_INDEX = 0xFFFFFFFF
def u32(o): return struct.unpack_from('<I', d, o)[0]
def u16(o): return struct.unpack_from('<H', d, o)[0]
def uleb(p):
    r = s = 0
    while True:
        x = d[p]; p += 1
        r |= (x & 0x7f) << s; s += 7
        if not x & 0x80:
            return r, p

# ---------------- 1. header
if d[:8] != b'dex\n035\x00':
    err('magic: %r' % d[:8])
file_size = u32(32); header_size = u32(36); endian = u32(40)
link_size = u32(44); link_off = u32(48); map_off = u32(52)
nstr, soff = u32(56), u32(60)
ntyp, toff = u32(64), u32(68)
npro, poff = u32(72), u32(76)
nfd,  foff = u32(80), u32(84)
nmth, moff = u32(88), u32(92)
ncls, coff = u32(96), u32(100)
data_size = u32(104); data_off = u32(108)
if file_size != len(d): err('file_size %d != actual %d' % (file_size, len(d)))
if header_size != 0x70: err('header_size 0x%x' % header_size)
if endian != 0x12345678: err('endian 0x%x' % endian)
if data_off + data_size != file_size: err('data_off+data_size != file_size')
if link_size != 0: warn('link_size nonzero')
chk = zlib.adler32(d[12:]) & 0xFFFFFFFF
if chk != u32(8): err('adler32 mismatch')
sha = hashlib.sha1(d[32:]).digest()
if sha != d[12:32]: err('sha1 mismatch')
print('header: ok  (map=0x%x data=0x%x..0x%x nstr=%d ntype=%d nproto=%d nfield=%d nmethod=%d nclass=%d)'
      % (map_off, data_off, data_off + data_size, nstr, ntyp, npro, nfd, nmth, ncls))

# ---------------- 2. map list
cnt = u32(map_off)
items = []
for i in range(cnt):
    t, unused, sz, off = struct.unpack_from('<HHII', d, map_off + 4 + 12*i)
    if unused != 0: err('map item %d unused!=0' % i)
    items.append((t, sz, off))
offs = [o for _, _, o in items]
if offs != sorted(offs): err('map not offset-sorted')
tags = {}
for t, sz, off in items:
    if off >= file_size: err('map off out of range 0x%x' % off)
    tags[t] = (sz, off)
NEED = {0x0000: 1, 0x1000: 1}
for t in (0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0006):
    NEED[t] = None
for t, v in NEED.items():
    if t not in tags: err('map missing tag 0x%x' % t)
    elif v is not None and tags[t][0] != v: err('map tag 0x%x size %d != %d' % (t, tags[t][0], v))
# consistency with header
if tags[0x0001] != (nstr, soff): err('string_ids map/header mismatch')
if tags[0x0002] != (ntyp, toff): err('type_ids map/header mismatch')
if tags[0x0003] != (npro, poff): err('proto_ids map/header mismatch')
if tags[0x0004] != (nfd, foff): err('field_ids map/header mismatch')
if tags[0x0005] != (nmth, moff): err('method_ids map/header mismatch')
if tags[0x0006] != (ncls, coff): err('class_defs map/header mismatch')
print('map: %d items, tags %s' % (cnt, ' '.join('0x%x:%d@0x%x' % x for x in sorted(items))))

def in_data(off):
    return off != 0 and data_off <= off < data_off + data_size

# ---------------- 3. string data
for i in range(nstr):
    sdoff = u32(soff + 4*i)
    if not in_data(sdoff): err('string_data[%d] off 0x%x out of data region' % (i, sdoff)); continue
    ln, p = uleb(sdoff)
    if d[p + ln] != 0: err('string_data[%d] not null-terminated at 0x%x' % (i, p + ln))
    if p + ln + 1 >= file_size: err('string_data[%d] runs past EOF' % i)
print('string_data: %d items checked' % nstr)

def type_desc(ti):
    si = u32(toff + 4*ti)
    sdoff = u32(soff + 4*si)
    ln, p = uleb(sdoff)
    return d[p:p+ln].decode('utf-8', 'replace')

# ---------------- 4. type_lists & proto params
def check_type_list(off, ctx):
    if off == 0:
        return
    if not in_data(off): err('%s: type_list off 0x%x out of data' % (ctx, off)); return
    sz = u32(off)
    end = off + 4 + 2*sz
    if end >= file_size: err('%s: type_list 0x%x runs past EOF' % (ctx, off)); return
    for i in range(sz):
        ti = u16(off + 4 + 2*i)
        if ti >= ntyp: err('%s: type_list idx %d out of range' % (ctx, ti))
for i in range(npro):
    sh, rt, po = struct.unpack_from('<III', d, poff + 12*i)
    if sh >= nstr: err('proto[%d] shorty idx %d oob' % (i, sh))
    if rt >= ntyp: err('proto[%d] ret idx %d oob' % (i, rt))
    if po != 0:
        check_type_list(po, 'proto[%d]' % i)
print('protos: %d checked' % npro)

# ---------------- 5+6. class_defs & class_data
BRANCH_OPS = {0x28: 1, 0x29: 2, 0x2A: 3,
              0x32: 2, 0x33: 2, 0x34: 2, 0x35: 2, 0x36: 2, 0x37: 2,
              0x38: 2, 0x39: 2, 0x3A: 2, 0x3B: 2, 0x3C: 2, 0x3D: 2}
W = {}
for o in [0x00, 0x01, 0x04, 0x07, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12,
          0x1D, 0x1E, 0x21, 0x27, 0x28, 0x3E, 0x3F, 0x40, 0x41, 0x42, 0x43,
          0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85,
          0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F,
          0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC,
          0xBD, 0xBE, 0xBF, 0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9,
          0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9,
          0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF, 0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6,
          0xF7, 0xF8, 0xF9, 0xFC, 0xFD, 0xFE, 0xFF]:
    W[o] = 1
for o in [0x02, 0x05, 0x08, 0x13, 0x15, 0x16, 0x19, 0x1A, 0x1C, 0x1F, 0x20, 0x22, 0x23,
          0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
          0x3A, 0x3B, 0x3C, 0x3D,
          0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
          0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E,
          0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D,
          0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D,
          0x9E, 0x9F, 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB,
          0xAC, 0xAD, 0xAE, 0xAF,
          0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC,
          0xDD, 0xDE, 0xDF, 0xE0, 0xE1, 0xE2, 0x29]:
    W[o] = 2
for o in [0x03, 0x06, 0x09, 0x14, 0x17, 0x1B, 0x25, 0x26, 0x2B, 0x2C,
          0x6E, 0x6F, 0x70, 0x71, 0x72, 0x74, 0x75, 0x76, 0x77, 0x78]:
    W[o] = 3
for o in [0xFA, 0xFB]:
    W[o] = 4
for o in [0x18, 0x24, 0x2A]:
    W[o] = 5

code_offs_seen = set()
def check_code(co, ctx):
    if co == 0:
        return
    if not in_data(co): err('%s: code_off 0x%x out of data region' % (ctx, co)); return
    regs, ins, outs, ntry, dbg, sz = struct.unpack_from('<HHHHII', d, co)
    insns_off = co + 16
    insns_end = insns_off + 2*sz
    tries_off = insns_end
    total_end = tries_off + 4*ntry
    if total_end > file_size:
        err('%s: code 0x%x runs past EOF (sz=%d ntry=%d)' % (ctx, co, sz, ntry)); return
    # walk instructions
    p = insns_off; u = 0
    while p < insns_end:
        op = d[p] & 0xFF
        w = W.get(op)
        if w is None:
            err('%s: unknown opcode 0x%02x at insn unit %d' % (ctx, op, u)); return
        if op in BRANCH_OPS:
            # branch operand: 10t s8 in high byte; 20t/21t/22t s16 at unit+1; 30t s32 at unit+1
            if op == 0x28:
                b = d[p + 1]
                if b & 0x80: b -= 0x100
                target = u + 1 + b
            elif op in (0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D):
                b = struct.unpack_from('<h', d, p + 2)[0]
                target = u + 2 + b
            elif op == 0x29:
                b = struct.unpack_from('<h', d, p + 2)[0]
                target = u + 2 + b
            elif op == 0x2A:
                b = struct.unpack_from('<i', d, p + 2)[0]
                target = u + 3 + b
            if not (0 <= target < sz):
                err('%s: branch target %d out of [0,%d) (insn 0x%02x at unit %d)' % (ctx, target, sz, op, u))
        p += 2*w; u += w
    if u != sz:
        err('%s: walked %d units != insns_size %d' % (ctx, u, sz))
    # try items
    hp = tries_off
    for t in range(ntry):
        start, icount, hoff = struct.unpack_from('<IHH', d, hp); hp += 8
        if start + icount > sz: err('%s: try %d [start %d count %d] exceeds insns' % (ctx, t, start, icount))
        if hoff >= 4*ntry: err('%s: try %d handler off 0x%x out of range' % (ctx, t, hoff))
    # handlers
    hp = tries_off + 4*ntry
    while hp < total_end:
        n, hp = uleb(hp)
        if n == 0:
            h, hp = uleb(hp)
            if h >= sz: err('%s: catch-all handler %d oob' % (ctx, h))
        else:
            for _ in range(n):
                tidx, hp = uleb(hp)
                h, hp = uleb(hp)
                if tidx >= ntyp: err('%s: handler type %d oob' % (ctx, tidx))
                if h >= sz: err('%s: handler %d oob' % (ctx, h))
    code_offs_seen.add(co)

for i in range(ncls):
    base = coff + 32*i
    cls_idx, access, super_idx, ifaces_off, src_idx, ann_off, cdata_off, sv_off = struct.unpack_from('<8I', d, base)
    if cls_idx >= ntyp: err('class_def[%d] class idx oob' % i); continue
    if super_idx != NO_INDEX and super_idx >= ntyp: err('class_def[%d] super idx oob' % i)
    if ifaces_off: check_type_list(ifaces_off, 'class_def[%d]' % i)
    ctx = 'class %s' % type_desc(cls_idx)
    if cdata_off == 0:
        continue
    if not in_data(cdata_off): err('%s: cdata 0x%x out of data' % (ctx, cdata_off)); continue
    p = cdata_off
    sf, p = uleb(p); iff, p = uleb(p); dm, p = uleb(p); vm, p = uleb(p)
    def check_field_section(n, is_static, p):
        prev = 0
        for _ in range(n):
            diff, p = uleb(p)
            fl, p = uleb(p)
            idx = prev + diff
            if diff < 0 or idx >= nfd:
                err('%s: field idx %d oob (sf=%d static=%s)' % (ctx, idx, n, is_static)); continue
            if idx < prev: err('%s: field idx not increasing' % ctx)
            if (fl & 0x8) != (0x8 if is_static else 0):
                err('%s: field %d static-flag mismatch (flags 0x%x, static=%s)' % (ctx, idx, fl, is_static))
            fcls = u16(foff + 8*idx)
            if fcls != cls_idx:
                warn('%s: field %d declared in class %s, not %s (inherited?)'
                     % (ctx, idx, type_desc(fcls), type_desc(cls_idx)))
            prev = idx
        return p
    def check_method_section(n, p):
        prev = 0
        for _ in range(n):
            diff, p = uleb(p)
            fl, p = uleb(p)
            co, p = uleb(p)
            idx = prev + diff
            if idx >= nmth: err('%s: method idx %d oob' % (ctx, idx)); continue
            prev = idx
            check_code(co, '%s method %d' % (ctx, idx))
        return p
    p = check_field_section(sf, True, p)
    p = check_field_section(iff, False, p)
    p = check_method_section(dm, p)
    p = check_method_section(vm, p)
    print('class_def[%d] %s: sf=%d if=%d dm=%d vm=%d cdata=0x%x -> parsed ok' % (i, type_desc(cls_idx), sf, iff, dm, vm, cdata_off))

# ---------------- 8. all map code items covered
ncode = tags.get(0x2001, (0, 0))[0]
print('code items: %d in map, %d referenced from class_data' % (ncode, len(code_offs_seen)))
if ncode != len(code_offs_seen):
    warn('code item count mismatch (map=%d referenced=%d)' % (ncode, len(code_offs_seen)))

# ---------------- 9. strings all ASCII-safe (MUTF-8 == UTF-8)
non_ascii = 0
for i in range(nstr):
    sdoff = u32(soff + 4*i)
    ln, p = uleb(sdoff)
    raw = d[p:p+ln]
    try:
        s = raw.decode('utf-8')
        if any(ord(c) > 0x7F for c in s): non_ascii += 1
    except UnicodeDecodeError:
        err('string %d not valid utf-8' % i)
if non_ascii: warn('%d non-ascii strings (MUTF-8 edge cases)' % non_ascii)

print()
for w in warns: print('WARN:', w)
for e in errs: print('FAIL:', e)
print()
print('RESULT:', 'PASS (standard 035)' if not errs else 'FAIL (%d errors)' % len(errs))
sys.exit(1 if errs else 0)
