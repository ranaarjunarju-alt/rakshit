#!/usr/bin/env python3
"""Full rigorous verification + disassembly of classes2.dex (logger dex).

Dialect opcode/size table = the one validated by walking stock classes.dex
(11123/12908 coherent code items): numbering is shifted vs standard ART
(const/4=0x12, const/16=0x13, const-string=0x1a, const-class=0x1c,
array-length=0x21, goto=0x28, if-eq=0x32..if-lez=0x3d, aconst-null=0x3e,
aget=0x44.., iget=0x52.., sget=0x60.., invoke=0x6e..0x72, range=0x74..0x78).
Branch convention A: target = insn unit start + off.
"""
import struct, zlib, hashlib, sys

B = open(sys.argv[1] if len(sys.argv) > 1 else 'work/repack/classes2.dex', 'rb').read()
errs = []
def err(m): errs.append(m); print('  !!', m)

# ---------------- header
if B[:8] != b'dex\n037\x00': err('magic')
file_size = struct.unpack_from('<I', B, 0x20)[0]
header_size, endian = struct.unpack_from('<II', B, 0x24)
map_off = struct.unpack_from('<I', B, 0x34)[0]
str_size, str_off = struct.unpack_from('<II', B, 0x38)
typ_size, typ_off = struct.unpack_from('<II', B, 0x40)
pro_size, pro_off = struct.unpack_from('<II', B, 0x48)
fld_size, fld_off = struct.unpack_from('<II', B, 0x50)
mtd_size, mtd_off = struct.unpack_from('<II', B, 0x58)
cls_size, cls_off = struct.unpack_from('<II', B, 0x60)
data_size, data_off = struct.unpack_from('<II', B, 0x68)
print(f'file={len(B)} header: fs={file_size:#x} map={map_off:#x} '
      f'str={str_size}@{str_off:#x} typ={typ_size}@{typ_off:#x} pro={pro_size}@{pro_off:#x} '
      f'fld={fld_size}@{fld_off:#x} mtd={mtd_size}@{mtd_off:#x} cls={cls_size}@{cls_off:#x} '
      f'data={data_size}@{data_off:#x}')
if file_size != len(B): err('file_size mismatch')
if header_size != 0x70 or endian != 0x12345678: err('header_size/endian')

# chksum & signature
chk = struct.unpack_from('<I', B, 0x08)[0]
calc = zlib.adler32(B[12:]) & 0xFFFFFFFF
if chk != calc: err(f'chksum {chk:#x} != {calc:#x}')
sig = B[0x0C:0x20]
h = hashlib.sha1(B[0x20:]).digest()
if sig != h: err('signature')

# ---------------- tables
str_ids = [struct.unpack_from('<I', B, str_off + 4*i)[0] for i in range(str_size)]
typ_ids = [struct.unpack_from('<I', B, typ_off + 4*i)[0] for i in range(typ_size)]
def str_at(i):
    p = str_ids[i]
    ln = 0; s = 0; sh = 0
    while True:
        b = B[p + s]; s += 1; ln |= (b & 0x7F) << sh
        if not (b & 0x80): break
        sh += 7
    raw = B[p + s: p + s + ln]
    if B[p + s + ln] != 0: err(f'str {i} not NUL-terminated')
    return raw.decode('utf-8', 'replace')

def typ_at(i): return str_at(typ_ids[i])
protos = []
for i in range(pro_size):
    o = pro_off + 12*i
    sidx, ret, par = struct.unpack_from('<III', B, o)
    protos.append((sidx, ret, par))
fields = []
for i in range(fld_size):
    o = fld_off + 8*i
    cls, pr, nm = struct.unpack_from('<HHI', B, o)
    fields.append((cls, pr, nm))
methods = []
for i in range(mtd_size):
    o = mtd_off + 8*i
    cls, pr, nm = struct.unpack_from('<HHI', B, o)
    methods.append((cls, pr, nm))
for (cls, pr, nm) in fields + methods:
    if cls >= typ_size: err(f'bad type idx {cls}')
    if pr >= pro_size: err(f'bad proto idx {pr}')
    if nm >= str_size: err(f'bad str idx {nm}')

classes = []
for i in range(cls_size):
    o = cls_off + 32*i
    (cls, acc, sup, if_off, src, x, clsdata_off, sv) = struct.unpack_from('<IIIIIIII', B, o)
    classes.append((acc, cls, sup, if_off, src, x, clsdata_off, sv))

def uleb_at(p, data=B):
    r = 0; s = 0
    while True:
        b = data[p]; p += 1; r |= (b & 0x7F) << s
        if not (b & 0x80): return r, p
        s += 7

# ---------------- dialect insn sizes (stock-walk validated)
SZ = {}
def S(ops, n):
    for o in ops: SZ[o] = n
S([0x00, 0x01, 0x04, 0x07, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x1d, 0x1e, 0x21, 0x27, 0x28, 0x3e], 1)
S([0x02, 0x03, 0x05, 0x06, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d], 2)
S([0x13, 0x15, 0x16, 0x19, 0x1a, 0x1c, 0x1f, 0x20, 0x22, 0x23, 0x24, 0x25, 0x26], 2)
S(list(range(0x29, 0x3e)), 2)
S([0x3f, 0x40, 0x41, 0x42, 0x43, 0x4f], 2)
S(list(range(0x44, 0x6e)), 2)
S(list(range(0x6e, 0x79)), 3)
S(list(range(0x7b, 0xd0)), 2)
S([0xd0], 3)
S(list(range(0xd1, 0xe3)), 2)
S(list(range(0xe3, 0xf8)), 2)
S([0xfc, 0xfd], 2)
S([0x14, 0x17, 0x18, 0x1b], 3)
S([0xf8, 0xf9, 0xfa, 0xfb], 3)

BR11 = set(range(0x32, 0x3e))      # if-* (22t with lit8): A, B + offset
BR10 = set(range(0x29, 0x2d))      # goto/16, goto/32, packed, sparse: offset only
INVK = set(range(0x6e, 0x73))
INVKR = set(range(0x74, 0x79))

n_methods_checked = 0
def verify_code(co, label, quiet=False):
    global n_methods_checked
    regs, ins, outs, ntry, dbg, insns = struct.unpack_from('<HHHHII', B, co)
    if ntry != 0: err(f'{label}: ntry={ntry} (must be 0)')
    if not (0 < regs <= 255 and 0 <= ins <= regs and 0 <= outs <= regs - ins):
        err(f'{label}: regs/ins/outs bad regs={regs} ins={ins} outs={outs}')
    if dbg == 0: err(f'{label}: dbg=0 (stock dialect never uses 0)')
    units = struct.unpack_from(f'<{insns}H', B, co + 16)
    starts = set()
    i = 0
    while i < insns:
        u = units[i]; op = u & 0xFF
        sz = SZ.get(op)
        if sz is None:
            err(f'{label}: unknown opcode {op:#x} at u{i}')
            return
        starts.add(i)
        if i + sz > insns:
            err(f'{label}: insn at u{i} overruns ({sz}u)')
            return
        A = (u >> 8) & 0xF; Bn = (u >> 12) & 0xF
        if op == 0x12:                                  # const/4 A/2t (1u)
            if A >= regs: err(f'{label}: const4 v{A} >= regs at u{i}')
            if (u >> 12) & 0xF >= 16: err(f'{label}: const4 lit8 >15 at u{i}')
        elif op in (0x13, 0x15, 0x16, 0x19):            # 21s
            if (u >> 8) & 0x3F >= regs: err(f'{label}: 21s v{(u>>8)&0x3F} >= regs at u{i}')
        elif op in (0x1a, 0x1c, 0x1f):                  # 21c idx
            if A >= regs: err(f'{label}: 21c v{A} >= regs at u{i}')
            idx = units[i+1]
            lim = str_size if op == 0x1a else typ_size
            if idx >= lim: err(f'{label}: 21c idx {idx} oob at u{i}')
        elif op in (0x20, 0x22, 0x23):                  # 22c type
            if A >= regs or Bn >= regs: err(f'{label}: 22c reg oob at u{i}')
            if units[i+1] >= typ_size: err(f'{label}: 22c type {units[i+1]} oob at u{i}')
        elif op == 0x21:                                 # array-length: vA=len, vB=array
            if A >= regs: err(f'{label}: alen res v{A} >= regs at u{i}')
            if Bn >= regs: err(f'{label}: alen arr v{Bn} >= regs at u{i}')
        elif op in BR11:
            if A >= regs: err(f'{label}: 11n res v{A} >= regs at u{i}')
            if Bn >= regs: err(f'{label}: 11n arr v{Bn} >= regs at u{i}')
            off = units[i+1]; off -= 0x10000 if off & 0x8000 else 0
            t = i + off
            if not (0 <= t < insns): err(f'{label}: br at u{i} off {off} -> {t} oob')
        elif op in BR10:                                 # 10t / 2t branches: no regs
            off = units[i+1]; off -= 0x10000 if off & 0x8000 else 0
            t = i + off
            if not (0 <= t < insns): err(f'{label}: br at u{i} off {off} -> {t} oob')
        elif op == 0x28:                                 # goto/8 (1u)
            o = (u >> 8) & 0xFF; o -= 0x100 if o & 0x80 else 0
            t = i + o
            if not (0 <= t < insns): err(f'{label}: goto/8 at u{i} -> {t} oob')
        elif 0x44 <= op <= 0x51:                          # 23x / aget-aput
            if A >= regs or Bn >= regs: err(f'{label}: 23x reg oob at u{i}')
        elif 0x52 <= op <= 0x5F:                          # 22c field
            if A >= regs or Bn >= regs: err(f'{label}: 22c reg oob at u{i}')
            if units[i+1] >= fld_size: err(f'{label}: 22c field {units[i+1]} oob at u{i}')
        elif 0x60 <= op <= 0x6D:                          # 21c field
            if A >= regs: err(f'{label}: 21c v{A} >= regs at u{i}')
            if units[i+1] >= fld_size: err(f'{label}: 21c field {units[i+1]} oob at u{i}')
        elif op in INVK:                                  # 35C
            cnt = (u >> 12) & 0xF
            if cnt > 5: err(f'{label}: invoke cnt {cnt} at u{i}')
            if units[i+1] >= mtd_size: err(f'{label}: invoke m{units[i+1]} oob at u{i}')
            r = units[i+2]
            for j in range(5):
                if ((r >> (4*j)) & 0xF) >= regs: err(f'{label}: 35C v{r>>12 & 0xF} reg oob at u{i}')
        elif op in INVKR:                                 # 3rc
            cnt = (u >> 12) & 0xF
            if cnt > 5: err(f'{label}: invoke-range cnt {cnt} at u{i}')
            if units[i+1] >= mtd_size: err(f'{label}: invoke-range m{units[i+1]} oob at u{i}')
            r = (u >> 8) & 0xF
            if r >= regs or r + cnt > regs: err(f'{label}: 3rc range oob at u{i}')
        elif 0x7B <= op <= 0xE2:                          # arith 23x/22x
            if A >= regs or Bn >= regs: err(f'{label}: arith reg oob at u{i}')
        elif 0xF8 <= op <= 0xFB:
            if A >= regs or Bn >= regs: err(f'{label}: long arith reg oob at u{i}')
        if not quiet:
            extra = ''
            if op == 0x12: extra = f' v{A}={(u>>12)&0xF}'
            elif op in (0x13, 0x15, 0x16, 0x19): extra = f' v{(u>>8)&0x3F}={units[i+1]:#x}'
            elif op in (0x1a, 0x1c, 0x1f): extra = f' v{A} idx={units[i+1]}'
            elif op in (0x20, 0x22, 0x23): extra = f' v{A}=({Bn},t{units[i+1]})'
            elif op == 0x21: extra = f' v{A}=len(v{Bn})'
            elif op in (0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d): extra = f' v{(u>>8)&0xFF}'
            elif op in (0x02, 0x03): extra = f' v{(u>>8)&0xFF}=v{units[i+1]}'
            elif op == 0x31: extra = f' v{(u>>8)&0xFF} cmp v{units[i+1]}'
            elif op in (0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51):
                extra = f' v{(u>>8)&0xFF}[v{units[i+1]&0xFF}]=v{(units[i+1]>>8)&0xFF}'
            elif op in BR11:
                off = units[i+1]; off -= 0x10000 if off & 0x8000 else 0
                extra = f' v{A} vs v{Bn} -> u{i+off}'
            elif op in BR10:
                off = units[i+1]; off -= 0x10000 if off & 0x8000 else 0
                extra = f' -> u{i+off}'
            elif op == 0x28:
                o = (u >> 8) & 0xFF; o -= 0x100 if o & 0x80 else 0
                extra = f' -> u{i+o}'
            elif 0x52 <= op <= 0x5F: extra = f' v{A}=v{Bn}.{units[i+1]}'
            elif 0x60 <= op <= 0x6D: extra = f' v{A}=F{units[i+1]}'
            elif op in INVK:
                cnt = (u >> 12) & 0xF
                rn = units[i+2]
                rs = ', '.join(str((rn >> (4*j)) & 0xF) for j in range(cnt))
                extra = f' m{units[i+1]}({rs})' if rs else f' m{units[i+1]}()'
            elif op in INVKR:
                cnt = (u >> 12) & 0xF
                st = (u >> 8) & 0xF
                extra = f' m{units[i+1]}(v{st}..v{st+cnt-1})'
            elif op in (0x01, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a):
                extra = f' v{u>>8}'
            elif op in (0x02, 0x03):
                extra = f' v{u>>8&0xF}=v{units[i+1]}'
            if op != 0x00:
                print(f'    u{i:3d} {op:02x}{extra}')
        i += sz
    # post: all branch targets must be instruction starts
    i = 0
    while i < insns:
        u = units[i]; op = u & 0xFF
        sz = SZ.get(op, 1)
        if op in BR11 | BR10:
            off = units[i+1]; off -= 0x10000 if off & 0x8000 else 0
            t = i + off
            if 0 <= t < insns and t not in starts:
                err(f'{label}: br at u{i} -> u{t} NOT insn start')
        elif op == 0x28:
            o = (u >> 8) & 0xFF; o -= 0x100 if o & 0x80 else 0
            t = i + o
            if 0 <= t < insns and t not in starts:
                err(f'{label}: goto/8 at u{i} -> u{t} NOT insn start')
        i += sz
    # debug item sanity
    if dbg != 0:
        seq, q = uleb_at(dbg)
        if B[q] != 0x00: err(f'{label}: dbg{dbg:#x} no DW_END after seq={seq}')
        else:
            ni, q = uleb_at(q)
            di, q = uleb_at(q)
            si, q = uleb_at(q)
            if ni >= str_size or di >= str_size:
                err(f'{label}: dbg idx oob name={ni} desc={di}')
    n_methods_checked += 1

# ---------------- walk classes via class_data (counts-first, continuous chain)
for ci, (acc, cls, sup, if_off, src, x, cd, sv) in enumerate(classes):
    name = typ_at(cls)
    print(f'class {ci}: {name}  acc={acc:#x} sup={typ_at(sup) if sup else None} clsdata={cd:#x}')
    if cd == 0:
        print('  (no class data)')
        continue
    p = cd
    nstatic, p = uleb_at(p)
    ninst, p = uleb_at(p)
    ndm, p = uleb_at(p)
    nvm, p = uleb_at(p)
    print(f'  statics={nstatic} inst={ninst} directs={ndm} virtuals={nvm}')
    prev = 0
    for sec, cnt in (('static', nstatic), ('inst', ninst)):
        for _ in range(cnt):
            d, p = uleb_at(p); prev += d
            a, p = uleb_at(p)
    n_with_code = 0
    for sec, cnt in (('direct', ndm), ('virtual', nvm)):
        for k in range(cnt):
            d, p = uleb_at(p); gi = prev + d; prev = gi
            a, p = uleb_at(p)
            co, p = uleb_at(p)
            if gi >= mtd_size:
                err(f'class {name}: method gi {gi} out of range'); continue
            mcls, mpr, mnm = methods[gi]
            mname = f'{typ_at(mcls)}.{str_at(mnm)}'
            if co == 0:
                print(f'  m{gi} [{sec}] {mname}  (no code)')
                continue
            if not (data_off <= co < data_off + data_size):
                err(f'class {name}: code_off {co:#x} outside data region')
            print(f'  m{gi} [{sec}] {mname}  code={co:#x}')
            verify_code(co, mname)
            n_with_code += 1

print(f'\nmethods verified: {n_methods_checked}')
print('\n' + ('ALL CLEAN' if not errs else f'{len(errs)} ERRORS'))
sys.exit(1 if errs else 0)
