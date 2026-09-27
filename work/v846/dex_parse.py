#!/usr/bin/env python3
"""Pure-Python DEX parser v2: full inventory + per-method bytecode reference extraction."""
import struct, json, sys, re
from collections import defaultdict, Counter

def uleb128(d, p):
    v = 0; sh = 0
    while True:
        b = d[p]; p += 1
        v |= (b & 0x7f) << sh
        if not (b & 0x80): return v, p
        sh += 7

def mutf8(d, p):
    out = bytearray()
    while d[p] != 0:
        b1 = d[p]
        if b1 < 0x80: out.append(b1); p += 1
        elif b1 & 0xE0 == 0xC0:
            out.append(((b1 & 0x1F) << 6) | (d[p+1] & 0x3F)); p += 2
        elif b1 & 0xF0 == 0xE0:
            out.append(((b1 & 0x0F) << 12) | ((d[p+1] & 0x3F) << 6) | (d[p+2] & 0x3F)); p += 3
        else: out.append(b1); p += 1
    return out.decode('utf-8', 'replace'), p + 1

def parse_dex(path):
    d = open(path, 'rb').read()
    (chk, size, fsize, hdr, endian, lk_sz, lk_off, map_off,
     n_str, off_str, n_type, off_type, n_proto, off_proto, n_field, off_field,
     n_meth, off_meth, n_class, off_class, data_sz, data_off) = struct.unpack_from('<12I', d, 32)
    strings = []
    for i in range(n_str):
        (o,) = struct.unpack_from('<I', d, off_str + 4*i)
        _, p = uleb128(d, o)
        s, _ = mutf8(d, p)
        strings.append(s)
    types = [strings[struct.unpack_from('<I', d, off_type + 4*i)[0]] for i in range(n_type)]
    protos = []
    for i in range(n_proto):
        o = off_proto + 12*i
        shorty, rt, po = struct.unpack_from('<HHI', d, o)
        if po:
            (cnt,) = struct.unpack_from('<I', d, po)
            pl = [types[struct.unpack_from('<H', d, po + 4 + 2*j)[0]] for j in range(cnt)]
        else:
            pl = []
        protos.append((strings[shorty] if shorty else '', strings[rt] if rt else 'V', pl))
    fields = []
    for i in range(n_field):
        c, t, nm = struct.unpack_from('<HHI', d, off_field + 8*i)
        fields.append((c, t, nm))
    methods = []
    for i in range(n_meth):
        c, p, nm = struct.unpack_from('<HHI', d, off_meth + 8*i)
        methods.append((c, p, nm))
    classes = []
    for i in range(n_class):
        o = off_class + 32*i
        cidx, flags, sup, ifo, cdo, svo, vmo = struct.unpack_from('<IIIIIII', d, o)
        cname = types[cidx]
        supc = types[sup] if sup != 0xFFFFFFFF else None
        ifaces = []
        if ifo:
            (nn,) = struct.unpack_from('<I', d, ifo)
            ifaces = [types[struct.unpack_from('<H', d, ifo + 4 + 2*j)[0]] for j in range(nn)]
        flds = []; mths = []
        if cdo:
            p = cdo
            nsf, nif, ndm, nvm = struct.unpack_from('<HHHH', d, p)
            p += 8
            def idxlist(n):
                nonlocal p
                out = []
                prev = 0
                for _ in range(n):
                    dd, p2 = uleb128(d, p)
                    prev += dd; p = p2
                    out.append(prev)
                return out
            sf = idxlist(nsf)
            for _ in range(nsf): p += 1
            ifi = idxlist(nif)
            for _ in range(nif): p += 1
            for fi in sf:
                c, t, nm = fields[fi]
                flds.append({'name': strings[nm], 'type': types[t], 'static': True})
            for fi in ifi:
                c, t, nm = fields[fi]
                flds.append({'name': strings[nm], 'type': types[t], 'static': False})
            dm = idxlist(ndm)
            dmf = []
            for _ in range(ndm):
                af, p2 = uleb128(d, p); p = p2; dmf.append(af)
            vm = idxlist(nvm)
            vmf = []
            for _ in range(nvm):
                af, p2 = uleb128(d, p); p = p2; vmf.append(af)
            def addm(mi, fl):
                c, pr, nm = methods[mi]
                mths.append({'name': strings[nm], 'proto': pr, 'flags': fl,
                             'native': bool(fl & 0x400), 'static': bool(fl & 8),
                             'final': bool(fl & 0x0010), 'abstract': bool(fl & 0x0400),
                             'code_off': 0})
            for mi, fl in zip(dm, dmf): addm(mi, fl)
            for mi, fl in zip(vm, vmf): addm(mi, fl)
        classes.append({'name': cname, 'super': supc, 'ifaces': ifaces, 'flags': flags,
                        'abstract': bool(flags & 0x400), 'fields': flds, 'methods': mths,
                        'class_idx': cidx})
    # code offsets: re-walk method_id list order? code_off lives in class_data after flags.
    # Redo minimal: for each class_data, method entries are (off,flags,code_off?) — actually
    # code_off follows the access_flags uleb for each method. Capture now:
    for i in range(n_class):
        o = off_class + 32*i
        cidx, flags, sup, ifo, cdo, svo, vmo = struct.unpack_from('<IIIIIII', d, o)
        if not cdo: continue
        p = cdo
        nsf, nif, ndm, nvm = struct.unpack_from('<HHHH', d, p); p += 8
        for _ in range(nsf + nif):
            _, p = uleb128(d, p); p += 1
        def idxlist(n):
            nonlocal p
            out = []; prev = 0
            for _ in range(n):
                dd, p2 = uleb128(d, p); prev += dd; p = p2; out.append(prev)
            return out
        dm = idxlist(ndm)
        dmf = []
        dco = []
        for _ in range(ndm):
            af, p2 = uleb128(d, p); p = p2; dmf.append(af)
            (co,) = struct.unpack_from('<I', d, p); p += 4; dco.append(co)
        vm = idxlist(nvm)
        vmf = []
        vco = []
        for _ in range(nvm):
            af, p2 = uleb128(d, p); p = p2; vmf.append(af)
            (co,) = struct.unpack_from('<I', d, p); p += 4; vco.append(co)
        cl = classes[i]
        k = 0
        for co in dco:
            cl['methods'][k]['code_off'] = co; k += 1
        for co in vco:
            cl['methods'][k]['code_off'] = co; k += 1
    return d, strings, types, protos, fields, methods, classes

def proto_sig(protos, pi):
    shorty, ret, pl = protos[pi]
    if pi is None: return '()'
    return '(' + ','.join(x.replace('L', '').replace(';', '').replace('/', '.') for x in pl) + ')L' + ret.replace(';', '').replace('/', '.') + ';' if ret.startswith('L') else '(' + ','.join(pl) + ')' + ret

def analyze_code(d, strings, types, protos, methods, code_off, max_insns=4000):
    """Extract refs from a method's code item. Returns dict of refs."""
    refs = {'strings': [], 'calls': [], 'new': [], 'fields': [], 'types': [], 'consts': []}
    if not code_off: return refs
    (regs, ins, outs, tries, dbg, insns_sz) = struct.unpack_from('<HHhhII', d, code_off)
    n16 = insns_sz
    ip = code_off + 24
    count = 0
    while count < n16:
        w = struct.unpack_from('<H', d, ip)[0]
        op = w & 0xFF
        if op == 0x1A:  # const-string 31c
            refs['strings'].append(w >> 8)
            ip += 4; count += 2
        elif op == 0x2A:  # const-string/jumbo 31t
            (idx,) = struct.unpack_from('<I', d, ip + 2)
            refs['strings'].append(idx)
            ip += 8; count += 4
        elif 0x000 <= op <= 0x008:  # invokes
            G = (w >> 24) & 0xF
            (mc,) = struct.unpack_from('<H', d, ip + 2)
            refs['calls'].append((mc, G))
            if G == 0 or G == 0x10:
                (cnt2,) = struct.unpack_from('<H', d, ip + 4)
                ip += 4 + cnt2*2; count += 2 + cnt2
            else:
                ip += 12; count += 6
        elif op == 0x20:  # new-instance 22s
            refs['new'].append(w >> 8)
            ip += 6; count += 3
        elif 0x1B <= op <= 0x25 or 0x28 <= op <= 0x2D or 0x5B <= op <= 0x6D:
            refs['fields'].append((op, w >> 8))
            ip += 6; count += 3
        elif op == 0x1F or op == 0x21:  # check-cast / instance-of
            refs['types'].append(w >> 8)
            ip += 6; count += 3
        elif op == 0x19:  # const-object 31c
            refs['types'].append(w >> 8)
            ip += 4; count += 2
        elif op == 0x0A:  # const/4
            refs['consts'].append((w >> 8) & 0xF if ((w >> 8) & 0xF) < 8 else ((w >> 8) & 0xF) - 16)
            ip += 4; count += 2
        elif op == 0x10:  # const/16
            (v,) = struct.unpack_from('<h', d, ip + 2)
            refs['consts'].append(v)
            ip += 6; count += 3
        elif op == 0x11:  # const 32i
            (v,) = struct.unpack_from('<i', d, ip + 2)
            refs['consts'].append(v)
            ip += 8; count += 4
        elif op in (0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18):
            if op == 0x12:
                (v,) = struct.unpack_from('<h', d, ip + 2)
                refs['consts'].append(v << 16)
                ip += 6; count += 3
            elif op == 0x13:
                (v,) = struct.unpack_from('<h', d, ip + 2)
                refs['consts'].append(v << 48)
                ip += 6; count += 3
            else:
                (v,) = struct.unpack_from('<q', d, ip + 2)
                refs['consts'].append(v)
                ip += 8; count += 4
        elif op == 0x3B:  # fill-array-data 31t
            (off,) = struct.unpack_from('<I', d, ip + 2)
            p = off
            (sz,) = struct.unpack_from('<I', d, p)
            (tc,) = struct.unpack_from('<I', d, p + 8)
            refs['types'].append(tc)
            # skip payload (align to 4)
            payload = 12 + sz * (4 if tc in (0x0017, 0x0018, 0x0019, 0x001A, 0x001C) else 2) + 4
            # type: 4-byte for int/long/float/double/char? (char=2). just skip conservatively
            ip += 8; count += 4
        else:
            # default: skip by format heuristic — use known format table fallback:
            # format by opcode class (21c/22c/22s/23x/31i/32i/32x/35c handled/3rc/51l/52l)
            if op in (0x6E, 0x6F):  # goto/16, goto/32
                ip += 6; count += 3
            elif op in (0x0C, 0x0D, 0x0E):  # packed-switch/sparse/goto
                ip += 8; count += 4
            elif 0x26 <= op <= 0x34 or 0x3A <= op <= 0x4A or 0x50 <= op <= 0x5A or 0x90 <= op <= 0x9A:
                # 21c/22c/23x family (move, const/4 handled, cmp, add, mul, div, and, or, xor, shl, shr, neg, not, arrays load/store, monitor)
                ip += 6; count += 3
            elif op in (0x35, 0x36, 0x37, 0x38, 0x39, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5B):
                ip += 6; count += 3
            elif 0x60 <= op <= 0x65:
                ip += 6; count += 3
            elif op in (0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D):
                ip += 6; count += 3
            elif 0x70 <= op <= 0x7A or op in (0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F, 0x9B):
                ip += 6; count += 3
            elif op in (0x9C, 0x9D, 0x9E, 0x9F):
                ip += 8; count += 4
            elif op in (0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA):
                ip += 8; count += 4
            elif op in (0xC0, 0xC1):  # 51l/52l
                ip += 8; count += 4
            elif op == 0x00:  # nop
                ip += 2; count += 1
            else:
                # unknown: assume 2-wide unless looks 31c (A register only opcodes end 0x0-0x7 of 31c class)
                ip += 4; count += 2
        if count >= max_insns: break
    return refs

if __name__ == '__main__':
    path = sys.argv[1] if len(sys.argv) > 1 else 'apkx/classes.dex'
    d, strings, types, protos, fields, methods, classes = parse_dex(path)
    print('strings:', len(strings), 'types:', len(types), 'methods:', len(methods), 'classes:', len(classes))
