#!/usr/bin/env python3
"""
dex_typecheck.py — register-type flow checker for the hand-assembled dex.

Checks (ART register-verifier essentials, dialect-aware):
  * invoke: register count vs proto param count (+1 for non-static)
  * invoke: arg register kind matches param type
            (J/D -> wide, L...;/[...] -> object, else int)
  * invoke: following move_result* matches return type
  * const4/16/const -> int ; constw* -> wide ; const_string/new_instance/
    const_class/cstr -> object
  * wide sources (cmp-long, aput/aput... J-params, sb append(J), long ops)
    must read registers last written as wide
  * object params must read object registers; int params int registers
"""
import struct, sys, logging
logging.disable(logging.CRITICAL)

U1 = {0x00,0x01,0x02,0x03,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,0x11,
      0x12,0x1d,0x1e,0x21,0x27,0x28,0x7e,0xbb,0xbc}
U2 = {0x13,0x16,0x1a,0x1f,0x20,0x22,0x23,0x31,0x34,0x35,0x38,0x39,
      0x3b,0x46,0x4d,0x52,0x54,0x59,0x5b,0x60,0x61,0x62,0x63,0x67,
      0x68,0x69,0x81,0x9c,0xd8}
U3 = {0x14,0x17,0x18}
INV35C = {0x6e,0x6f,0x70,0x71,0x72}
INV3RC = {0x74,0x76,0x77}
STATIC_INV = {0x70, 0x71}  # static / interface? -> interface(0x72) is NON-static; static = 0x70
# careful: 0x70 invoke-static, 0x71 invoke-direct, 0x72 invoke-interface, 0x6e invoke-virtual, 0x6f invoke-super
STATIC_OPS = {0x71}  # dialect: 0x70=invoke-direct, 0x71=invoke-static (reversed vs standard dex)
# wide-source consuming ops (besides invoke params):
# 0x31 cmp-long (A dest, B,C wide src), 0x45 aput-wide?, 0x4c aget-wide?,
# 0xbb/0xbc long/2addr (A dest-wide, B src-wide), 0x7e neg-long (A dest, B src-wide),
# 0x81 int-to-long (A dest-wide, B src-int), 0x9c sub-long (A dest, B src-wide)

INT_KIND = 'int'
WIDE_KIND = 'wide'
OBJ_KIND = 'object'
UNKNOWN = None

def kind_of_type(t):
    if t in ('J', 'D'):
        return WIDE_KIND
    if t[0] in 'L[':
        return OBJ_KIND
    return INT_KIND  # I Z B S C V

def insn_size(op, u0):
    if op in U1: return 1
    if op in U2: return 2
    if op in U3: return 3
    if op in INV35C:
        cnt = (u0 >> 12) & 0xF
        return 3 + (1 if cnt == 5 else 0)
    if op in INV3RC:
        return 3
    return None

def main(path):
    dex = open(path, 'rb').read()
    from androguard.core.dex import DEX
    d = DEX(dex)
    h = d.get_header_item()

    # ---- parse tables from raw bytes
    def u32(off): return struct.unpack_from('<I', dex, off)[0]
    def u16(off): return struct.unpack_from('<H', dex, off)[0]

    # strings
    nstr = h.string_ids_size
    sids = h.string_ids_off
    strings = []
    for i in range(nstr):
        sdo = u32(sids + 4 * i)
        # uleb length
        p = sdo
        ln = s = 0
        while True:
            x = dex[p]; p += 1
            ln |= (x & 0x7F) << s
            if not x & 0x80: break
            s += 7
        strings.append(dex[p:p + ln].decode('utf-8', 'replace'))

    ntype = h.type_ids_size
    tids = h.type_ids_off
    types = [strings[u32(tids + 4 * i)] for i in range(ntype)]

    nproto = h.proto_ids_size
    pids = h.proto_ids_off
    protos = []
    for i in range(nproto):
        off = pids + 12 * i
        shorty_idx = u32(off)
        ret = u32(off + 4)
        params_off = u32(off + 8)
        params = []
        if params_off:
            n = u32(params_off)  # dialect: u32 size in type_list
            params = [types[u16(params_off + 4 + 2 * k)] for k in range(n)]
        protos.append((types[ret], params))

    nmdl = h.method_ids_size
    mids = h.method_ids_off
    methods = []
    for i in range(nmdl):
        off = mids + 8 * i
        cls = u16(off)
        proto = u16(off + 2)
        name = u32(off + 4)
        methods.append((types[cls], strings[name], protos[proto]))

    nfdl = h.field_ids_size
    fids = h.field_ids_off
    fields = []
    for i in range(nfdl):
        off = fids + 8 * i
        cls = u16(off)
        typ = u16(off + 2)
        name = u32(off + 4)
        fields.append((types[cls], types[typ], strings[name]))

    issues = 0
    for c in d.get_classes():
        for m in c.get_methods():
            code = m.get_code()
            if code is None:
                continue
            tag = f"{c.get_name().rstrip(';')}.{m.get_name()}"
            off = code.get_off()
            regs = code.get_registers_size()
            ins = code.get_ins_size()
            insns_size = code.get_insns_size()
            insns = dex[off + 16: off + 16 + insns_size * 2]
            # register kinds: params v0..v(ins-1) unknown; locals unknown
            kind = [UNKNOWN] * regs
            p = 0
            def bad(msg):
                nonlocal issues
                issues += 1
                print(f"[{tag}] u{p}: {msg}")
            while p < insns_size:
                u0 = struct.unpack_from('<H', insns, p * 2)[0]
                op = u0 & 0xFF
                sz = insn_size(op, u0)
                if sz is None:
                    bad(f"unhandled op 0x{op:02x}"); break
                A = (u0 >> 8) & 0xF
                B = (u0 >> 12) & 0xF
                u1 = struct.unpack_from('<H', insns, (p + 1) * 2)[0] if p + 1 < insns_size else 0
                u2 = struct.unpack_from('<H', insns, (p + 2) * 2)[0] if p + 2 < insns_size else 0
                # ---- writes (dest kinds)
                if op in (0x12, 0x13):            # const/4, const/16
                    kind[A] = INT_KIND
                elif op in (0x14,):               # const
                    kind[A] = INT_KIND
                elif op in (0x16, 0x17, 0x18):    # const-wide family
                    kind[A] = WIDE_KIND
                elif op in (0x1a, 0x1c, 0x22):    # cstr/const-class/new-instance
                    kind[A] = OBJ_KIND
                elif op == 0x0a: kind[A] = INT_KIND
                elif op == 0x0b: kind[A] = WIDE_KIND
                elif op in (0x0c, 0x0d): kind[A] = OBJ_KIND
                elif op == 0x01:
                    kind[A] = kind[B]
                elif op == 0x03:
                    kind[A] = kind[B] or OBJ_KIND
                elif op == 0x02:
                    kind[A] = WIDE_KIND
                elif op == 0x21:
                    kind[A] = INT_KIND
                elif op in (0x60, 0x52):
                    kind[A] = INT_KIND
                elif op in (0x62, 0x54, 0x0c, 0x23, 0x1f):
                    kind[A] = OBJ_KIND
                elif op == 0x20:
                    kind[A] = INT_KIND
                elif op in (0x61,):
                    kind[A] = WIDE_KIND
                elif op in (0x63, 0x67, 0x68, 0x69, 0x59, 0x5b, 0x5a):
                    kind[A] = None  # sget bool/int or writes into object; keep
                elif op == 0x81:
                    kind[A] = WIDE_KIND
                elif op in (0xbb, 0xbc, 0x7e):
                    kind[A] = WIDE_KIND
                elif op in (0xd8,):
                    kind[A] = INT_KIND
                # ---- invoke checks
                if op in INV35C:
                    cnt = (u0 >> 12) & 0xF
                    rs = [(u2 >> (4 * k)) & 0xF for k in range(min(cnt, 4))]
                    if cnt == 5:
                        u3 = struct.unpack_from('<H', insns, (p + 3) * 2)[0]
                        rs.append(u3 & 0xF)
                    mth = u1
                    mcls, mname, (ret, params) = methods[mth]
                    nskip = 0 if op in STATIC_OPS else 1
                    if cnt - nskip != len(params):
                        bad(f"invoke {mname} param mismatch: regs {cnt} (skip={nskip}) vs proto {len(params)} {params}")
                    else:
                        for r, pt in zip(rs[nskip:], params):
                            need = kind_of_type(pt)
                            have = kind[r]
                            if have is not None and need is not None and have != need:
                                bad(f"invoke {mname}: v{r} kind {have} != param {pt} ({need})")
                    if ret in ('J', 'D'):
                        want = 'move_result_wide'
                    elif ret[0] in 'L[':
                        want = 'move_result_object'
                    elif ret == 'V':
                        want = None
                    else:
                        want = 'move_result'
                    if want:
                        nu = struct.unpack_from('<H', insns, (p + sz) * 2)[0]
                        nop = nu & 0xFF
                        nA = (nu >> 8) & 0xF
                        exp = { 'move_result': 0x0a, 'move_result_wide': 0x0b,
                                'move_result_object': 0x0c }[want]
                        if nop != exp:
                            bad(f"invoke {mname} returns {ret} but next op is 0x{nop:02x} (want {want})")
                        else:
                            kind[nA] = kind_of_type(ret)
                    p += sz
                    continue
                elif op in INV3RC:
                    cnt = (u0 >> 12) & 0xF
                    st = u2
                    rs = list(range(st, st + cnt))
                    mth = u1
                    mcls, mname, (ret, params) = methods[mth]
                    nskip = 0 if op in STATIC_OPS else 1
                    if cnt - nskip != len(params):
                        bad(f"invoke-range {mname}: regs {cnt} (skip={nskip}) vs proto {len(params)} {params}")
                    else:
                        for r, pt in zip(rs[nskip:], params):
                            need = kind_of_type(pt)
                            have = kind[r]
                            if have is not None and need is not None and have != need:
                                bad(f"invoke-range {mname}: v{r} kind {have} != param {pt} ({need})")
                    p += sz
                    continue
                # ---- specific reads
                if op == 0x31:  # cmp-long vA, vB, vC  (dialect: [op|a<<8, b|c<<8])
                    for r in (u1 & 0xF, (u1 >> 8) & 0xF):
                        if kind[r] is not None and kind[r] != WIDE_KIND:
                            bad(f"cmp-long: v{r} not wide (kind={kind[r]})")
                    kind[A] = INT_KIND
                elif op in (0xbb, 0xbc):
                    if kind[B] is not None and kind[B] != WIDE_KIND:
                        bad(f"0x{op:02x}: wide src v{B} kind={kind[B]}")
                elif op == 0x7e:
                    if kind[B] is not None and kind[B] != WIDE_KIND:
                        bad(f"neg-long: v{B} kind={kind[B]}")
                elif op == 0x9c:
                    for r in (u1 & 0xF, (u1 >> 8) & 0xF):
                        if kind[r] is not None and kind[r] != WIDE_KIND:
                            bad(f"sub-long: v{r} kind={kind[r]}")
                elif op == 0x81:
                    if kind[B] is not None and kind[B] != INT_KIND:
                        bad(f"int-to-long: v{B} kind={kind[B]}")
                elif op == 0x46:  # aget-object vA, vB[], vC  (dialect: [op|a<<8, b|c<<8])
                    if kind[(u1 >> 8) & 0xF] is not None and kind[(u1 >> 8) & 0xF] != INT_KIND:
                        bad(f"aget-object: idx v{(u1 >> 8) & 0xF} kind={kind[(u1 >> 8) & 0xF]}")
                    if kind[u1 & 0xF] is not None and kind[u1 & 0xF] != OBJ_KIND:
                        bad(f"aget-object: arr v{u1 & 0xF} kind={kind[u1 & 0xF]}")
                    kind[A] = OBJ_KIND
                elif op == 0x4d:  # aput-object vA[], vB, vC  (dialect: [op|a<<8, b|c<<8])
                    if kind[u1 & 0xF] is not None and kind[u1 & 0xF] != INT_KIND:
                        bad(f"aput-object: idx v{u1 & 0xF} kind={kind[u1 & 0xF]}")
                elif op in (0x52, 0x54):  # iget / iget-object
                    if kind[A] is not None and kind[A] != OBJ_KIND:
                        bad(f"iget: obj v{A} kind={kind[A]}")
                    kind[B] = OBJ_KIND if op == 0x54 else INT_KIND
                elif op in (0x59, 0x5b):  # iput / iput-object
                    if kind[A] is not None and kind[A] != OBJ_KIND:
                        bad(f"iput: obj v{A} kind={kind[A]}")
                elif op in (0x62,):  # sget-object
                    kind[A] = OBJ_KIND
                elif op in (0x61,):
                    kind[A] = WIDE_KIND
                elif op in (0x60, 0x63):
                    kind[A] = INT_KIND
                p += sz
    print(f"type-check done, ISSUES: {issues}")
    return 1 if issues else 0

if __name__ == '__main__':
    sys.exit(main(sys.argv[1]))
