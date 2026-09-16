#!/usr/bin/env python3
"""
dex_preflight.py — structural verifier for the hand-assembled classes2.dex
(dialect exactly as emitted by dex_core.py / dex_emit.py):

  u16 packing: unit = op | A<<8 | B<<12
  1-unit ops:  0x01-0x03 (move*), 0x0a-0x0d (move_result*), 0x0e-0x11 (ret*),
               0x12 (const/4), 0x1d/0x1e (monitor), 0x21 (array-length),
               0x27 (throw), 0x28 (goto g8: target = p + off8),
               0x7e (neg-long), 0xbb/0xbc (*/long/2addr)
  2-unit ops:  0x13/0x16 (21h), 0x1a/0x1f/0x22 (21c: str/type idx),
               0x20/0x23 (22c type idx), 0x52/0x54/0x59/0x5b (22c field),
               0x60-0x63/0x67-0x69 (22c field), 0x81 (int-to-long),
               0x9c (sub-long), 0x31/0x46/0x4d (23x), 0x34/0x35/0x38/0x39/0x3b
               (31t: target = (p+1) + lit16), 0xd8 (22b: B = u1&0xF)
  3-unit ops:  0x14/0x17/0x18 (31i), invokes 0x6e-0x72 (35c:
               [op|cnt][mth16][r0|r1<<4|r2<<8|r3<<12, (+r4<<16 -> 4u if cnt=5)]),
               invoke-range 0x74/0x76/0x77 (3Rc: [op|cnt][mth16][start16])
  try items:   per try [start:u32][insn_cnt:u16][handler_off:u16] (8B,
               offsets in 2-byte units), then uleb128(n) + handler list
               (sleb128(size) [uleb128(type)]*size uleb128(off_units))

Checks: register bounds, invoke args <= outs, table-index bounds,
branch targets land on instruction boundaries, try/handler validity.
"""
import struct, sys, logging
logging.disable(logging.CRITICAL)

U1 = {0x00,  # nop (emitter pads insns to 4-byte alignment with 0x0000)
      0x01,0x02,0x03,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,0x11,
      0x12,0x1d,0x1e,0x21,0x27,0x28,0x7e,0xbb,0xbc}
U2 = {0x13,0x16,0x1a,0x1f,0x20,0x22,0x23,0x31,0x34,0x35,0x38,0x39,
      0x3b,0x46,0x4d,0x52,0x54,0x59,0x5b,0x60,0x61,0x62,0x63,0x67,
      0x68,0x69,0x81,0x9c,0xd8}
U3 = {0x14,0x17,0x18}
INV35C = {0x6e,0x6f,0x70,0x71,0x72}
INV3RC = {0x74,0x76,0x77}
STR21C = {0x1a}
TYPE21C = {0x1f,0x22,0x20,0x23}
FIELD22C = {0x52,0x54,0x59,0x5b,0x60,0x61,0x62,0x63,0x67,0x68,0x69,0x9c}

def uleb(b, p):
    r = s = 0
    while True:
        x = b[p]; p += 1
        r |= (x & 0x7F) << s
        if not x & 0x80:
            return r, p
        s += 7

def sleb(b, p):
    r = s = 0
    while True:
        x = b[p]; p += 1
        r |= (x & 0x7F) << s
        s += 7
        if not x & 0x80:
            if x & 0x40:
                r -= 1 << s
            return r, p

def insn_size(op, u0, insns, p):
    if op in U1:
        return 1
    if op in U2:
        return 2
    if op in U3:
        return 3
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
    nstr, ntype = h.string_ids_size, h.type_ids_size
    nfdl, nmdl = h.field_ids_size, h.method_ids_size
    issues = total = 0
    for c in d.get_classes():
        for m in c.get_methods():
            code = m.get_code()
            if code is None:
                continue
            total += 1
            tag = f"{c.get_name().rstrip(';')}.{m.get_name()}"
            errs = []
            def bad(msg):
                errs.append(msg)
                print(f"[{tag}] u{p} 0x{op:02x}: {msg}")
            off = code.get_off()
            regs = code.get_registers_size()
            outs = code.get_outs_size()
            insns_size = code.get_insns_size()
            tries_size = code.get_tries_size()
            raw = dex[off: off + 16 + insns_size * 2 + tries_size * 8 + 128]
            insns = raw[16:16 + insns_size * 2]
            # pass 1: instruction starts
            starts = set()
            p, broken = 0, False
            while p < insns_size:
                u0 = struct.unpack_from('<H', insns, p * 2)[0]
                op = u0 & 0xFF
                starts.add(p)
                sz = insn_size(op, u0, insns, p)
                if sz is None:
                    print(f"[{tag}] u{p}: UNHANDLED opcode 0x{op:02x}")
                    issues += 1
                    broken = True
                    break
                p += sz
            if p != insns_size:
                print(f"[{tag}] decode end at u{p} != insns_size {insns_size}")
                issues += 1
                broken = True
            if broken:
                continue
            # pass 2: operands
            p = 0
            max_inv = 0
            def U(k):
                o = (p + k) * 2
                return struct.unpack_from('<H', insns, o)[0] if o + 2 <= len(insns) else 0
            while p < insns_size:
                u0 = struct.unpack_from('<H', insns, p * 2)[0]
                op = u0 & 0xFF
                A = (u0 >> 8) & 0xF
                B = (u0 >> 12) & 0xF
                u1, u2 = U(1), U(2)
                sz = insn_size(op, u0, insns, p)
                if op in U1:
                    if op == 0x28:  # goto g8
                        off8 = (u0 >> 8) & 0xFF
                        if off8 & 0x80:
                            off8 -= 0x100
                        t = p + off8
                        if t not in starts:
                            bad(f"goto target u{t} not an insn start")
                    elif op in (0x01, 0x02, 0x03, 0x21, 0x7e, 0xbb, 0xbc):
                        for r in (A, B):
                            if r >= regs:
                                bad(f"reg {r} >= regs {regs}")
                    elif A >= regs:
                        bad(f"vA={A} >= regs {regs}")
                elif op in U2:
                    if op in FIELD22C or op in (0x52, 0x54):
                        for r in (A, B):
                            if r >= regs:
                                bad(f"reg {r} >= regs {regs}")
                        if u1 >= nfdl:
                            bad(f"field idx {u1} >= {nfdl}")
                    elif op in TYPE21C:
                        if A >= regs:
                            bad(f"vA={A} >= regs {regs}")
                        if u1 >= ntype:
                            bad(f"type idx {u1} >= {ntype}")
                    elif op in STR21C:
                        if A >= regs:
                            bad(f"vA={A} >= regs {regs}")
                        if u1 >= nstr:
                            bad(f"string idx {u1} >= {nstr}")
                    elif op in (0x13, 0x16):
                        if A >= regs:
                            bad(f"vA={A} >= regs {regs}")
                    elif op == 0x81:
                        if A >= regs:
                            bad(f"vA={A} >= regs {regs}")
                    elif op in (0x31, 0x46, 0x4d):
                        C = (u1 >> 4) & 0xF
                        for r in (A, B, C):
                            if r >= regs:
                                bad(f"reg {r} >= regs {regs}")
                    elif op == 0xd8:
                        for r in (A, u1 & 0xF):
                            if r >= regs:
                                bad(f"reg {r} >= regs {regs}")
                    elif 0x32 <= op <= 0x3d:
                        if A >= regs or B >= regs:
                            bad(f"reg {A}/{B} >= regs {regs}")
                        lit = u1 if u1 < 0x8000 else u1 - 0x10000
                        t = (p + 1) + lit
                        if t not in starts:
                            bad(f"branch target u{t} not an insn start (lit {lit})")
                elif op in U3:
                    if A >= regs:
                        bad(f"vA={A} >= regs {regs}")
                elif op in INV35C:
                    cnt = (u0 >> 12) & 0xF
                    rs = [(u2 >> (4 * k)) & 0xF for k in range(4)]
                    if cnt == 5:
                        rs.append(U(3) & 0xF)
                    for r in rs[:cnt]:
                        if r >= regs:
                            bad(f"invoke reg {r} >= regs {regs}")
                    if cnt > outs:
                        bad(f"INVOKE args {cnt} > outs {outs}")
                    max_inv = max(max_inv, cnt)
                    if u1 >= nmdl:
                        bad(f"method idx {u1} >= {nmdl}")
                elif op in INV3RC:
                    cnt = (u0 >> 12) & 0xF
                    st = u2
                    if st + cnt > regs:
                        bad(f"invoke-range v{st}..v{st+cnt-1} exceeds regs {regs}")
                    if cnt > outs:
                        bad(f"INVOKE-RANGE args {cnt} > outs {outs}")
                    max_inv = max(max_inv, cnt)
                    if u1 >= nmdl:
                        bad(f"method idx {u1} >= {nmdl}")
                p += sz
            issues += len(errs)
            # tries
            if tries_size:
                tries = raw[16 + insns_size * 2:]
                item_hoffs = []
                for t in range(tries_size):
                    s, cnt, hoff = struct.unpack_from('<IHH', tries, t * 8)
                    item_hoffs.append(hoff)
                    if s >= insns_size or s + cnt > insns_size:
                        print(f"[{tag}] try{s:#x}+{cnt} out of bounds (insns {insns_size})")
                        issues += 1
                    elif s not in starts or (s + cnt not in starts and s + cnt != insns_size):
                        print(f"[{tag}] try {s:#x}..{s+cnt:#x} boundary not at insn start")
                        issues += 1
                tpos = tries_size * 8
                n, q = uleb(tries, tpos)
                if n != tries_size:
                    print(f"[{tag}] handler-list size {n} != {tries_size} tries")
                    issues += 1
                for k in range(n):
                    entry_start = q
                    sz, q = sleb(tries, q)
                    if k < len(item_hoffs) and entry_start != tpos + item_hoffs[k]:
                        print(f"[{tag}] handler {k}: stored off {item_hoffs[k]} != actual {entry_start - tpos}")
                        issues += 1
                    if sz < 0:
                        print(f"[{tag}] negative filter size")
                        issues += 1
                        break
                    for _k in range(sz):
                        ti, q = uleb(tries, q)
                        if ti >= ntype:
                            print(f"[{tag}] catch type {ti} >= {ntype}")
                            issues += 1
                    hoffv, q = uleb(tries, q)
                    # handler offset = instruction-unit offset of catch target
                    if hoffv > insns_size or hoffv not in starts:
                        print(f"[{tag}] catch handler at u{hoffv} not an insn start (insns {insns_size})")
                        issues += 1
            print(f"[{tag}] checked regs={regs} outs={outs} max_inv_args={max_inv} tries={tries_size}")
    print(f"\nmethods checked: {total}  ISSUES: {issues}")
    return 1 if issues else 0

if __name__ == '__main__':
    sys.exit(main(sys.argv[1]))
