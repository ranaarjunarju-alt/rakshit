#!/usr/bin/env python3
"""Dialect-dex auditor: parse both dexes, disassemble every code item with the
dialect opcodes (as defined by dex_core.py), and check (regs, ins, outs) vs the
registers actually referenced.  Usage: tmp_dex_audit.py <dexfile>"""
import struct, sys

def uleb(d, o):
    v = sh = 0
    while True:
        b = d[o]; o += 1
        v |= (b & 0x7F) << sh
        if not b & 0x80: break
        sh += 7
    return v, o

class D:
    def __init__(self, d):
        self.d = d
        self.sec = {}
        for i, name in enumerate(['string', 'type', 'proto', 'field', 'method', 'class']):
            cnt, off = struct.unpack_from('<II', d, 0x38 + 8 * i)
            self.sec[name] = (cnt, off)
        self.N, self.S = self.sec['string']          # N=count, S=off
        T, To = self.sec['type']
        self.types = [struct.unpack_from('<I', d, To + 4 * i)[0] for i in range(T)]
        M, Mo = self.sec['method']
        self.meth = [struct.unpack_from('<HHHH', d, Mo + 8 * i) for i in range(M)]
        C, Co = self.sec['class']
        self.classes = [struct.unpack_from('<8I', d, Co + 32 * i) for i in range(C)]

    def sstr(self, i):
        d = self.d
        if i < 0 or i >= self.N: return f"<S{i}>"
        off = struct.unpack_from('<I', d, self.S + 4 * i)[0]
        if off + 1 >= len(d): return f"<S{i}@{off:#x}>"
        j = off + 1; bs = bytearray()
        while d[j]: bs.append(d[j]); j += 1
        return bs.decode('utf-8', 'replace')

    def tstr(self, i):
        return self.sstr(self.types[i]) if 0 <= i < len(self.types) else f"<T{i}>"

    def mname(self, i):
        c, p, n, q = self.meth[i]   # dialect: (class, proto, name, pad)
        return f"{self.tstr(c)}.{self.sstr(n)}"

    def class_data(self, coff):
        d = self.d
        nf, o = uleb(d, coff); ni, o = uleb(d, o); nd, o = uleb(d, o); nv, o = uleb(d, o)
        acc = 0; fields = []
        for _ in range(nf):
            df, o = uleb(d, o); acc += df; af, o = uleb(d, o); fields.append(acc)
        acc = 0; directs = []
        for _ in range(nd):
            dm, o = uleb(d, o); acc += dm; am, o = uleb(d, o); co, o = uleb(d, o)
            directs.append((am, co))
        acc = 0; virtuals = []
        for _ in range(nv):
            dm, o = uleb(d, o); acc += dm; am, o = uleb(d, o); co, o = uleb(d, o)
            virtuals.append((am, co))
        return nf, ni, nd, nv, fields, directs, virtuals

# ---------------- dialect disassembler (opcodes per dex_core.py) ------------
REG_FMTS = {  # op -> (n_units, [reg fields as (shift,mask) on unit0], 'A' on unit1 for 21c/22c)
    0x00: (1, [(8, 0xF)]),            # nop
    0x0a: (1, [(8, 0xF)]), 0x0b: (1, [(8, 0xF)]), 0x0c: (1, [(8, 0xF)]),
    0x0d: (1, [(8, 0xF)]), 0x0f: (1, [(8, 0xF)]), 0x10: (1, [(8, 0xF)]),
    0x11: (1, [(8, 0xF)]), 0x12: (1, [(8, 0xF)]), 0x1d: (1, [(8, 0xF)]),
    0x1e: (1, [(8, 0xF)]), 0x27: (1, [(8, 0xF)]),
    0x01: (1, [(8, 0xF), (12, 0xF)]), 0x04: (1, [(8, 0xF), (12, 0xF)]),
    0x07: (1, [(8, 0xF), (12, 0xF)]), 0x21: (1, [(8, 0xF), (12, 0xF)]),
    0x7d: (1, [(8, 0xF), (12, 0xF)]), 0x81: (1, [(8, 0xF), (12, 0xF)]),
    0xbb: (1, [(8, 0xF), (12, 0xF)]), 0xbc: (1, [(8, 0xF), (12, 0xF)]),
    0x31: (2, [(8, 0xF)]),            # + unit1: b|c<<8
    0x46: (2, [(8, 0xF)]), 0x4d: (2, [(8, 0xF)]),
    0xd8: (2, [(8, 0xF)]), 0x9c: (2, [(8, 0xF)]),
    0x13: (2, [(8, 0xF)]), 0x14: (2, [(8, 0xF)]), 0x16: (2, [(8, 0xF)]),
    0x17: (2, [(8, 0xF)]),
    0x1a: (2, [(8, 0xF)]), 0x1f: (2, [(8, 0xF)]), 0x22: (2, [(8, 0xF)]),
    0x60: (2, [(8, 0xF)]), 0x61: (2, [(8, 0xF)]), 0x62: (2, [(8, 0xF)]),
    0x63: (2, [(8, 0xF)]), 0x67: (2, [(8, 0xF)]), 0x68: (2, [(8, 0xF)]),
    0x69: (2, [(8, 0xF)]),
    0x52: (2, [(8, 0xF), (12, 0xF)]), 0x54: (2, [(8, 0xF), (12, 0xF)]),
    0x59: (2, [(8, 0xF), (12, 0xF)]), 0x5b: (2, [(8, 0xF), (12, 0xF)]),
    0x23: (2, [(8, 0xF), (12, 0xF)]), 0x20: (2, [(8, 0xF), (12, 0xF)]),
    0x34: (2, [(8, 0xF), (12, 0xF)]), 0x35: (2, [(8, 0xF), (12, 0xF)]),
    0x38: (2, [(8, 0xF)]), 0x39: (2, [(8, 0xF)]), 0x3b: (2, [(8, 0xF)]),
}
INV = {0x6e: 'v', 0x6f: 's', 0x70: 'd', 0x71: 't', 0x72: 'i'}
INVR = {0x74: 'v', 0x76: 'd', 0x77: 't'}

def disasm(units, base_off):
    """returns (list of (off_units, desc), regs_used set, problems list)"""
    out = []; used = set(); probs = []; i = 0
    while i < len(units):
        u = units[i]
        op = u & 0xFF
        off = i
        if op in INV:
            n = (u >> 12) & 0xF
            mref = units[i + 1]; r = units[i + 2]
            regs = [(r >> (4 * k)) & 0xF for k in range(n)]
            used.update(regs); used.add(r & 0xF) if n == 0 else None
            out.append((off, f"invoke-{INV[op]} n={n} m={mref} regs={regs}"))
            i += 3
        elif op in INVR:
            cnt = (u >> 12) & 0xF
            mref = units[i + 1]; start = units[i + 2]
            used.update(range(start, start + cnt))
            out.append((off, f"invoke-{INVR[op]}_range m={mref} v{start}-{start+cnt-1}"))
            i += 3
        elif op in REG_FMTS:
            nu, fields = REG_FMTS[op]
            for sh, mk in fields:
                used.add((u >> sh) & mk)
            # 2-unit 21c/22c/35C formats: second unit holds target (not reg) except branches
            if op in (0x31, 0x46, 0x4d, 0xd8, 0x9c):
                u1 = units[i + 1]
                if op in (0x31, 0x46, 0x4d, 0x9c):
                    used.add(u1 & 0xF); used.add((u1 >> 8) & 0xF)
                else:
                    used.add(u1 & 0xFF)
            out.append((off, f"op{op:02x} u1={units[i+1] if nu==2 else '-'}"))
            i += nu
        else:
            probs.append((off, f"UNKNOWN op {u:04x}"))
            i += 1
    return out, used, probs

def audit(path):
    d = open(path, 'rb').read()
    x = D(d)
    print(f"===== {path}  ({len(d)} B, strings={x.N}, methods={x.sec['method'][0]}) =====")
    issues = 0
    for ci, cd in enumerate(x.classes):
        typ, acc, sup, ifo, x1, x2, cdata, x3 = cd
        nf, ni, nd, nv, fields, directs, virtuals = x.class_data(cdata)
        print(f"-- class {x.tstr(typ)}  cdata={cdata:#x}  statics={nf} direct={nd} virtual={nv}")
        for kind, mlist in (('direct', directs), ('virtual', virtuals)):
            for mi, coff in mlist:
                nm = x.mname(mi)
                regs, ins, outs, ntry, dbg, nins = struct.unpack_from('<HHHHII', d, coff)
                units = [struct.unpack_from('<H', d, coff + 16 + 2 * k)[0] for k in range(nins)]
                insns_off = coff + 16
                tryitems = []
                p = coff + 16 + 2 * nins
                for t in range(ntry):
                    s, e, h = struct.unpack_from('<IHH', d, p); p += 8
                    tryitems.append((s, e, h))
                listing, used, probs = disasm(units, insns_off)
                bad = []
                if regs != ins + outs: bad.append(f"regs{regs} != ins{ins}+outs{outs}")
                for r in used:
                    if r >= regs: bad.append(f"v{r} >= regs{regs}")
                for t in probs: bad.append(f"insn@{t[0]}u: {t[1]}")
                for (s, e, h) in tryitems:
                    if e < s or h > 2 * nins: bad.append(f"try({s},{e},{h}) oob")
                flag = "  <<< " + "; ".join(bad) if bad else ""
                if bad: issues += 1
                print(f"   {kind:7s} {nm:55s} coff={coff:#06x} (regs={regs},ins={ins},outs={outs}) "
                      f"insns={nins:3d} used={sorted(used)}{flag}")
    print(f"== {path}: ISSUES = {issues}")
    return x

if __name__ == '__main__':
    audit(sys.argv[1])
