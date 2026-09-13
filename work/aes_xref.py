"""
AES cross-reference resolver for libtopfollow.so (all three ABIs).

Why this exists
---------------
`work/fn_strings3.py` resolved per-function .rodata references but kept only
printable C strings (its `cstr()` rejects anything that is not >=92% printable).
The AES S-box, inverse S-box and rcon are high-entropy *binary* tables, so they
were silently discarded -- which is why the first pass over this binary reported
"no crypto in libtopfollow.so". That conclusion was wrong.

This script keeps every resolved .rodata reference, binary or not, and answers:

  1. which functions reference the AES tables (S-box / inverse / rcon)
  2. the full call graph into those functions, up to the JNI entry points
  3. the 22 RegisterNatives entries for x86 (literal table) so an AES-using
     function can be mapped back to its Java method signature

Architectures
-------------
x86      PIC thunk: `call $+5; pop REG; add REG, K` then `[REG+disp]`.
         K is per-function, so a single global base mis-resolves everything.
x86_64   RIP-relative: `lea reg, [rip+disp]` resolves directly.
arm64    ADRP+ADD / ADRP+LDR: page from ADRP, offset from the next instruction.

Run:  .venv/bin/python work/aes_xref.py
"""
import collections
import json
import re
import struct
import sys

import capstone
import lief

ABI = sys.argv[1] if len(sys.argv) > 1 else 'arm64-v8a'
SO = f'work/apk/lib/{ABI}/libtopfollow.so'
OUT = 'work/out'


# ---------------------------------------------------------------- AES tables
def _gmul(a, b):
    r = 0
    for _ in range(8):
        if b & 1:
            r ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return r


def _rotl8(v, n):
    return ((v << n) | (v >> (8 - n))) & 0xFF


def build_aes_tables():
    """Derive S-box / inverse S-box / rcon from first principles."""
    sb = bytearray(256)
    for i in range(256):
        inv = 0
        if i:
            for c in range(256):
                if _gmul(i, c) == 1:
                    inv = c
                    break
        x = inv
        for n in (1, 2, 3, 4):
            x ^= _rotl8(inv, n)
        sb[i] = (x ^ 0x63) & 0xFF
    sb = bytes(sb)
    assert sb[:16].hex() == '637c777bf26b6fc53001672bfed7ab76', 'S-box derivation broken'
    isb = bytearray(256)
    for i, v in enumerate(sb):
        isb[v] = i
    rcon = bytearray([0x01])
    for _ in range(13):
        v = rcon[-1]
        hi = v & 0x80
        v = (v << 1) & 0xFF
        if hi:
            v ^= 0x1B
        rcon.append(v)
    return sb, bytes(isb), bytes(rcon[:14])


def main():
    SBOX, ISBOX, RCON = build_aes_tables()
    raw = open(SO, 'rb').read()
    b = lief.parse(SO)
    secs = {s.name: s for s in b.sections}
    text = secs['.text']
    tb, tsize = text.virtual_address, text.size
    loads = [(s.virtual_address, s.file_offset, max(s.virtual_size, s.physical_size))
             for s in b.segments if 'LOAD' in str(s.type)]

    def va2off(va):
        for v, fo, sz in loads:
            if v <= va < v + sz:
                return fo + (va - v)
        return None

    print(f"=== AES XREF: {SO}  ({len(raw):,} bytes, {ABI}) ===")

    # ---- 1. locate the tables -------------------------------------------
    tbl = {}
    for nm, pat in (('SBOX', SBOX), ('ISBOX', ISBOX), ('RCON', RCON)):
        hits = [m.start() for m in re.finditer(re.escape(pat), raw)]
        tbl[nm] = hits
        print(f"  {nm:<6} {len(pat):>3} B  file offsets {[hex(h) for h in hits] or 'NONE'}")
    if not any(tbl.values()):
        print("  no AES tables in this ABI")
        return
    # file offset == VA for the first PT_LOAD in these DSOs; verify
    for nm, hits in tbl.items():
        for h in hits:
            assert va2off(h) == h, f'{nm}: file offset != VA, adjust'

    # ---- 2. function boundaries -----------------------------------------
    fns = []
    if '.eh_frame' in secs:
        d = bytes(secs['.eh_frame'].content)
        base = secs['.eh_frame'].virtual_address
        i, n = 0, len(d)
        while i + 4 <= n:
            length = struct.unpack_from('<I', d, i)[0]
            if length in (0, 0xFFFFFFFF):
                break
            body = i + 4
            cid = struct.unpack_from('<I', d, body)[0]
            if cid != 0:
                fb = body + 4
                il = struct.unpack_from('<i', d, fb)[0]
                loc = (base + fb + il) & 0xFFFFFFFFFFFFFFFF
                rng = struct.unpack_from('<I', d, fb + 4)[0]
                if rng:
                    fns.append((loc, rng))
            i = body + length
    fns = sorted({(l, r) for l, r in fns})
    merged = []
    for l, r in fns:
        if merged and merged[-1][0] == l:
            merged[-1] = (l, max(merged[-1][1], r))
        else:
            merged.append((l, r))
    fns = merged
    print(f"\n  functions from .eh_frame: {len(fns)}")

    def owner(va):
        best = None
        for l, r in fns:
            if l <= va < l + r:
                best = l
        return best

    # ---- 3. disassemble + resolve data references ------------------------
    if ABI.startswith('arm64'):
        md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
    elif ABI == 'x86_64':
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    else:
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = True

    toff = va2off(tb)
    code = raw[toff:toff + tsize]
    insns = list(md.disasm(code, tb))
    print(f"  disassembled {len(insns):,} instructions")

    # index instructions by owning function
    by_fn = collections.defaultdict(list)
    for ins in insns:
        o = owner(ins.address)
        if o is not None:
            by_fn[o].append(ins)

    tbl_vas = set()
    for hits in tbl.values():
        tbl_vas.update(hits)

    def resolve_fn(fva, flist):
        """Return set of .rodata/data VAs this function references, and its bl/call targets."""
        refs, calls = set(), set()
        if ABI.startswith('arm64'):
            page = {}
            for ins in flist:
                p = [x.strip() for x in ins.op_str.split(',')]
                if ins.mnemonic == 'adrp' and len(p) == 2:
                    try:
                        page[p[0]] = int(p[1].replace('#', ''), 0)
                    except ValueError:
                        pass
                elif ins.mnemonic in ('add', 'ldr', 'ldrb', 'ldrh', 'ldrsw', 'str', 'strb'):
                    reg = imm = None
                    if ins.mnemonic == 'add' and len(p) == 3 and p[2].startswith('#'):
                        reg, imm = p[1], p[2][1:]
                    elif len(p) == 2 and p[1].startswith('['):
                        ip = [x.strip() for x in p[1].strip('[]').split(',')]
                        if len(ip) == 2 and ip[1].startswith('#'):
                            reg, imm = ip[0], ip[1][1:]
                    if reg in page and imm:
                        try:
                            refs.add(page[reg] + int(imm.replace('#', ''), 0))
                        except ValueError:
                            pass
                elif ins.mnemonic in ('bl', 'b') and ins.op_str.startswith('#'):
                    try:
                        calls.add(int(ins.op_str[1:], 0))
                    except ValueError:
                        pass
        elif ABI == 'x86_64':
            for ins in flist:
                if ins.mnemonic == 'lea' and 'rip' in ins.op_str:
                    m = re.search(r'rip\s*\+\s*(?:0x)?([0-9a-fA-F]+)', ins.op_str)
                    if m:
                        refs.add(ins.address + ins.size + int(m.group(1), 16))
                elif ins.mnemonic in ('call', 'jmp'):
                    m = re.match(r'^(?:0x)?([0-9a-fA-F]+)$', ins.op_str.strip())
                    if m:
                        calls.add(int(m.group(1), 16))
        else:
            # x86 PIC thunk. Capstone renders `call $+5` as the literal address
            # of the following instruction, so the pattern to match is:
            #     call <addr>   where <addr> == address of the NEXT insn
            #     pop  REG
            #     add  REG, K          ; REG = <addr> + K  == GOT base
            # then every [REG + disp] resolves to GOT_base + disp.
            base = {}
            for idx, ins in enumerate(flist):
                if ins.mnemonic == 'call' and re.match(r'^0x[0-9a-f]+$', ins.op_str.strip()):
                    try:
                        tgt = int(ins.op_str.strip(), 16)
                    except ValueError:
                        continue
                    nxt = ins.address + ins.size
                    if tgt != nxt:
                        continue
                    for j in (idx + 1, idx + 2):
                        if j >= len(flist):
                            break
                        c = flist[j]
                        if c.mnemonic == 'pop':
                            reg = c.op_str.strip()
                            for k in (j + 1, j + 2, j + 3):
                                if k >= len(flist):
                                    break
                                a2 = flist[k]
                                if a2.mnemonic == 'add' and a2.op_str.startswith(reg + ','):
                                    try:
                                        base[reg] = nxt + int(a2.op_str.split(',')[1].strip(), 0)
                                    except ValueError:
                                        pass
                                    break
                            break
                elif ins.mnemonic in ('call', 'jmp'):
                    m = re.match(r'^0x([0-9a-fA-F]+)$', ins.op_str.strip())
                    if m:
                        calls.add(int(m.group(1), 16))
            # NB: the GOT base sits ABOVE .rodata in this DSO (0xdfe0c), so
            # references to the AES tables are NEGATIVE displacements, rendered
            # by Capstone as `[ebx - 0x8cd9c]`. A regex that only accepts `+`
            # silently resolves nothing -- that is why the first revision of
            # this script reported zero AES references on x86.
            DISP = re.compile(r'\[(e[bcdsx]p|e[abcd]x|e[sd]i)\s*([+-])\s*(0x[0-9a-fA-F]+|\d+)\]')
            for ins in flist:
                for reg, sign, disp in DISP.findall(ins.op_str):
                    if reg in base:
                        d = int(disp, 0)
                        refs.add(base[reg] + (d if sign == '+' else -d))
        return refs, calls

    # ---- 4. which functions touch the AES tables -------------------------
    aes_fns = {}
    allrefs, allcalls = {}, {}
    for fva, flist in by_fn.items():
        refs, calls = resolve_fn(fva, flist)
        allrefs[fva], allcalls[fva] = refs, calls
        hit = {t for t in refs if t in tbl_vas}
        if hit:
            aes_fns[fva] = sorted(hit)
    print(f"\n--- 4. functions referencing AES tables: {len(aes_fns)} ---")
    for fva in sorted(aes_fns):
        rng = dict(fns).get(fva)
        labels = []
        for t in aes_fns[fva]:
            for nm, hits in tbl.items():
                if t in hits:
                    labels.append(nm)
        print(f"    fn {fva:#08x} size {rng or '?':>8}  tables={sorted(set(labels))}  offsets={[hex(x) for x in aes_fns[fva]]}")

    # ---- 5. reverse call graph: who reaches the AES functions ------------
    callers = collections.defaultdict(set)
    for fva, cs in allcalls.items():
        for c in cs:
            if c in allrefs:            # c is a known function
                callers[c].add(fva)

    print(f"\n--- 5. call graph into the AES functions ---")
    reach = {}
    for seed in sorted(aes_fns):
        seen, stack, depth = {seed}, [seed], 0
        levels = [[seed]]
        while stack and depth < 6:
            nxt = []
            for f in stack:
                for c in callers.get(f, ()):
                    if c not in seen:
                        seen.add(c)
                        nxt.append(c)
            if not nxt:
                break
            levels.append(sorted(nxt))
            stack = nxt
            depth += 1
        reach[seed] = [len(l) for l in levels]
        print(f"    {seed:#08x}: BFS fan-in per level = {[len(l) for l in levels]}  total ancestors {len(seen)}")
        for li, l in enumerate(levels[1:4], 1):
            print(f"        L{li}: {[hex(x) for x in l[:12]]}{' ...' if len(l) > 12 else ''}")

    # ---- 6. map to JNI entries (x86 has the literal table) ---------------
    print(f"\n--- 6. JNI RegisterNatives mapping ---")
    try:
        J = json.load(open(f'{OUT}/14_jni_natives.json')).get(ABI) or {}
    except Exception:
        J = {}
    if J:
        items = sorted(((nm, int(i['fn_va'], 16), i['signature']) for nm, i in J.items()),
                       key=lambda x: x[1])
        for nm, va, sig in items:
            anc = set()
            for seed in aes_fns:
                seen, stack = {seed}, [seed]
                while stack:
                    nxt = []
                    for f in stack:
                        for c in callers.get(f, ()):
                            if c not in seen:
                                seen.add(c)
                                nxt.append(c)
                    stack = nxt
                anc |= seen
            mark = 'USES-AES' if va in anc or va in aes_fns else ''
            print(f"    {nm:<14} {va:#08x}  {sig[:70]:<70} {mark}")
    else:
        print(f"    no literal JNI table for {ABI} (64-bit builds materialise it at runtime)")
        print("    -> use dynamic-lab/07_native_jni_dumper.js to intercept RegisterNatives")

    with open(f'{OUT}/32_aes_xref_{ABI}.json', 'w') as f:
        json.dump({'abi': ABI, 'size': len(raw),
                   'tables': {k: [hex(x) for x in v] for k, v in tbl.items()},
                   'aes_functions': {hex(k): [hex(x) for x in v] for k, v in aes_fns.items()},
                   'reachability': {hex(k): v for k, v in reach.items()},
                   'function_count': len(fns)}, f, indent=2)
    print(f"\n    wrote {OUT}/32_aes_xref_{ABI}.json")


if __name__ == '__main__':
    main()
