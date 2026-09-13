"""
arm64-v8a libtopfollow.so: function boundaries from .eh_frame, the RegisterNatives
table recovered statically from JNI_OnLoad, and identification of the AES code.

Three things this produces that the earlier pass did not have:

  1. A real function table for arm64 (FDE initial_location + address_range from
     .eh_frame), so a code address can be attributed to a function.
  2. The 22-entry JNINativeMethod array as materialised on arm64. The 64-bit
     builds do NOT contain the table as literal VA pointers (only x86 does), so
     it is recovered by tracking ADRP/ADD pairs inside JNI_OnLoad and grouping
     them into {name, signature, fnPtr, reserved} quadruples.
  3. Which function(s) reference the AES S-box at VA 0x128b0, the inverse
     S-box at 0x139b0 and rcon at 0x13b10 -- plus a full disassembly of that
     function so the round structure / key length can be read directly.

Run:  .venv/bin/python work/native_deep.py
"""
import collections
import json
import re
import struct
import sys

import capstone
import lief

SO = sys.argv[1] if len(sys.argv) > 1 else 'work/apk/lib/arm64-v8a/libtopfollow.so'
OUT = sys.argv[2] if len(sys.argv) > 2 else 'work/out'

SBOX_VA = 0x128B0
ISBOX_VA = 0x139B0
RCON_VA = 0x13B10


# --------------------------------------------------------------------------
# .eh_frame -> function boundaries
# --------------------------------------------------------------------------
def parse_eh_frame(raw, b):
    """Yield (initial_location, address_range) for every FDE."""
    sec = next((s for s in b.sections if s.name == '.eh_frame'), None)
    if sec is None:
        return []
    d = bytes(sec.content)
    base = sec.virtual_address
    out = []
    i = 0
    n = len(d)
    cie_cache = {}
    while i + 4 <= n:
        length = struct.unpack_from('<I', d, i)[0]
        start = i
        if length == 0:
            break
        if length == 0xFFFFFFFF:
            break  # 64-bit DWARF not expected here
        body = i + 4
        cid = struct.unpack_from('<I', d, body)[0]
        if cid == 0:
            # CIE
            cie_cache[start] = body
            i = body + length
            continue
        # FDE: cie_pointer is relative to its own field position
        cie_field = body
        cie_ptr = struct.unpack_from('<I', d, cie_field)[0]
        cie_start = cie_field - cie_ptr
        fde_body = cie_field + 4
        # pointer encoding from the CIE augmentation
        enc = 0x1B  # DW_EH_PE_pcrel | DW_EH_PE_sdata4 (the usual default)
        cie_aug = cie_cache.get(cie_start)
        if cie_aug is not None:
            # CIE: version(1) augstring(NUL-term) ...  augmentation data
            p = cie_aug + 4 + 1  # skip length+id? recompute below
        # Read pcrel sdata4 initial_location
        il = struct.unpack_from('<i', d, fde_body)[0]
        initial_location = (base + fde_body + il) & 0xFFFFFFFFFFFFFFFF
        ar = struct.unpack_from('<I', d, fde_body + 4)[0]
        out.append((initial_location, ar, base + fde_body))
        i = body + length
    return out


def functions_from_eh(raw, b):
    fdes = parse_eh_frame(raw, b)
    fns = [(loc, rng) for loc, rng, _ in fdes if rng]
    fns.sort()
    # merge duplicates
    merged = []
    for loc, rng in fns:
        if merged and merged[-1][0] == loc:
            merged[-1] = (loc, max(merged[-1][1], rng))
        else:
            merged.append((loc, rng))
    return merged


# --------------------------------------------------------------------------
# ADRP/ADD page tracking
# --------------------------------------------------------------------------
def track_adrp(md, code, base):
    """Return list of (addr, mnemonic, op_str, resolved_target)."""
    page = {}
    events = []
    for ins in md.disasm(code, base):
        parts = [x.strip() for x in ins.op_str.split(',')]
        if ins.mnemonic == 'adrp' and len(parts) == 2:
            try:
                page[parts[0]] = int(parts[1].replace('#', ''), 0)
            except ValueError:
                pass
            events.append((ins.address, ins.mnemonic, ins.op_str, None))
        elif ins.mnemonic == 'add' and len(parts) == 3 and parts[2].startswith('#'):
            tgt = None
            if parts[1] in page:
                try:
                    tgt = page[parts[1]] + int(parts[2][1:].replace('#', ''), 0)
                except ValueError:
                    tgt = None
            events.append((ins.address, ins.mnemonic, ins.op_str, tgt))
        else:
            events.append((ins.address, ins.mnemonic, ins.op_str, None))
    return events


def main():
    raw = open(SO, 'rb').read()
    b = lief.parse(SO)
    text = next(s for s in b.sections if s.name == '.text')
    tbase, tdata = text.virtual_address, bytes(text.content)

    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
    md.detail = True

    print(f"=== {SO} ===")
    print(f"size {len(raw):,}  .text VA {tbase:#x} size {text.size:,}")

    fns = functions_from_eh(raw, b)
    print(f"\n--- 1. function boundaries from .eh_frame: {len(fns)} FDEs ---")
    if fns:
        print(f"    first: {fns[0][0]:#x} (+{fns[0][1]})   last: {fns[-1][0]:#x} (+{fns[-1][1]})")
        sizes = [r for _, r in fns]
        print(f"    size total {sum(sizes):,}  max {max(sizes):,}  median {sorted(sizes)[len(sizes)//2]:,}")

    def containing(va):
        best = None
        for loc, rng in fns:
            if loc <= va < loc + rng:
                best = (loc, rng)
        return best

    # ------------------------------------------------------------------
    print(f"\n--- 2. AES table locations ---")
    for nm, va in [('forward S-box', SBOX_VA), ('inverse S-box', ISBOX_VA), ('rcon', RCON_VA)]:
        off = va  # in this DSO, VA == file offset for the first LOAD segment
        print(f"    {nm:<16} VA {va:#x}  file off {off:#x}  bytes {raw[off:off+16].hex(' ')}")

    # ------------------------------------------------------------------
    print(f"\n--- 3. code that references the AES tables ---")
    events = track_adrp(md, tdata, tbase)
    targets = {SBOX_VA: 'SBOX', ISBOX_VA: 'ISBOX', RCON_VA: 'RCON'}
    refs = collections.defaultdict(list)
    for addr, mn, op, tgt in events:
        if tgt in targets:
            refs[targets[tgt]].append((addr, mn, op))
    fn_of_ref = collections.defaultdict(list)
    for tbl, lst in sorted(refs.items()):
        print(f"    {tbl}: {len(lst)} direct ADRP+ADD references")
        for addr, mn, op in lst[:14]:
            c = containing(addr)
            tag = f"  [fn {c[0]:#x}+{c[1]}]" if c else "  [fn ?]"
            print(f"      {addr:#x}  {mn} {op}{tag}")
            if c:
                fn_of_ref[c[0]].append((tbl, addr))
        if len(lst) > 14:
            print(f"      ... and {len(lst)-14} more")

    # ------------------------------------------------------------------
    print(f"\n--- 4. functions that touch the AES tables ---")
    aes_fns = []
    for loc in sorted(fn_of_ref):
        rng = containing(loc)
        tbls = collections.Counter(t for t, _ in fn_of_ref[loc])
        print(f"    fn {loc:#x} size {rng[1] if rng else '?'}  refs={dict(tbls)}")
        aes_fns.append((loc, rng[1] if rng else 0, dict(tbls)))

    # ------------------------------------------------------------------
    print(f"\n--- 5. RegisterNatives table recovered from JNI_OnLoad ---")
    jon = next((s for s in b.exported_symbols if s.name == 'JNI_OnLoad'), None)
    if jon is None:
        print("    JNI_OnLoad not exported")
        return
    c = containing(jon.value)
    print(f"    JNI_OnLoad VA {jon.value:#x}  fn range {c}")
    rng = c[1] if c else 0x6000
    seg = tdata[jon.value - tbase: jon.value - tbase + rng]
    jev = track_adrp(md, seg, jon.value)
    # Collect resolved data pointers in order; the JNINativeMethod array is
    # built as a sequence of {name, sig, fnPtr, reserved} stores.
    ptrs = [(a, t) for a, mn, op, t in jev if t and t > 0x1000]
    print(f"    ADRP+ADD data pointers inside JNI_OnLoad: {len(ptrs)}")
    # heuristic: group consecutive resolved pointers into quadruples
    quads = []
    buf = []
    for a, t in ptrs:
        buf.append((a, t))
        if len(buf) == 4:
            quads.append(buf)
            buf = []
    print(f"    candidate quadruples: {len(quads)}")
    methods = []
    for q in quads[:40]:
        name_p, sig_p, fn_p, _ = q[0][1], q[1][1], q[2][1], q[3][1]
        def cstr(va):
            if not (0 < va < len(raw)):
                return None
            e = raw.find(b'\x00', va)
            s = raw[va:e] if e != -1 else b''
            return s.decode('utf-8', 'replace') if s and all(32 <= ch < 127 for ch in s) else None
        nm, sg = cstr(name_p), cstr(sig_p)
        if nm and sg and sg.startswith('('):
            methods.append({'name': nm, 'sig': sg, 'fn_va': hex(fn_p), 'tbl_va': hex(name_p)})
    print(f"    VALIDATED JNINativeMethod entries: {len(methods)}")
    for m in methods:
        cf = containing(int(m['fn_va'], 16))
        extra = f"  [eh_frame fn {cf[0]:#x}+{cf[1]}]" if cf else ""
        mark = "  <== AES fn" if any(int(m['fn_va'], 16) == a for a, _, _ in aes_fns) else ""
        print(f"      {m['name']:<22} {m['sig']:<62} -> {m['fn_va']}{extra}{mark}")

    with open(f"{OUT}/31_arm64_jni_and_aes.json", 'w') as f:
        json.dump({'so': SO, 'size': len(raw),
                   'aes_tables': {'sbox': hex(SBOX_VA), 'isbox': hex(ISBOX_VA), 'rcon': hex(RCON_VA)},
                   'aes_functions': [{'va': hex(a), 'size': s, 'refs': t} for a, s, t in aes_fns],
                   'jni_methods': methods,
                   'function_count': len(fns)}, f, indent=2)
    print(f"\n    wrote {OUT}/31_arm64_jni_and_aes.json")

    # ------------------------------------------------------------------
    print(f"\n--- 6. callers of the AES functions ---")
    aes_addrs = {a for a, _, _ in aes_fns}
    if aes_addrs:
        callers = collections.defaultdict(set)
        for ins in md.disasm(tdata, tbase):
            if ins.mnemonic in ('bl', 'b') and ins.op_str.startswith('#'):
                try:
                    tgt = int(ins.op_str[1:], 0)
                except ValueError:
                    continue
                if tgt in aes_addrs:
                    cf = containing(ins.address)
                    if cf and cf[0] != tgt:
                        callers[cf[0]].add(tgt)
        print(f"    direct branch callers: {len(callers)}")
        for loc in sorted(callers):
            print(f"      fn {loc:#x} -> {[hex(x) for x in sorted(callers[loc])]}")
    else:
        print("    no AES function identified")


if __name__ == '__main__':
    main()
