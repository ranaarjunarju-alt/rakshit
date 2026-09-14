#!/usr/bin/env python3
"""
Close the "which JNI native reaches the AES?" gap on the x86 build.

The x86 libtopfollow.so is the ONE ABI whose JNINativeMethod table is stored as
literal VA pointers (imagebase 0), so all 22 natives are known by name, signature
and entry VA.  arm64/x86_64 materialise the table at runtime, so static
attribution is impossible there -- but the three ABIs are compiled from the same
source, so an AES<->JNI edge found on x86 holds for all of them.

Strategy (no PIC-thunk guessing):
  1. functions from .eh_frame FDEs
  2. full call graph from every E8 call / E9 jmp inside each function body
  3. functions that REFERENCE the AES tables, found by the x86 PIC idiom
         call $+5 ; pop reg ; add reg, K   => reg = base
         ... [reg + D] ...                 => base + D
     and by direct rip-less absolute references; a reference lands on a table if
     base+D is within [SBOX, SBOX+256) etc.
  4. backward BFS: which of the 22 JNI entry VAs can reach an AES-referencing fn
"""
import struct, json, sys, collections
import lief, capstone

SO = 'work/apk/lib/x86/libtopfollow.so'
SBOX, ISBOX, RCON = 0x7070, 0x8170, 0x82d0
TABLES = {'SBOX': (SBOX, 256), 'ISBOX': (ISBOX, 256), 'RCON': (RCON, 16)}

raw = open(SO, 'rb').read()
b = lief.parse(SO)
secs = {s.name: s for s in b.sections}
text = secs['.text']
TVA, TSZ, TOFF = text.virtual_address, text.size, text.offset

# ---- 1. functions from .eh_frame_hdr binary-search table --------------------
# (.eh_frame FDE walking is fragile on this build; the hdr table gives the
#  function start VAs directly.  table_enc 0x3b = datarel|sdata4, relative to
#  the eh_frame_hdr VA.)
fns = {}
ehh = secs.get('.eh_frame_hdr')
d = bytes(ehh.content); hbase = ehh.virtual_address
fde_count = struct.unpack('<I', d[8:12])[0]
tbl = d[12:]
starts = []
for k in range(fde_count):
    if (k + 1) * 8 > len(tbl):
        break
    loc = struct.unpack('<i', tbl[k*8:k*8+4])[0]
    starts.append(hbase + loc)
starts.sort()
for a, z in zip(starts, starts[1:] + [TVA + TSZ]):
    fns[a] = max(0, z - a)
print(f"[1] .eh_frame_hdr functions: {len(fns)}  (range {hex(starts[0])}..{hex(starts[-1])})")

# ---- 2+3. disassemble .text once; build call graph + table refs ------------
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
md.detail = True

insn_at = {}
calls = collections.defaultdict(set)      # caller_va -> {callee_va}
# per-instruction we need to know the containing function; sort fn starts
starts = sorted(fns)
import bisect
def fn_of(addr):
    j = bisect.bisect_right(starts, addr) - 1
    if j < 0: return None
    st = starts[j]
    sz = fns[st]
    if sz == 0 or addr < st + max(sz, 0x400):
        return st
    return st

# PIC base tracking: call $+5 / pop reg / add reg,imm  => base
pic_base = {}     # (fn, reg) -> base   (last wins within a fn)
tabrefs = collections.defaultdict(set)   # table -> {fn_va}
tabref_detail = collections.defaultdict(list)

code = bytes(raw[TOFF:TOFF+TSZ])
prev = {}          # reg -> last known base within current fn
cur_fn = None
last_call5 = None  # addr of instruction after `call $+5`
for ins in md.disasm(code, TVA):
    f = fn_of(ins.address)
    if f != cur_fn:
        cur_fn = f; prev = {}
    m = ins.mnemonic; ops = ins.op_str
    if m == 'call' and ops.startswith('0x'):
        tgt = int(ops, 16)
        if tgt == ins.address + ins.size:     # call $+5  (PIC thunk)
            last_call5 = ins.address + ins.size
        elif TVA <= tgt < TVA+TSZ and f is not None:
            calls[f].add(tgt)
    elif m == 'jmp' and ops.startswith('0x'):
        tgt = int(ops, 16)
        if TVA <= tgt < TVA+TSZ and f is not None:
            calls[f].add(tgt)
    elif m == 'pop' and last_call5 is not None and ops in ('ebx','eax','ecx','edx','esi','edi','ebp'):
        prev[ops] = last_call5
        last_call5 = None
    elif m == 'add' and ',' in ops:
        a, bb = [x.strip() for x in ops.split(',', 1)]
        if a in prev and bb.startswith('0x'):
            prev[a] = (prev[a] + int(bb, 16)) & 0xFFFFFFFF
    # any memory operand [reg + disp] where reg has a tracked base
    if '[' in ops:
        for reg, base in prev.items():
            tok = f'{reg} +'
            tok2 = f'{reg} -'
            idx = ops.find(f'[{reg}')
            if idx == -1: continue
            sub = ops[idx:]
            disp = 0
            if '+' in sub.split(']')[0]:
                try: disp = int(sub.split('+')[1].split(']')[0].strip(), 0)
                except Exception: disp = 0
            eff = (base + disp) & 0xFFFFFFFF
            for tn, (tva, tlen) in TABLES.items():
                if tva <= eff < tva + tlen:
                    if f is not None:
                        tabrefs[tn].add(f)
                        tabref_detail[tn].append((hex(ins.address), ins.mnemonic+' '+ins.op_str, hex(eff), hex(f)))

print("[3] functions referencing AES tables (x86 PIC idiom):")
for tn in TABLES:
    print(f"    {tn:<6}: {sorted(hex(x) for x in tabrefs[tn])}")

# ---- 4. JNI entries --------------------------------------------------------
jni = json.load(open('work/out/35_x86_jni_full.json'))
jni_va = {int(r['fn_va'], 16): (r['name'], r['signature']) for r in jni}

# reverse call graph
rev = collections.defaultdict(set)
for c, ts in calls.items():
    for t in ts: rev[t].add(c)

def ancestors(seed):
    seen, stack = {seed}, [seed]
    while stack:
        nxt = []
        for f in stack:
            for c in rev.get(f, ()):
                if c not in seen: seen.add(c); nxt.append(c)
        stack = nxt
    return seen

aes_fns = set()
for tn in tabrefs: aes_fns |= tabrefs[tn]
print(f"\n[4] AES-referencing x86 functions: {sorted(hex(x) for x in aes_fns)}")
all_anc = set()
for a in aes_fns: all_anc |= ancestors(a)
print(f"    total ancestors (any depth): {len(all_anc)}")

print("\n[5] JNI natives that reach the AES:")
hit = 0
for va, (nm, sg) in sorted(jni_va.items()):
    if va in all_anc or va in aes_fns:
        hit += 1
        print(f"    USES-AES  {nm:<12} {va:#08x}  {sg}")
if hit == 0:
    print("    none of the 22 JNI natives reach an AES-referencing function")
    print("    => the AES is internal-only on x86 as well (consistent with CRYP-09)")

json.dump({
    'abi': 'x86', 'eh_frame_functions': len(fns),
    'table_refs': {k: sorted(hex(x) for x in v) for k, v in tabrefs.items()},
    'aes_functions': sorted(hex(x) for x in aes_fns),
    'ancestors': sorted(hex(x) for x in all_anc),
    'jni_reaching_aes': [jni_va[va][0] for va in jni_va if va in all_anc],
    'ref_detail': {k: v[:40] for k, v in tabref_detail.items()},
}, open('work/out/36_x86_aes_jni.json', 'w'), indent=2)
print("\nwrote work/out/36_x86_aes_jni.json")
