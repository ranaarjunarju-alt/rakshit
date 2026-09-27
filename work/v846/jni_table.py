#!/usr/bin/env python3
"""Stage 4: disassemble JNI_OnLoad (v846 @0x3f4d8) and recover the
RegisterNatives table (name, sig, fnptr) for the 22 natives."""
import re, struct, sys
sys.path.insert(0, 'work/v846')
from elf_dump import elf64
import capstone

SO = 'work/v846/extract/lib/arm64-v8a/libtopfollow.so'
e = elf64(SO)
raw = e['raw']
secs = {s['name']: (s['addr'], s['size'], s['off']) for s in e['secs']}
RO_VA = 0x11510
JNI = 0x3f4d8
JNISZ = 2304

def cstr(va, maxlen=300):
    end = raw.find(b'\x00', va, va+maxlen)
    s = raw[va:end if end > 0 else va+maxlen]
    try: return s.decode('ascii') if all(32 <= c < 127 for c in s) else None
    except Exception: return None

md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
md.detail = True
code = raw[JNI:JNI+JNISZ]

# First: find ADRP+ADD to .rodata (string/const loads) within JNI_OnLoad
adrp = {}
events = []
for ins in md.disasm(code, JNI):
    a = ins.address
    if ins.mnemonic == 'adrp':
        reg = ins.op_str.split(',')[0]
        try:
            base = int(ins.op_str.split('#')[1], 0)
            adrp[reg] = base
            events.append((a, 'adrp', ins.op_str))
        except Exception: pass
    elif ins.mnemonic in ('add','ldr') and '#' in ins.op_str:
        m = re.search(r'\[(x\d+)\]\s*\+\s*#(0x[0-9a-fA-F]+|\d+)', ins.op_str)
        if m:
            src, imm = m.group(1), m.group(2)
        else:
            m2 = re.fullmatch(r'\s*(x\d+)\s*,\s*(x\d+)\s*,\s*#(0x[0-9a-fA-F]+|\d+)', ins.op_str)
            if not m2: continue
            src, imm = m2.group(2), m2.group(3)
        if src in adrp:
            tgt = adrp[src] + int(imm, 0)
            s = cstr(tgt) if RO_VA - 0x4000 <= tgt < RO_VA + 0x20000 else None
            events.append((a, ins.mnemonic, f'{ins.op_str}  -> {tgt:#x}' + (f'  "{s}"' if s else '')))
    elif ins.mnemonic in ('bl','blr'):
        events.append((a, ins.mnemonic, ins.op_str))
    elif ins.mnemonic == 'mov' and 'x' in ins.op_str:
        m = re.fullmatch(r'\s*(x\d+|w\d+)\s*,\s*(0x[0-9a-fA-F]+|\d+)', ins.op_str)
        if m and int(m.group(2),0) > 0x10000:
            events.append((a, 'mov', ins.op_str))

print(f"=== JNI_OnLoad @ {JNI:#x} : string/const refs + calls ===")
for a, mn, op in events:
    if mn in ('add','ldr') and ('->' in op) or mn=='adrp' or mn in ('bl','blr'):
        print(f"  {a:#08x} {mn:4s} {op}")

# Now: the RegisterNatives table. It is a contiguous array of 22 JNINativeMethod
# structs: { const char* name; const char* sig; void* fnPtr; } (24 bytes each).
# The fnPtr values point into .text. Find where 22 struct fnPtrs point to valid .text
# and the name pointers point to the x00... strings.
NAMES = ["x00105e9b","x0010e27f","x00113f7a","x0011a4c2","x0011e28b","x0011f1a2",
         "x0011f42b","x00120b1e","x00126f7c","x0012d3e0","x0012e5a1","x0012f5b7",
         "x00135e2a","x0014b4f3","x0014c1f9","x0014e2e9","x0015a3b7","x0015b1e9",
         "x0015e49c","x0016d3b9","x0017b62c","x0018d3f7"]
name_off = {n: raw.find(n.encode()+b'\x00') for n in NAMES}
TVA, TSZ = secs['.text'][0], secs['.text'][1]
def in_text(va): return TVA <= va < TVA+TSZ

# scan .rodata for the table: 22 consecutive 24-byte records where
#   *(p) = name VA (points at x00 string), *(p+8)=sig VA (rodata), *(p+16)=fnptr (text)
# The name pointers in the table point to the .rodata copy of the x00 strings.
# Find, for each name string offset, pointer-sized slots equal to that VA.
cand = []
for n, off in name_off.items():
    va = off  # file off == va in rodata (rodata in first load seg? verify)
    # rodata is in the first LOAD (off==vaddr) so VA == file offset here
    target = struct.pack('<Q', va)
    i = 0
    while True:
        i = raw.find(target, i)
        if i < 0: break
        cand.append((i, n, va))
        i += 8
# A table base B has 22 entries; entry k at B+24k has name@B+24k, fn@B+24k+16.
# So the 22 name-slot file offsets should be B+24k for k=0..21 (an arithmetic
# progression with step 24).
from collections import defaultdict
by_slot = {}
for i, n, va in cand:
    by_slot.setdefault(i, []).append((n, va))
# group by base = i - 24k where (i - 24k) >= 0 and all 22 present
found = []
for slot, lst in by_slot.items():
    k = slot % 24
    base = slot - k
    if base < 0: continue
    present = set()
    ok = True
    for k2 in range(22):
        s2 = base + 24*k2
        if s2 in by_slot:
            present.add(by_slot[s2][0][0])
    if len(present) == 22:
        found.append(base)
print()
print(f"=== candidate RegisterNatives table bases (file offset) : {found} ===")
for base in found:
    print(f"\n  table @ file {base:#x} (VA {base:#x})")
    for k2 in range(22):
        s = base + 24*k2
        nva = struct.unpack('<Q', raw[s:s+8])[0]
        sva = struct.unpack('<Q', raw[s+8:s+16])[0]
        fva = struct.unpack('<Q', raw[s+16:s+24])[0]
        nm = cstr(nva, 20) if RO_VA-0x4000 <= nva < RO_VA+0x20000 else '?'
        sg = cstr(sva, 60) if RO_VA-0x4000 <= sva < RO_VA+0x20000 else '?'
        print(f"    [{k2:2d}] name={nm:12s} fn={fva:#010x}{'  (in .text)' if in_text(fva) else '  <-- NOT text'}  sig={sg}")
