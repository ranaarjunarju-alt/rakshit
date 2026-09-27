#!/usr/bin/env python3
"""
patch_topfollow.py — deterministic binary patcher for libtopfollow.so (TopFollow v846, arm64-v8a)
==============================================================================================
Purpose : disable the anti-detection checks that block traffic/data capture on a
          NON-ROOTED device (Frida-gadget, inline-hook or modified-APK scenarios).
Method  : every patch forces the CALLER of a detection check onto the already-
          verified "clean" path. The detection function itself still runs
          (all buffer init / side effects preserved) -> no crash, no missing state.
Rules   : pure Python + capstone. Byte-exact: refuses to run unless the original
          4 bytes at every site decode to the exact expected instruction.
Layout  : in this .so, file offset == virtual address for the whole first LOAD
          segment (verified via section table; asserted below).

Patch list (all verified by disassembly, see PATCH_SPEC_v846.md):
  #  VA       before (decoded)                 after            what it disables
  1  0x4c86c  tbz w28,#0,#0x4e15c              b  #0x4e15c      Frida scan #1 (pre-request, x0012e5a1)
  2  0x4e11c  tbz w0,#0,#0x4e15c               b  #0x4e15c      APK-SHA pre-request compare (0x85a4c result)
  3  0x64994  tbz w0,#0,#0x649a8               b  #0x649a8      Frida scan #2 (string-transform path, x0014b4f3)
  4  0x71268  tbnz w24,#0,#0x71408             NOP              delmaps maps-tamper (post-response)
  5  0x72770  tbz w0,#0,#0x72784               b  #0x72784      frida_tokens (post-response)
  6  0x3ff98  tbz w21,#0,#0x3ffd8              b  #0x3ffd8      APK-SHA init compare (returns 0x85ec29 on mismatch)
  7  0xa536c  tbnz w0,#0,#0xa5378              NOP              hooktokens (post-response internal)
  8  0xa5374  tbz w0,#0,#0xa565c               b  #0xa565c      frida_tokens (post-response internal)
  9  0x72f88  tbz w24,#0,#0x730f8              b  #0x730f8      R6/R7 post-response verdict loop -> force clean
 10  0x5f2f8  tbz w0,#0,#0x5f30c               b  #0x5f30c      hooktokens (call site @0x5f2f4)
 11  0xa5ba4  tbz w0,#0,#0xa5370               b  #0xa5370      hooktokens (call site @0xa5ba0)
 12  0x44c60  tbz w0,#0,#0x44c74               b  #0x44c74      frida_tokens (call site @0x44c0c)

NOTE: the signer-pin BLOB itself (data @0x14ce4) is still rewritten by the
      existing resign pipeline (defense in depth); patch #9 covers its
      compare-consumption channel as well. See PATCH_SPEC_v846.md.
"""
import struct, sys, json, hashlib, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

SO_IN  = 'work/v846/apkx/lib/arm64-v8a/libtopfollow.so'
SO_OUT = 'work/v846/apkx/lib/arm64-v8a/libtopfollow_patched.so'
MANIF  = 'work/v846/notes/v846_patch_manifest.json'

# (va, expected_mnemonic, expected_opstr, action, target_or_None, label)
PATCHES = [
    (0x4c86c, 'tbz',  'w28, #0, #0x4e15c', 'b',   0x4e15c, 'frida scan #1 (pre-request) -> force clean'),
    (0x4e11c, 'tbz',  'w0, #0, #0x4e15c',  'b',   0x4e15c, 'APK-SHA pre-request compare -> force clean'),
    (0x64994, 'tbz',  'w0, #0, #0x649a8',  'b',   0x649a8, 'frida scan #2 (string transform) -> force clean'),
    (0x71268, 'tbnz', 'w24, #0, #0x71408', 'nop', None,    'delmaps maps-tamper -> force clean (fallthrough)'),
    (0x72770, 'tbz',  'w0, #0, #0x72784',  'b',   0x72784, 'frida_tokens (post-response) -> force clean'),
    (0x3ff98, 'tbz',  'w21, #0, #0x3ffd8', 'b',   0x3ffd8, 'APK-SHA init compare -> force clean (ret 0)'),
    (0xa536c, 'tbnz', 'w0, #0, #0xa5378',  'nop', None,    'hooktokens (post-response internal) -> force clean'),
    (0xa5374, 'tbz',  'w0, #0, #0xa565c',  'b',   0xa565c, 'frida_tokens (post-response internal) -> force clean'),
    (0x72f88, 'tbz',  'w24, #0, #0x730f8', 'b',   0x730f8, 'R6/R7 post-response verdict (APK-SHA#2 compare + pin channel) -> force clean'),
    (0x5f2f8, 'tbz',  'w0, #0, #0x5f30c',  'b',   0x5f30c, 'hooktokens (call site @0x5f2f4) -> force clean'),
    (0xa5ba4, 'tbz',  'w0, #0, #0xa5370',  'b',   0xa5370, 'hooktokens (call site @0xa5ba0) -> force clean'),
    (0x44c60, 'tbz',  'w0, #0, #0x44c74',  'b',   0x44c74, 'frida_tokens (call site @0x44c0c) -> force clean'),
]
NOP64 = 0xD503201F

def enc_b(target: int, pc: int) -> int:
    """ARM64 unconditional branch: imm26 = (target-pc)/4, signed 26-bit."""
    d = target - pc
    if d % 4 != 0 or not (-2**25 <= d // 4 < 2**25):
        raise ValueError(f"branch out of range: pc={pc:#x} target={target:#x}")
    imm26 = d // 4          # imm26 is stored raw in bits [25:0]; decode applies *4
    return 0x14000000 | (imm26 & 0x3FFFFFF)

def check_layout() -> None:
    """Assert file-offset == VA for the .text section (true for this .so)
    and that every patch site lies inside .text."""
    from elf_dump import elf64
    e = elf64(SO_IN)
    secs = {s['name']: (s['addr'], s['size'], s['off']) for s in e['secs']}
    if '.text' not in secs:
        raise SystemExit(".text not found")
    tva, tsize, toff = secs['.text']
    if tva != toff:
        raise SystemExit(f"layout assumption broken: .text VA {tva:#x} != off {toff:#x}")
    for va, *_ in PATCHES:
        if not (tva <= va < tva + tsize):
            raise SystemExit(f"patch site {va:#x} outside .text")

def main():
    import capstone
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
    raw = bytearray(open(SO_IN, 'rb').read())
    sha_in = hashlib.sha256(bytes(raw)).hexdigest()
    check_layout()  # raises if the ELF layout assumption changed
    manifest = {
        'input': SO_IN,
        'input_sha256': sha_in,
        'input_size': len(raw),
        'output': SO_OUT,
        'patches': [],
    }
    for va, mexp, oexp, act, tgt, label in PATCHES:
        cur = struct.unpack_from('<I', raw, va)[0]
        ins = list(md.disasm(struct.pack('<I', cur), va))
        if len(ins) != 1 or ins[0].mnemonic != mexp or ins[0].op_str != oexp:
            raise SystemExit(
                f"VERIFY FAIL @ {va:#x}: expected '{mexp} {oexp}' "
                f"got '{ins[0].mnemonic} {ins[0].op_str}' (bytes {cur:08x}) — ABORTING, no file written")
        if act == 'b':
            new = enc_b(tgt, va)
            newtext = f"b #{tgt:#x}"
        else:
            new = NOP64
            newtext = "nop"
        struct.pack_into('<I', raw, va, new)
        # verify the new bytes disassemble as intended (and that any 'b' lands on the right target)
        chk = list(md.disasm(struct.pack('<I', new), va))[0]
        if act == 'b':
            import re as _re
            m = _re.search(r'#0x([0-9a-f]+)', chk.op_str)
            if not m or int(m.group(1), 16) != tgt:
                raise SystemExit(f"ENCODE FAIL @ {va:#x}: wrote {new:08x} but it decodes to "
                                 f"'{chk.mnemonic} {chk.op_str}', not 'b #{tgt:#x}'")
        elif not (chk.mnemonic == 'nop'):
            raise SystemExit(f"ENCODE FAIL @ {va:#x}: expected nop, got '{chk.mnemonic} {chk.op_str}'")
        manifest['patches'].append({
            'va': va, 'file_offset': va,
            'before_hex': f'{cur:08x}', 'before_asm': f'{mexp} {oexp}',
            'after_hex': f'{new:08x}', 'after_asm': chk.mnemonic + ' ' + chk.op_str,
            'label': label,
        })
    open(SO_OUT, 'wb').write(bytes(raw))
    manifest['output_sha256'] = hashlib.sha256(bytes(raw)).hexdigest()
    os.makedirs(os.path.dirname(MANIF), exist_ok=True)
    json.dump(manifest, open(MANIF, 'w'), indent=2)
    print(f"OK: {len(PATCHES)} patches applied -> {SO_OUT}")
    for p in manifest['patches']:
        print(f"  {p['va']:07x}  {p['before_asm']:<24s} -> {p['after_asm']:<16s}  {p['label']}")
    print(f"out sha256: {manifest['output_sha256']}")

if __name__ == '__main__':
    main()
