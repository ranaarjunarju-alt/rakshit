#!/usr/bin/env python3
"""Stage 3b: xref for XOR-ciphertext blobs + AES tables (no ASCII requirement)."""
import re, struct, sys, bisect, collections
sys.path.insert(0, 'work/v846')
from elf_dump import elf64
import capstone

SO = 'work/v846/extract/lib/arm64-v8a/libtopfollow.so'
e = elf64(SO)
raw = e['raw']
secs = {s['name']: (s['addr'], s['size'], s['off']) for s in e['secs']}
TVA, TSZ, TOFF = secs['.text']

EH = secs['.eh_frame_hdr']
d = raw[EH[2]:EH[2]+EH[1]]
fc = struct.unpack('<I', d[8:12])[0]
tbl = d[12:]
fnstarts = sorted(set(EH[0] + struct.unpack('<i', tbl[k*8:k*8+4])[0]
                      for k in range(fc) if (k+1)*8 <= len(tbl)))

def fn_of(a):
    j = bisect.bisect_right(fnstarts, a) - 1
    return fnstarts[j] if j >= 0 else None

def fn_span(fn):
    i = fnstarts.index(fn)
    end = fnstarts[i+1] if i+1 < len(fnstarts) else fn + 0x2000
    return end - fn

md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
md.detail = True
xref = collections.defaultdict(set)
adrp = {}
for ins in md.disasm(raw[TOFF:TOFF+TSZ], TVA):
    if ins.mnemonic == 'adrp':
        reg = ins.op_str.split(',')[0]
        try: adrp[reg] = int(ins.op_str.split('#')[1], 0)
        except Exception: pass
    elif ins.mnemonic in ('add', 'ldr', 'str') and '#' in ins.op_str:
        m = re.search(r'\[(x\d+)\]\s*\+\s*#(0x[0-9a-fA-F]+|\d+)', ins.op_str)
        if m:
            src, imm = m.group(1), m.group(2)
        else:
            m2 = re.fullmatch(r'\s*(x\d+)\s*,\s*(x\d+)\s*,\s*#(0x[0-9a-fA-F]+|\d+)', ins.op_str)
            if not m2: continue
            src, imm = m2.group(2), m2.group(3)
        if src in adrp:
            try:
                target = adrp[src] + int(imm, 0)
                f = fn_of(ins.address)
                if f is not None: xref[target].add(f)
            except Exception: pass

def refs(off):
    fs = set()
    for dlt in range(0, 16):
        fs |= xref.get(off + dlt, set())
    return sorted(fs)

def show_off(label, off):
    fs = refs(off)
    print(f'--- {label} @{off:#08x} ---')
    for f in fs:
        print(f'    fn {f:#x} (size {fn_span(f)})')
    if not fs:
        print('    <no fn refs>')

def show_bytes(label, needle, lo=0x11000, hi=0x1a800):
    i = raw.find(needle, lo)
    if i < 0 or i > hi:
        print(f'--- {label} <not found in .rodata> ---')
        return
    show_off(label, i)

X55 = lambda s: bytes(c ^ 0x55 for c in s.encode())
X5A = lambda s: bytes(c ^ 0x5A for c in s.encode())
X37 = lambda s: bytes(c ^ 0x37 for c in s.encode())

show_bytes('check.php url (ciphertext x55)', X55('https://nivafollower-app.com/api-v3/topfollow_check.php'))
show_bytes('packed instagram urls (ciphertext x55)', X55('friendships/create/media'))
show_bytes('su paths packed (ciphertext x5a)', X5A('/system/app/Superuser.apk'))
show_bytes('hook tokens packed (ciphertext x5a)', X5A('/proc/self/maps'))
show_bytes('frida tokens packed (ciphertext x37)', X37('gum-js-loop'))
show_bytes('b64(re.frida.server)', b64b if (b64b := b'cmUuZnJpZGEuc2VydmVy') else b'')
show_bytes('b64(gum-js-loop)', b'Z3VtLWpzLWxvb3A=')
show_bytes('b64(libfrida-gadget)', b'bGJiZnJpZGEtZ2FkZ2V0')
show_bytes('b64(/proc/self/maps)', b'L3Byb2Mvc2VsZi9tYXBz')
show_bytes('b64(libart.so (deleted))', b'bGliYXJ0LnNvIChkZWxldGVkKQ==')
show_bytes('b64(libc.so (deleted))', b'bGlicy5zbyAoZGVsZXRlZCk9')
show_bytes('b64(libbridge.so)', b'bGliaHJpZGdlLnNv')
show_bytes('b64(libcso_substrate)', b'bGljc29fc3Vic3RyYXRl')
show_bytes('b64(substrate)', b's3Vic3RyYXRl')
show_bytes('b64(lsposed)', b'bnNwb3NlZA==')
show_bytes('b64(xposed)', b'eHBvc2Vk')
show_bytes('b64(edxposed)', b'ZWR4cG9zZWQ=')
show_bytes('pin blob', b'WkRnME5UVTVNV1V3T0RZd016TmhPVEF6Tldaa05tSTJObU16WXpOa056TmhZ')
show_bytes('plain key 16', b'0123456789abcdef')
show_bytes('key32 charset', b'0123456789abcdefABCDEFxX+-pPiInN')
show_bytes('b64 alphabet (plain)', b'qHaAk?ABCDEFGHIJKLMNOPQRSTUVWXYZ')
print()
print('--- AES Te0 table @0x11510 ---')
show_off('Te0', 0x11510)
print('--- AES Td0 table @0x12610 ---')
show_off('Td0', 0x12610)
print('--- Sbox @0x12510 ---')
show_off('Sbox', 0x12510)
print('--- RSbox @0x13610 ---')
show_off('RSbox', 0x13610)
