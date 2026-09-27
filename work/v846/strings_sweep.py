#!/usr/bin/env python3
"""v846 string sweep: single-byte XOR (0x55 / 0x5A) over libtopfollow.so,
filtered to meaningful runs, cross-referenced to functions via ADRP+ADD
resolution (same methodology as work/native_string_decrypt.py, lief-free)."""
import re, base64, collections, json, struct, sys, bisect
sys.path.insert(0, 'work/v846')
from elf_dump import elf64
import capstone

SO = 'work/v846/extract/lib/arm64-v8a/libtopfollow.so'
e = elf64(SO)
raw = e['raw']
secs = {s['name']: (s['addr'], s['size'], s['off']) for s in e['secs']}
RO_VA, RO_SZ, _ = secs['.rodata']
TVA, TSZ, TOFF = secs['.text']

def sweep(key, minlen=5):
    dec = bytes(x ^ key for x in raw)
    return [(m.start(), m.group().decode('latin1')) for m in re.finditer(rb'[ -~]{%d,}' % minlen, dec)]

KEYWORDS = ['http', 'api', '.php', 'topfollow', 'niva', 'instagram', '/v1/', '/v8',
            'frida', 'Frida', 'magisk', 'Magisk', 'xposed', 'Xposed', 'root',
            'zygisk', 'Zygisk', 'shamiko', 'riru', 'Riru', 'substrate', 'Substrate',
            'EdXposed', 'LSPosed', 'bridge', 'deleted', 'rwxp', 'TracerPid', 'ptrace',
            'emulator', 'Emulator', 'goldfish', 'qemu', 'nox', 'Nox', 'generic',
            'sha256', 'SHA-256', 'certificatePinner', 'ANDROID_ID', 'DeviceModel',
            'getPackageInfo', 'signatures', 'MessageDigest', '6Ld3', 'sitekey',
            'captcha', 'Captcha', 'recaptcha', 'hCaptcha', 'Bearer', 'IGT:',
            'signed_body', 'device', 'Device', 'nonce', 'Nonce', 'hash', 'Hash',
            'su', '/su', 'magisk', 'busybox', 'supersu', '/system/app', 'adb']

def interesting(s):
    return any(k in s for k in KEYWORDS)

results = {}
for key in (0x55, 0x5A):
    hits = sweep(key)
    keep, seen = [], set()
    for off, s in hits:
        s = s.strip()
        if len(s) < 5 or not interesting(s):
            continue
        if not (RO_VA - 0x2000 <= off < RO_VA + RO_SZ + 0x40000):
            continue
        if s in seen:
            continue
        seen.add(s)
        keep.append((off, s))
    results[key] = keep

def classify(s):
    if s.startswith('http') or '://' in s: return 'URL'
    if s.endswith('.php') or (s.startswith('/') and len(s) > 3): return 'endpoint'
    if re.match(r'^6L[0-9A-Za-z_-]{10,}', s): return 'recaptcha-sitekey'
    if re.match(r'^[0-9a-f]{32,}$', s): return 'uuid/hash'
    if s.startswith('(') and ('L' in s or ')' in s): return 'JNI-signature'
    if any(k in s for k in ['frida','Frida','magisk','Magisk','xposed','Xposed','root','zygisk','Zygisk','shamiko','riru','substrate','bridge','deleted','rwxp','TracerPid','ptrace','emulator','goldfish','qemu','nox','/su','supersu','busybox']): return 'detection-keyword'
    if any(k in s for k in ['sha256','SHA-256','certificatePinner','MessageDigest','signatures','getPackageInfo']): return 'integrity'
    if any(k in s for k in ['ANDROID_ID','DeviceModel','device','Device','nonce','Nonce','hash','Hash','signed_body','Bearer','IGT:']): return 'device/token'
    if any(k in s for k in ['captcha','Captcha','sitekey']): return 'captcha'
    return 'other'

# ---- function starts from .eh_frame_hdr FDE table ----
EH = secs['.eh_frame_hdr']
fnstarts = []
d = raw[EH[2]:EH[2]+EH[1]]
fc = struct.unpack('<I', d[8:12])[0]
tbl = d[12:]
for k in range(fc):
    if (k+1)*8 <= len(tbl):
        fnstarts.append(EH[0] + struct.unpack('<i', tbl[k*8:k*8+4])[0])
fnstarts = sorted(set(fnstarts))
def fn_of(a):
    j = bisect.bisect_right(fnstarts, a) - 1
    return fnstarts[j] if j >= 0 else None
print(f'# eh_frame_hdr functions: {len(fnstarts)}  .rodata [{RO_VA:#x},{RO_VA+RO_SZ:#x})  .text [{TVA:#x},{TVA+TSZ:#x})')

# ---- ADRP+ADD xref ----
md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
md.detail = True
xref = collections.defaultdict(set)
code = raw[TOFF:TOFF+TSZ]
adrp = {}
n_ins = 0
for ins in md.disasm(code, TVA):
    n_ins += 1
    if ins.mnemonic == 'adrp':
        reg = ins.op_str.split(',')[0]
        try: adrp[reg] = int(ins.op_str.split('#')[1], 0)
        except Exception: pass
    elif ins.mnemonic == 'add' and '#' in ins.op_str and ins.op_str.startswith('x'):
        parts = ins.op_str.split(',')
        m = re.search(r'\[(x\d+)\]\s*\+\s*#(0x[0-9a-fA-F]+|\d+)', ins.op_str)
        m2 = re.fullmatch(r'\s*(x\d+)\s*,\s*(x\d+)\s*,\s*#(0x[0-9a-fA-F]+|\d+)', ins.op_str)
        if m2:
            srcreg = m2.group(2)
            if srcreg in adrp:
                try:
                    target = adrp[srcreg] + int(m2.group(3), 0)
                    f = fn_of(ins.address)
                    if f is not None: xref[target].add(f)
                except Exception: pass
    elif ins.mnemonic == 'ldr' and '#' in ins.op_str:
        m = re.search(r'\[(x\d+)\]\s*\+\s*#(0x[0-9a-fA-F]+|\d+)', ins.op_str)
        if m:
            srcreg = m.group(1)
            if srcreg in adrp:
                try:
                    target = adrp[srcreg] + int(m.group(2), 0)
                    f = fn_of(ins.address)
                    if f is not None: xref[target].add(f)
                except Exception: pass
print(f'# disassembled {n_ins} instructions; xref targets: {len(xref)}')

def refs_for(off):
    fs = set()
    for delta in range(0, 12):
        fs |= xref.get(off + delta, set())
    return sorted(fs)

# ---- emit ----
lines = []
lines.append("=== v846 NATIVE STRING DECRYPTION (libtopfollow.so, arm64-v8a) ===")
lines.append(f"  file {len(raw):,} bytes; .rodata VA [{RO_VA:#x},{RO_VA+RO_SZ:#x})")
allrows = []
for key in (0x55, 0x5A):
    lines.append(f"\n########## XOR KEY {key:#x} ##########")
    cat = collections.Counter()
    for off, s in results[key]:
        cat[classify(s)] += 1
    lines.append(f"  {len(results[key])} distinct interesting strings; categories: {dict(cat)}")
    lines.append(f"\n  {'offset':<10} {'category':<18} {'xref-fns':<28} string")
    lines.append("  " + "-"*110)
    for off, s in results[key]:
        c = classify(s)
        fs = refs_for(off)
        xs = ','.join(hex(x) for x in fs[:3]) + ('...' if len(fs) > 3 else '')
        disp = s if len(s) <= 76 else s[:76]+'...'
        lines.append(f"  {off:#010x} {c:<18} {xs:<28} {disp!r}")
        allrows.append({'key': hex(key), 'offset': hex(off), 'category': c,
                        'xref': [hex(x) for x in fs], 'string': s})
txt = "\n".join(lines)
open('work/v846/notes/v846_decrypted_strings.txt','w').write(txt)
json.dump(allrows, open('work/v846/notes/v846_decrypted_strings.json','w'), indent=1)
print(txt[:9000])
print(f"\n... wrote work/v846/notes/v846_decrypted_strings.txt ({len(allrows)} rows)")
