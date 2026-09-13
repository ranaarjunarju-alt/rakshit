#!/usr/bin/env python3
"""
The REAL "string decryptor" of libtopfollow.so, run statically.

There is no native sub_128A0 blob-decryptor (0x128a0 is .rodata data 16 bytes
before the AES S-box, not code). Strings are protected with a single-byte XOR
(keys 0x55 and 0x5A) plus, for a few, nested base64. This script sweeps both
keys over the whole file, keeps meaningful runs, de-duplicates, classifies them
(URL / endpoint / key / detection-keyword / JNI-signature / other), and resolves
which functions reference each via the per-function ADRP+ADD resolver.

Output: work/out/43_native_decrypted_strings.txt  (the genuine
"unicorn_decrypted_strings.txt" equivalent -- these are the strings the app
decrypts at runtime, recovered without a device).
"""
import sys, re, base64, collections, json
import lief, capstone

SO = 'work/apk/lib/arm64-v8a/libtopfollow.so'
raw = open(SO, 'rb').read()
b = lief.parse(SO)
secs = {s.name: (s.virtual_address, s.size, s.offset) for s in b.sections}
RO_VA, RO_SZ, _ = secs['.rodata']

def sweep(key, minlen=5):
    dec = bytes(x ^ key for x in raw)
    out = []
    for m in re.finditer(rb'[ -~]{%d,}' % minlen, dec):
        out.append((m.start(), m.group().decode('latin1')))
    return out

# ---- collect candidate secrets from both keys ----
KEYWORDS = ['http', 'api', '.php', 'topfollow', 'niva', 'instagram', '/v1/', '/v8',
            'frida', 'Frida', 'magisk', 'Magisk', 'su', 'xposed', 'Xposed', 'root',
            'zygisk', 'Zygisk', 'shamiko', 'riru', 'Riru', 'substrate', 'Substrate',
            'EdXposed', 'LSPosed', 'bridge', 'deleted', 'rwxp', 'TracerPid', 'ptrace',
            'emulator', 'Emulator', 'goldfish', 'qemu', 'nox', 'Nox', 'generic',
            'sha256', 'SHA-256', 'certificatePinner', 'ANDROID_ID', 'DeviceModel',
            'getPackageInfo', 'signatures', 'MessageDigest', '6Ld3', 'sitekey',
            'captcha', 'Captcha', 'recaptcha', 'hCaptcha', 'Bearer', 'IGT:',
            'signed_body', 'device', 'Device', 'nonce', 'Nonce', 'hash', 'Hash']

def interesting(s):
    return any(k in s for k in KEYWORDS)

results = {}
for key in (0x55, 0x5A):
    hits = sweep(key)
    keep = []
    seen = set()
    for off, s in hits:
        s = s.strip()
        if len(s) < 5 or not interesting(s):
            continue
        # only keep runs that land in/near .rodata (the real string table region)
        if not (RO_VA - 0x2000 <= off < RO_VA + RO_SZ + 0x40000):
            continue
        if s in seen:
            continue
        seen.add(s)
        keep.append((off, s))
    results[key] = keep

# ---- classify ----
def classify(s):
    if s.startswith('http') or '://' in s: return 'URL'
    if s.endswith('.php') or s.startswith('/'): return 'endpoint'
    if re.match(r'^6L[0-9A-Za-z_-]{10,}', s): return 'recaptcha-sitekey'
    if re.match(r'^[0-9a-f]{32,}$', s): return 'uuid/hash'
    if s.startswith('(') and ('L' in s or ')' in s): return 'JNI-signature'
    if any(k in s for k in ['frida','Frida','magisk','Magisk','su','xposed','Xposed','root','zygisk','Zygisk','shamiko','riru','substrate','bridge','deleted','rwxp','TracerPid','ptrace','emulator','goldfish','qemu','nox']): return 'detection-keyword'
    if any(k in s for k in ['sha256','SHA-256','certificatePinner','MessageDigest','signatures','getPackageInfo']): return 'integrity'
    if any(k in s for k in ['ANDROID_ID','DeviceModel','device','Device','nonce','Nonce','hash','Hash','signed_body','Bearer','IGT:']): return 'device/token'
    if any(k in s for k in ['captcha','Captcha','sitekey']): return 'captcha'
    return 'other'

# ---- per-function ADRP+ADD resolver (arm64) for cross-refs ----
md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
md.detail = True
TVA, TSZ, TOFF = secs['.text']
# function starts from .eh_frame_hdr
ehh = [s for s in b.sections if s.name == '.eh_frame_hdr']
fnstarts = []
if ehh:
    import struct
    d = bytes(ehh[0].content); hb = ehh[0].virtual_address
    fc = struct.unpack('<I', d[8:12])[0]; tbl = d[12:]
    for k in range(fc):
        if (k+1)*8 <= len(tbl):
            fnstarts.append(hb + struct.unpack('<i', tbl[k*8:k*8+4])[0])
fnstarts = sorted(set(fnstarts))
import bisect
def fn_of(a):
    j = bisect.bisect_right(fnstarts, a) - 1
    return fnstarts[j] if j >= 0 else None

# build map: rodata VA -> referencing functions (ADRP+ADD pairs)
xref = collections.defaultdict(set)
code = raw[TOFF:TOFF+TSZ]
adrp = {}   # reg -> page base
for ins in md.disasm(code, TVA):
    if ins.mnemonic == 'adrp':
        reg = ins.op_str.split(',')[0]
        try: adrp[reg] = int(ins.op_str.split('#')[1], 0)
        except Exception: pass
    elif ins.mnemonic in ('add', 'ldr') and '#' in ins.op_str:
        parts = ins.op_str.split(',')
        if len(parts) >= 2:
            src = parts[1].strip() if ins.mnemonic=='add' else parts[-1].strip()
            m = re.search(r'\[(x\d+)', ins.op_str)
            srcreg = m.group(1) if m else None
            imm = re.search(r'#(0x[0-9a-fA-F]+|\d+)', ins.op_str.split(']')[-1] if ins.mnemonic=='ldr' else ins.op_str)
            if srcreg in adrp and imm:
                try:
                    target = adrp[srcreg] + int(imm.group(1), 0)
                    f = fn_of(ins.address)
                    if f is not None: xref[target].add(f)
                except Exception: pass

def refs_for(off):
    fs = set()
    for delta in range(0, 8):
        fs |= xref.get(off + delta, set())
    return sorted(fs)

# ---- emit ----
lines = []
lines.append("=== NATIVE STRING DECRYPTION (libtopfollow.so, arm64-v8a) ===")
lines.append(f"  file {len(raw):,} bytes; .rodata VA [{RO_VA:#x},{RO_VA+RO_SZ:#x})")
lines.append("  method: single-byte XOR sweep (keys 0x55, 0x5A) over the whole file,")
lines.append("  filtered to meaningful runs in the .rodata string-table region,")
lines.append("  cross-referenced to functions via per-function ADRP+ADD resolution.")
lines.append("  NOTE: there is NO native sub_128A0 blob-decryptor; 0x128a0 is .rodata")
lines.append("  data 16 bytes before the AES S-box (0x128b0), not executable code.")
lines.append("")
allrows = []
for key in (0x55, 0x5A):
    lines.append(f"\n########## XOR KEY {key:#x} ##########")
    cat = collections.Counter()
    for off, s in results[key]:
        c = classify(s)
        cat[c] += 1
    lines.append(f"  {len(results[key])} distinct interesting strings; categories: {dict(cat)}")
    lines.append(f"\n  {'offset':<10} {'category':<18} {'xref-fn':<12} string")
    lines.append("  " + "-"*100)
    for off, s in results[key]:
        c = classify(s)
        fs = refs_for(off)
        xs = (hex(fs[0]) if fs else '-')
        disp = s if len(s) <= 72 else s[:72]+'...'
        lines.append(f"  {off:#010x} {c:<18} {xs:<12} {disp!r}")
        allrows.append({'key': hex(key), 'offset': hex(off), 'category': c,
                        'xref': [hex(x) for x in fs], 'string': s})
txt = "\n".join(lines)
open('work/out/43_native_decrypted_strings.txt','w').write(txt)
json.dump(allrows, open('work/out/43_native_decrypted_strings.json','w'), indent=1)
print(txt[:6000])
print(f"\n... wrote work/out/43_native_decrypted_strings.txt ({len(allrows)} rows)")
