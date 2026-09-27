#!/usr/bin/env python3
"""Stage 3: string -> function xref map for v846 (ADRP+ADD resolver).
For every important string, which function(s) reference it."""
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

xref = collections.defaultdict(set)   # rodata VA -> {fn}
adrp = {}
# also record call targets per function (blr xN after mov xN, #va / adrp+add pattern)
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

def cstr(off, maxlen=300):
    end = raw.find(b'\x00', off, off+maxlen)
    s = raw[off:end if end > 0 else off+maxlen]
    try: return s.decode('ascii') if all(32 <= c < 127 for c in s) else None
    except Exception: return None

def refs(off):
    fs = set()
    for dlt in range(0, 16):
        fs |= xref.get(off + dlt, set())
    return sorted(fs)

def cstr_refs(needle, maxlen=400):
    out = []
    i = 0
    while True:
        i = raw.find(needle, i)
        if i < 0: break
        s = cstr(i, maxlen)
        if s is not None:
            out.append((i, s, refs(i)))
        i += 1
    return out

def show(label, needle):
    hits = cstr_refs(needle)
    print(f'--- {label}: {needle!r} ---')
    for off, s, fs in hits:
        for f in fs:
            print(f'    @{off:#08x}  fn {f:#x} (size {fn_span(f)})  str {s[:60]!r}')
        if not fs:
            print(f'    @{off:#08x}  <no fn refs found>  str {s[:60]!r}')
    if not hits:
        print('    <not found>')
    return hits

print(f'functions: {len(fnstarts)}')
show('JNI class helper/q', b'com/nivaroid/topfollow/helper/q')
show('JNI class helper/T', b'com/nivaroid/topfollow/helper/T')
show('plain key', b'0123456789abcdef')
show('b64 alphabet', b'qHaAk?ABCDEF')
show('pin blob', b'WkRnME5UVTVNV1V3T0RZd016TmhPVEF6Tldaa05tSTJObU16WXpOa056TmhZVE16WVdZNU1EYzVOR1Ey')
show('check.php url (xor55)', bytes(c ^ 0x55 for c in b'https://nivafollower-app.com/api-v3/topfollow_check.php'))
show('packed urls (xor55)', bytes(c ^ 0x55 for c in b'friendships/create/media'))
show('su paths (xor5a)', bytes(c ^ 0x5A for c in b'/system/app/Superuser.apk'))
show('hook blob (xor5a)', bytes(c ^ 0x5A for c in b'/proc/self/maps'))
show('frida blob (xor37)', bytes(c ^ 0x37 for c in b'gum-js-loop'))
show('b64 frida', b're.frida.server')
show('b64 gum', b'gum-js-loop')
show('b64 gadget', b'libfrida-gadget')
show('b64 maps', b'/proc/self/maps')
show('b64 libart deleted', b'libart.so (deleted)')
show('b64 libc deleted', b'libc.so (deleted)')
show('native name 1', b'x00105e9b')
show('native name 22', b'x0018d3f7')
show('RegisterNatives', b'RegisterNatives')
show('FindClass', b'FindClass')
show('getPackageInfo', b'getPackageInfo')
show('signatures', b'signatures')
show('MessageDigest', b'MessageDigest')
show('CertificatePinner', b'okhttp3/CertificatePinner')
show('SHA-256', b'SHA-256')
show('digest', b'digest')
show('AES', b'AES')
