#!/usr/bin/env python3
"""v846: recursive base64 corpus decode over .rodata + 0x37 packed-blob sweep.
Mirrors the v845 methodology (report §5.2 / §5.1)."""
import re, base64, sys, binascii

raw = open('work/v846/extract/lib/arm64-v8a/libtopfollow.so','rb').read()
RO_LO, RO_HI = 0x11510, 0x1a76b

def decode_b64(s):
    try:
        if len(s) % 4: s += '=' * (4 - len(s) % 4)
        d = base64.b64decode(s, validate=True)
        return d
    except Exception:
        return None

def looks_meaningful(b):
    if not b or len(b) < 4:
        return False
    if all(32 <= c < 127 for c in b):
        s = b.decode()
        return bool(re.search(r'[a-z]{3,}', s))
    return False

rows = []
seen = set()
# 1) base64-looking runs in .rodata window
for m in re.finditer(rb'[A-Za-z0-9+/]{8,}={0,2}', raw):
    off = m.start()
    if not (RO_LO - 0x200 <= off < RO_HI + 0x40000):
        continue
    s = m.group().decode()
    cur = s
    layers = 0
    out = None
    while layers < 4:
        d = decode_b64(cur)
        if d is None:
            break
        layers += 1
        if looks_meaningful(d):
            try:
                txt = d.decode('ascii')
            except Exception:
                break
            if re.search(r'[a-z]{3,}', txt):
                out = (layers, txt)
                break
            # if it's another base64 layer, keep going
            if re.fullmatch(r'[A-Za-z0-9+/=]+', txt):
                cur = txt
                continue
        else:
            break
    if out:
        key = (off, out[1])
        if key not in seen:
            seen.add(key)
            rows.append((off, out[0], out[1]))

rows.sort()
print("=== v846 base64 corpus (meaningful decodes) ===")
for off, layers, txt in rows:
    disp = txt if len(txt) <= 90 else txt[:90] + '...'
    print(f"  {off:#010x} L{layers}  {disp!r}")
print(f"  total: {len(rows)}")

# 2) key 0x37 sweep (v845 frida-token blob key)
print()
print("=== XOR 0x37 sweep (frida-token blob search) ===")
dec37 = bytes(x ^ 0x37 for x in raw)
for m in re.finditer(rb'[ -~]{6,}', dec37):
    off = m.start()
    if RO_LO - 0x200 <= off < RO_HI + 0x40000:
        s = m.group().decode('latin1')
        if any(k in s for k in ('frida', 'gum', 'zygisk', 'xposed', 'maps', 'su', 'rwxp', 'deleted', 'http', 're.')):
            print(f"  {off:#010x}  {s[:160]!r}")
