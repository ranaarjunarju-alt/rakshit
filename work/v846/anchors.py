#!/usr/bin/env python3
"""Stage 2: locate every known v845 anchor in the v846 .so (and vice-versa).
Proves or disproves which build features survived the 39% shrink."""
import sys

ANCHORS = [
    # (label, bytes, note)
    ('Te0   [8]',  b'\xa5\x63\x63\xc6\x84\x7c\x7c\xf8', 'LibTomCrypt Te0 table head'),
    ('Td0   [8]',  b'\x50\xa7\xf4\x51\x53\x65\x41\x7e', 'LibTomCrypt Td0 table head'),
    ('Sbox  [8]',  b'\x63\x7c\x77\x7b\xf2\x6b\x6f\xc5', 'AES S-box head'),
    ('RSbox [8]',  b'\x52\x09\x6a\xd5\x30\x36\xa5\x38', 'AES inv-S-box head'),
    ('Rcon  [8]',  b'\x01\x02\x04\x08\x10\x20\x40\x80', 'AES Rcon head'),
    ('"AES"  ',    b'AES\x00', 'cipher name'),
    ('plainkey',   b'0123456789abcdef', 'literal AES-128 key (hex string)'),
    ('pin120?',    None, '120-char base64 blob — pattern search'),
]
# the 22 JNI native names (v845 recovered table)
NAMES = ["x00105e9b","x0010e27f","x00113f7a","x0011a4c2","x0011e28b","x0011f1a2",
         "x0011f42b","x00120b1e","x00126f7c","x0012d3e0","x0012e5a1","x0012f5b7",
         "x00135e2a","x0014b4f3","x0014c1f9","x0014e2e9","x0015a3b7","x0015b1e9",
         "x0015e49c","x0016d3b9","x0017b62c","x0018d3f7"]

def find_all(raw, pat, limit=200):
    out, i = [], 0
    while len(out) < limit:
        i = raw.find(pat, i)
        if i < 0: break
        out.append(i); i += 1
    return out

def b64_120(raw):
    import re
    out = []
    for m in re.finditer(rb'[A-Za-z0-9+/=]{120}', raw):
        s = m.group()
        if b'=' in s[:100]:
            continue
        out.append((m.start(), s.decode()))
    return out

def cstr(raw, off, maxlen=300):
    e = raw.find(b'\x00', off, off + maxlen)
    if e < 0: return None
    try:
        s = raw[off:e].decode('ascii')
        return s if all(32 <= ord(c) < 127 for c in s) else None
    except Exception:
        return None

def analyze(path, tag):
    raw = open(path, 'rb').read()
    print(f'########## {tag}  ({len(raw)} B) ##########')
    for label, pat, note in ANCHORS:
        if pat is None:
            hits = b64_120(raw)
            for off, s in hits:
                print(f'  {label:10s} @{off:#010x}  {s[:80]}...')
            if not hits:
                print(f'  {label:10s}  <none>')
            continue
        hits = find_all(raw, pat)
        if not hits:
            print(f'  {label:10s}  <NOT FOUND>  ({note})')
        for off in hits[:8]:
            print(f'  {label:10s} @{off:#010x}  ({note})')
    print('  --- 22 JNI native names ---')
    found = 0
    for n in NAMES:
        off = raw.find(n.encode() + b'\x00')
        if off >= 0:
            found += 1
            print(f'    {n}  @{off:#010x}')
    print(f'  ({found}/22 native names present)')
    return raw

if __name__ == '__main__':
    analyze(sys.argv[1], sys.argv[2])
