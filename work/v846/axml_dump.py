#!/usr/bin/env python3
"""Minimal pure-Python AXML dumper: python axml_dump.py <apk|axml-file> [member]"""
import struct, sys, zipfile

def axml_dump(data):
    assert data[0:4] == b'\x03\x00\x08\x00', "not AXML"
    chunk_size = struct.unpack('<I', data[8:12])[0]
    base = 8                      # string pool chunk starts here
    strcount = struct.unpack('<I', data[base+8:base+12])[0]
    flags = struct.unpack('<I', data[base+16:base+20])[0]
    strs_off = struct.unpack('<I', data[base+20:base+24])[0]
    is_utf8 = bool(flags & (1 << 8))
    offs = [struct.unpack('<I', data[base+28+4*i: base+32+4*i])[0] for i in range(strcount)]
    pool_start = base + strs_off
    def cstr(off):
        p = pool_start + off
        if is_utf8:
            n = data[p]
            if n & 0x80: n = ((n & 0x7F) << 8) | data[p+1]; p += 2
            else: p += 1
            s = b''
            while data[p] != 0:
                s += bytes([data[p]]); p += 1
            return s.decode('utf8', 'replace')
        n = struct.unpack('<H', data[p:p+2])[0]; p += 2
        if n & 0x8000:
            n = ((n & 0x7FFF) << 16) | struct.unpack('<H', data[p:p+2])[0]; p += 2
        return data[p:p+2*n].decode('utf-16-le', 'replace')
    strings = [cstr(o) for o in offs]
    def ref(i):
        try: return strings[i]
        except IndexError: return f"<ref{i}>"
    out = []
    pos = 8
    while pos + 8 <= len(data):
        typ, hs = struct.unpack('<HH', data[pos:pos+4])
        sz = struct.unpack('<I', data[pos+4:pos+8])[0]
        if not (8 <= sz <= 0x100000):
            break
        if typ == 0x0102:
            ns = struct.unpack('<I', data[pos+16:pos+20])[0]
            name = struct.unpack('<I', data[pos+20:pos+24])[0]
            attr_count = struct.unpack('<H', data[pos+28:pos+30])[0]
            attrs = []
            ap = pos + 36
            for i in range(attr_count):
                aname = struct.unpack('<I', data[ap+4:ap+8])[0]
                atype = data[ap+15]
                adata = struct.unpack('<I', data[ap+16:ap+20])[0]
                if atype == 3: v = ref(adata)
                elif atype == 0x12: v = "true" if adata == 1 else "false"
                elif atype == 16: v = f"0x{adata:x}"
                elif atype == 0x10: v = f"int:{adata}"
                elif atype == 0x101: v = ref(adata)
                else: v = f"(t{atype}){adata:#x}"
                attrs.append(f'{ref(aname)}={v}')
                ap += 20
            ns_ = ref(ns) if ns != 0xFFFFFFFF else ''
            out.append(f"<{ns_}{ref(name)} {' '.join(attrs)}>")
            pos += sz
        elif typ == 0x0103:
            out.append(f"</{ref(struct.unpack('<I', data[pos+20:pos+24])[0])}>")
            pos += sz
        else:
            pos += sz
    return '\n'.join(out)

if __name__ == '__main__':
    path = sys.argv[1]
    member = sys.argv[2] if len(sys.argv) > 2 else None
    if member or zipfile.is_zipfile(path):
        z = zipfile.ZipFile(path)
        data = z.read(member or 'AndroidManifest.xml')
    else:
        data = open(path, 'rb').read()
    print(axml_dump(data))
