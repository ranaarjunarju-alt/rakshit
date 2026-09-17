#!/usr/bin/env python3
"""
axml_extractlibs.py — flip android:extractNativeLibs false -> true in an AXML.

Single in-place 32-bit typedValue.data flip (0 -> 1) on the <application>
start-element attribute. No string-pool changes (the attribute in this
manifest carries no rawValue string), so every other byte is untouched.

Why: with extractNativeLibs="false" the modern PackageManager validates
native-library entries in lib/<abi>/ at install time and the frida gadget's
APK-embedded config/script flow (minizip read from inside the zip) has a
known SIGSEGV in this gadget generation (frida/frida#3689, fixed in git
after this release). With extraction ON, all lib*.so entries (gadget +
config + script) are copied to /data/app/.../lib/<abi>/ at install time
(the standard objection-patchapk flow) and the gadget reads its config and
script from the real filesystem — no minizip path, no install-time ELF
validation of the JSON/JS "fake libraries".
"""
import struct, sys
sys.path.insert(0, __import__('os').path.dirname(__import__('os').path.abspath(__file__)))
from axml_edit import Pool, CH_START_EL

def main(src, dst):
    raw = bytearray(open(src, 'rb').read())
    ctype, hsize, total = struct.unpack_from('<HHI', raw, 0)
    assert ctype == 0x0003, 'not AXML'
    pool = Pool(bytes(raw), 8)

    off = 8 + pool.csize
    while off < total:
        t, hs, cs = struct.unpack_from('<HHI', raw, off)
        if t == CH_START_EL:
            nm = struct.unpack_from('<i', raw, off + 20)[0]
            if pool.strings[nm] == 'application':
                ns, nmi, astart, asize, acount, _i1, _i2, _fl = struct.unpack_from('<iiHHHHHH', raw, off + 16)
                for k in range(acount):
                    a = off + 36 + k * 20
                    _ans, an, _rv = struct.unpack_from('<iii', raw, a)
                    if pool.strings[an] == 'extractNativeLibs':
                        _t8, _res0, dt, data = struct.unpack_from('<HBBI', raw, a + 12)
                        assert dt == 0x12, f'expected INT_BOOL, got {dt:#x}'
                        assert data == 0, f'already true (data={data})'
                        struct.pack_into('<I', raw, a + 16, 1)   # typedValue.data 0 -> 1
                        print(f'flipped <application> extractNativeLibs false -> true (attr {k})')
                        open(dst, 'wb').write(bytes(raw))
                        print('wrote', dst, len(raw), 'bytes (identical except 4 bytes)')
                        return
                raise SystemExit('extractNativeLibs attribute not found on <application>')
        off += cs
    raise SystemExit('<application> element not found')

if __name__ == '__main__':
    main(sys.argv[1], sys.argv[2])
