#!/usr/bin/env python3
"""
apk_build.py — rebuild TopFollow APK without apktool/Java:
  * swap AndroidManifest.xml (patched: storage perms + RTLogProvider)
  * swap lib/<abi>/libtopfollow.so (patched pin blob)
  * add classes2.dex (embedded logger)
  * zipalign semantics: STORED data 4-byte aligned, .so data 16384-byte aligned
    (padding via 0xd935 extra-field entries, as zipalign/apksigner do)
  * preserve original entry order, methods, timestamps, attrs
Leaves the file UNSIGNED — v2sign.py adds the APK Signature Scheme v2 block.
"""
import struct, sys, zlib, zipfile

ALIGN_SO = 16384
ALIGN_STORED = 4

def lp_extra(pad):
    """0xd935 alignment extra (zipalign-style); header always emitted."""
    return struct.pack('<HH', 0xd935, pad) + b'\x00' * pad


def build(src, dst, manifest_bytes, dex_bytes, so_map):
    zin = zipfile.ZipFile(src)
    raw = open(src, 'rb').read()
    infos = zin.infolist()

    out = bytearray()
    cd_records = []

    def write_entry(info, data_plain, method_override=None, name_override=None):
        """data_plain: uncompressed bytes; we compress if the entry is deflate."""
        nonlocal out
        method = info.compress_type if method_override is None else method_override
        name = (name_override or info.filename).encode('utf-8')
        if method == 8:
            co = zlib.compressobj(6, zlib.DEFLATED, -15)
            comp = co.compress(data_plain) + co.flush()
        else:
            comp = data_plain
        crc = zlib.crc32(data_plain) & 0xFFFFFFFF
        usize = len(data_plain)
        csize = len(comp)

        # alignment for STORED data
        base = len(out) + 30 + len(name)
        extra = b''
        if method == 0:
            align = ALIGN_SO if info.filename.endswith('.so') else ALIGN_STORED
            pad = (-(base + 4)) % align          # 4-byte extra header always added
            extra = lp_extra(pad)
            assert (len(out) + 30 + len(name) + len(extra)) % align == 0, info.filename

        local_off = len(out)
        hdr = struct.pack('<IHHHHHIIIHH', 0x04034b50,
                          20,                     # version needed (2.0)
                          0,                      # flags: none (no data descriptor)
                          method,
                          info.date_time[3] << 11 | info.date_time[4] << 5 | info.date_time[5] // 2,
                          (info.date_time[0] - 1980) << 9 | info.date_time[1] << 5 | info.date_time[2],
                          crc, csize, usize, len(name), len(extra))
        out += hdr + name + extra + comp
        cd_records.append((info, name, crc, method, csize, usize, local_off))

    order = [i.filename for i in infos]
    assert 'classes.dex' in order and 'AndroidManifest.xml' in order

    for info in infos:
        nm = info.filename
        if nm == 'AndroidManifest.xml':
            write_entry(info, manifest_bytes)
        elif nm in so_map:
            write_entry(info, so_map[nm], method_override=0)
        else:
            data = zin.read(nm)
            write_entry(info, data)
        if nm == 'classes.dex':
            # insert classes2.dex right after classes.dex (same method: deflate)
            tmpl = zipfile.ZipInfo('classes2.dex', date_time=info.date_time)
            tmpl.compress_type = info.compress_type
            tmpl.external_attr = info.external_attr
            tmpl.create_system = info.create_system
            write_entry(tmpl, dex_bytes)

    # ------------------------------------------------------------ central dir
    cd_off = len(out)
    for (info, name, crc, method, csize, usize, local_off) in cd_records:
        ver_made = (info.create_system << 8) | info.create_version
        dt = info.date_time
        dostime = dt[3] << 11 | dt[4] << 5 | dt[5] // 2
        dosdate = (dt[0] - 1980) << 9 | dt[1] << 5 | dt[2]
        out += struct.pack('<IHHHHHHIIIHHHHHII', 0x02014b50,
                           ver_made, 20, 0, method, dostime, dosdate,
                           crc, csize, usize, len(name), 0, 0, 0, 0,
                           info.external_attr, local_off)
        out += name
    cd_size = len(out) - cd_off

    out += struct.pack('<IHHHHIIH', 0x06054b50, 0, 0,
                       len(cd_records), len(cd_records), cd_size, cd_off, 0)
    open(dst, 'wb').write(bytes(out))
    print(f"wrote {dst}: {len(out)} bytes, {len(cd_records)} entries, cd@{cd_off}")


if __name__ == '__main__':
    so_map = {f'lib/{abi}/libtopfollow.so': open(f'work/repack/lib/{abi}/libtopfollow.so', 'rb').read()
              for abi in ('arm64-v8a', 'x86', 'x86_64')}
    build(sys.argv[1], sys.argv[2],
          open('work/repack/AndroidManifest_new.xml', 'rb').read(),
          open('work/repack/classes2.dex', 'rb').read(),
          so_map)
