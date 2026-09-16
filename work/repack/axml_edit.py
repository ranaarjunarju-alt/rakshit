#!/usr/bin/env python3
"""
axml_edit.py — append-only binary AndroidManifest.xml editor (pure Python).

Safe-by-construction design:
  * existing string-pool entries keep their indices — new strings APPENDED
  * resource-id map extended for appended attribute-name strings
  * new <uses-permission> chunks inserted after the last existing one
  * <provider> chunk inserted as first child of <application>
  * requestLegacyExternalStorage="true" attribute added to <application>
Validate with androguard after editing.
"""
import struct, sys

CH_STRING_POOL = 0x0001
CH_RES_MAP     = 0x0180
CH_START_EL    = 0x0102
CH_END_EL      = 0x0103

TYPE_STRING   = 0x03
TYPE_INT_DEC  = 0x10
TYPE_INT_BOOL = 0x12

ANDROID_NS = 'http://schemas.android.com/apk/res/android'


class Pool:
    def __init__(self, data, off):
        self.off = off
        (self.ctype, self.hsize, self.csize, self.scount, self.stylecount,
         self.flags, self.sstart, self.stylestart) = struct.unpack_from('<HHIIIIII', data, off)
        assert self.ctype == CH_STRING_POOL
        self.utf8 = bool(self.flags & 0x100)
        self.offsets = list(struct.unpack_from('<%dI' % self.scount, data, off + self.hsize))
        self.style_offsets = list(struct.unpack_from('<%dI' % self.stylecount, data,
                                                      off + self.hsize + 4 * self.scount))
        self.data_start = off + self.sstart
        self.data_len = (off + self.csize) - self.data_start
        self.raw = data
        self.strings = [self._decode(i) for i in range(self.scount)]
        self.new_strings = []

    def _decode(self, i):
        p = self.data_start + self.offsets[i]
        if self.utf8:
            nc = self.raw[p]; p += 1
            if nc & 0x80: p += 1
            nb = self.raw[p]; p += 1
            if nb & 0x80:
                nb = ((nb & 0x7F) << 8) | self.raw[p]; p += 1
            return self.raw[p:p + nb].decode('utf-8')
        nc = struct.unpack_from('<H', self.raw, p)[0]; p += 2
        if nc & 0x8000:
            nc = ((nc & 0x7FFF) << 16) | struct.unpack_from('<H', self.raw, p)[0]; p += 2
        return self.raw[p:p + 2 * nc].decode('utf-16-le')

    def index(self, s):
        try:
            return self.strings.index(s)
        except ValueError:
            return -1

    def encode_new(self, s):
        if self.utf8:
            b = s.encode('utf-8')
            assert len(s) < 0x80 and len(b) < 0x80
            return bytes([len(s), len(b)]) + b + b'\x00'
        u = s.encode('utf-16-le')
        assert len(s) < 0x8000
        return struct.pack('<H', len(s)) + u + b'\x00\x00'

    def rebuild(self):
        old_data = self.raw[self.data_start:self.data_start + self.data_len]
        add = b''
        new_offsets, cursor = [], self.data_len
        for s in self.new_strings:
            new_offsets.append(cursor)
            enc = self.encode_new(s)
            cursor += len(enc)
            add += enc
        n = self.scount + len(self.new_strings)
        sstart = self.hsize + 4 * n + 4 * self.stylecount
        stylestart = (self.stylestart + 4 * len(self.new_strings)) if self.stylecount else 0
        data = old_data + add
        data += b'\x00' * ((4 - len(data) % 4) % 4)
        payload = struct.pack('<HHIIIIII', CH_STRING_POOL, self.hsize,
                              sstart + len(data), n, self.stylecount, self.flags,
                              sstart, stylestart)
        payload += struct.pack('<%dI' % n, *(self.offsets + new_offsets))
        if self.stylecount:
            payload += struct.pack('<%dI' % self.stylecount, *self.style_offsets)
        payload += data
        return payload


def attr(ns, name, raw, dtype, data):
    """one 20-byte attribute: ns, name, rawValue, typedValue{8,0,dtype,data}"""
    return struct.pack('<iiiHBBI', ns, name, raw, 8, 0, dtype, data)


def start_el(name_idx, attrs, line=2):
    body = struct.pack('<II', line, 0xFFFFFFFF)
    body += struct.pack('<iiHHHHHH', -1, name_idx, 0x14, 0x14, len(attrs), 0, 0, 0)
    for a in attrs:
        body += a
    return struct.pack('<HHI', CH_START_EL, 16, 8 + len(body)) + body


def end_el(name_idx, line=2):
    body = struct.pack('<II', line, 0xFFFFFFFF) + struct.pack('<ii', -1, name_idx)
    return struct.pack('<HHI', CH_END_EL, 16, 8 + len(body)) + body


def el_name(raw, off):
    # element chunk: 8-byte hdr, line, comment, ns, name
    return struct.unpack_from('<i', raw, off + 20)[0]


def main(src, dst):
    raw = open(src, 'rb').read()
    ctype, hsize, total = struct.unpack_from('<HHI', raw, 0)
    assert ctype == 0x0003, 'not AXML'
    pool = Pool(raw, 8)
    assert pool.index(ANDROID_NS) >= 0
    ans = pool.index(ANDROID_NS)

    chunks, off = [], 8 + pool.csize
    while off < total:
        t, hs, cs = struct.unpack_from('<HHI', raw, off)
        chunks.append((off, t, cs))
        off += cs
    assert chunks[0][1] == CH_RES_MAP, 'expected resource map first'
    map_ids = list(struct.unpack_from('<%dI' % ((chunks[0][2] - 8) // 4), raw, chunks[0][0] + 8))

    def S(x):
        i = pool.index(x)
        if i >= 0:
            return i
        pool.new_strings.append(x)
        return pool.scount + len(pool.new_strings) - 1

    # strings + resource ids
    ids = {}
    for nm, rid in (('name', 0x01010003), ('maxSdkVersion', 0x01010271),
                    ('authorities', 0x01010018), ('exported', 0x01010010),
                    ('requestLegacyExternalStorage', 0x0101058e)):
        ids[nm] = S(nm)
    up_i, prov_i, app_i, true_i = S('uses-permission'), S('provider'), S('application'), S('true')
    perms = [(S('android.permission.WRITE_EXTERNAL_STORAGE'), 29),
             (S('android.permission.READ_EXTERNAL_STORAGE'), 32),
             (S('android.permission.MANAGE_EXTERNAL_STORAGE'), None)]
    prov_name, prov_auth = S('com.tf.lab.RTLogProvider'), S('com.nivaroid.topfollow.rtlog')

    # extend resource map for appended name strings
    n_total = pool.scount + len(pool.new_strings)
    while len(map_ids) < n_total:
        map_ids.append(0)
    for nm, rid in (('name', 0x01010003), ('maxSdkVersion', 0x01010271),
                    ('authorities', 0x01010018), ('exported', 0x01010010),
                    ('requestLegacyExternalStorage', 0x0101058e)):
        map_ids[ids[nm]] = rid

    # locate: last uses-permission END, application START
    last_up_end = app_off = app_cs = None
    for (o, t, cs) in chunks:
        if t == CH_END_EL and el_name(raw, o) == up_i:
            last_up_end = o + cs
        if t == CH_START_EL and el_name(raw, o) == app_i:
            app_off, app_cs = o, cs
    assert last_up_end and app_off

    # permission chunks (manifest level, after last uses-permission)
    perm_chunks = b''
    for ps, maxsdk in perms:
        a = [attr(ans, ids['name'], ps, TYPE_STRING, ps)]
        if maxsdk:
            a.append(attr(ans, ids['maxSdkVersion'], -1, TYPE_INT_DEC, maxsdk))
        perm_chunks += start_el(up_i, a) + end_el(up_i)

    # provider chunk (first child of <application>)
    provider = (start_el(prov_i, [attr(ans, ids['name'], prov_name, TYPE_STRING, prov_name),
                                  attr(ans, ids['authorities'], prov_auth, TYPE_STRING, prov_auth),
                                  attr(ans, ids['exported'], true_i, TYPE_INT_BOOL, 0)])
                + end_el(prov_i))

    # patch <application> start: + requestLegacyExternalStorage="true"
    line, comment = struct.unpack_from('<II', raw, app_off + 8)
    ns, nm, astart, asize, acount = struct.unpack_from('<iiHHH', raw, app_off + 16)
    attrs_blob = raw[app_off + 36:app_off + 36 + acount * 20]
    attrs_blob += attr(ans, ids['requestLegacyExternalStorage'], true_i, TYPE_INT_BOOL, 1)
    body = struct.pack('<II', line, comment)
    body += struct.pack('<iiHHHHHH', ns, nm, 0x14, 0x14, acount + 1, 0, 0, 0)
    body += attrs_blob
    new_app = struct.pack('<HHI', CH_START_EL, 16, 8 + len(body)) + body

    # assemble: map + tree-part-1 + perms + tree-part-2(+patched app+provider) + rest
    tree_start = chunks[0][0] + chunks[0][2]          # right after res-map
    part1 = raw[tree_start:last_up_end]
    part2 = raw[last_up_end:app_off]
    part3 = raw[app_off + app_cs:]
    map_bytes = struct.pack('<HHI', CH_RES_MAP, 8, 8 + 4 * len(map_ids)) + \
                struct.pack('<%dI' % len(map_ids), *map_ids)
    content = map_bytes + part1 + perm_chunks + part2 + new_app + provider + part3
    pool_bytes = pool.rebuild()
    out = struct.pack('<HHI', 0x0003, 8, 8 + len(pool_bytes) + len(content)) + pool_bytes + content
    open(dst, 'wb').write(out)
    print('wrote', dst, len(out), 'bytes (orig', total, ')')


if __name__ == '__main__':
    main(sys.argv[1], sys.argv[2])
