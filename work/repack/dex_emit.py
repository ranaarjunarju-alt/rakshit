#!/usr/bin/env python3
"""dex_emit.py — serialize a dex_core.Dex model + assembled code to DEX-035."""
import hashlib, struct, zlib
from dex_core import uleb, sleb, NO_INDEX

ACC = dict(PUBLIC=0x1, PRIVATE=0x2, PROTECTED=0x4, STATIC=0x8, FINAL=0x10,
           SUPER=0x20, ABSTRACT=0x400, CONSTRUCTOR=0x10000)


class Emitter:
    def __init__(self, dex, code_map):
        """
        dex      : dex_core.Dex
        code_map : {method_key: (regs, ins, outs, Asm)}
        classes  must carry explicit flags:
          statics/instances  : [(field_key, access), ...]
          directs/virtuals   : [(method_key, access), ...]
        """
        self.dex = dex
        u = lambda t: t[1] if isinstance(t, tuple) and len(t) == 2 and t[0] in ('f', 'm', 't', 's', 'p') else t
        self.code_map = {u(k): v for k, v in code_map.items()}
        self.unwrap = u
        self.finalize_ids()

    # ------------------------------------------------------------ ids
    def finalize_ids(self):
        d = self.dex
        for (ret, params, shorty) in d.protos:
            d.sid(shorty)
        for c in d.classes:
            d.sid(c.get('source', 'RTLog.java'))
        self.strings = sorted(d.str_map.keys())
        self.sidx = {s: i for i, s in enumerate(self.strings)}
        descs = sorted(d.type_map.keys(), key=lambda t: self.sidx[t])
        self.tidx = {t: i for i, t in enumerate(descs)}

        def pkey(i):
            ret, params, _ = d.protos[i]
            return (self.tidx[ret], tuple(self.tidx[p] for p in params))
        self.pidx = [0] * len(d.protos)
        for new, old in enumerate(sorted(range(len(d.protos)), key=pkey)):
            self.pidx[old] = new

        self.fidx = [0] * len(d.fields)
        for new, old in enumerate(sorted(range(len(d.fields)),
                                         key=lambda i: (self.tidx[d.fields[i][0]],
                                                        self.sidx[d.fields[i][1]],
                                                        self.tidx[d.fields[i][2]]))):
            self.fidx[old] = new

        self.midx = [0] * len(d.methods)
        for new, old in enumerate(sorted(range(len(d.methods)),
                                         key=lambda i: (self.tidx[d.methods[i][0]],
                                                        self.sidx[d.methods[i][1]],
                                                        self.pidx[d.proto_map[(d.methods[i][2], d.methods[i][3], None) if False else self._proto_key_of(i)]]))):
            self.midx[old] = new

    def _proto_key_of(self, i):
        cls, name, ret, params = self.dex.methods[i]
        for k, v in self.dex.proto_map.items():
            if k[0] == ret and k[1] == tuple(params):
                return k
        raise KeyError(i)

    # ------------------------------------------------------------ assembly
    def assemble(self, asm):
        pos, labels = 0, {}
        for kind, pay in asm.items:
            if kind == 'label':
                labels[pay] = pos
            elif kind == 'insn':
                pos += len(pay)
        units = [0] * pos
        for idx, (kind, pay) in enumerate(asm.items):
            if kind != 'insn':
                continue
            # compute this insn's start position
            p = 0
            for kind2, pay2 in asm.items[:idx]:
                if kind2 == 'insn':
                    p += len(pay2)
            for j, t in enumerate(pay):
                if not isinstance(t, tuple):
                    units[p + j] = t
                    continue
                k = t[0]
                v = t[1]
                if isinstance(v, tuple):
                    v = v[1]
                if k == 's':
                    units[p + j] = self.sidx[v]
                elif k == 't':
                    units[p + j] = self.tidx[v]
                elif k == 'f':
                    units[p + j] = self.fidx[self.dex.field_map[v]]
                elif k == 'm':
                    units[p + j] = self.midx[self.dex.method_map[v]]
                elif k == 'rel':
                    # standard 21t/22t: B = target - (insn_start + insn_size)
                    off = labels[t[1]] - (p + len(pay))
                    assert -32768 <= off <= 32767, t
                    units[p + j] = off & 0xFFFF
                elif k == 'g8':
                    # standard 10t: B = target - (insn_start + insn_size)
                    off = labels[t[1]] - (p + len(pay))
                    assert -128 <= off <= 127, (t, off)
                    units[p + j] = 0x28 | (off & 0xFF) << 8
                else:
                    raise ValueError(k)
        insns = b''.join(struct.pack('<H', u) for u in units)

        tries = [pay for (kind, pay) in asm.items if kind == 'try']
        tries.sort(key=lambda t: labels[t[0]])
        tries_bytes = b''
        if tries:
            if len(units) % 2:
                insns += b'\x00\x00'
            handlers = b''
            items = []
            for (b, e, h, tdesc) in tries:
                hoff = len(uleb(len(tries))) + len(handlers)
                if tdesc is None:
                    handlers += sleb(0) + uleb(labels[h])      # size=0: catch-all only
                else:
                    handlers += sleb(1) + uleb(self.tidx[tdesc]) + uleb(labels[h])
                items.append((labels[b], labels[e] - labels[b], hoff))
            tb = b''.join(struct.pack('<IHH', s, c, o) for (s, c, o) in items)
            tries_bytes = tb + uleb(len(tries)) + handlers
        return bytes(insns), tries_bytes, len(tries)

    # ------------------------------------------------------------ emit
    def emit(self):
        d = self.dex
        code_blobs = {k: (r, i, o) + self.assemble(a)
                      for k, (r, i, o, a) in self.code_map.items()}

        nstr, ntype = len(self.strings), len(self.tidx)
        nproto, nfield, nmethod, nclass = len(d.protos), len(d.fields), len(d.methods), len(d.classes)

        s_ids = 0x70
        t_ids = s_ids + 4 * nstr
        p_ids = t_ids + 4 * ntype
        f_ids = p_ids + 12 * nproto
        fd_ids = f_ids + 8 * nfield
        m_ids = fd_ids + 8 * nmethod
        c_ids = m_ids + 8 * nmethod
        data0 = c_ids + 32 * nclass
        out = bytearray(data0)
        data = bytearray()
        doff = data0
        code_offs, cdata_offs, type_list_offs = [], [], {}

        def put(item, align4=True):
            if align4:
                while (doff + len(data)) % 4:
                    data.append(0)
            off = doff + len(data)
            data.extend(item)
            return off

        def tlist(tl):
            if not tl:
                return 0
            key = tuple(tl)
            if key not in type_list_offs:
                body = struct.pack('<I', len(tl)) + b''.join(struct.pack('<H', self.tidx[t]) for t in tl)
                type_list_offs[key] = put(body)
            return type_list_offs[key]

        # string ids / type ids
        for i in range(ntype):
            desc = [k for k, v in self.tidx.items() if v == i][0]
            struct.pack_into('<I', out, t_ids + 4 * i, self.sidx[desc])
        # proto ids — params type-list offsets are patched AFTER the data
        # region layout is final (dialect order: code FIRST, then lists).
        proto_param_lists = []
        for old in range(nproto):
            i = self.pidx[old]
            ret, params, shorty = d.protos[old]
            struct.pack_into('<III', out, p_ids + 12 * i,
                             self.sidx[shorty], self.tidx[ret], 0)
            proto_param_lists.append((i, params))
        # field ids
        for old in range(nfield):
            i = self.fidx[old]
            cls, name, desc = d.fields[old]
            struct.pack_into('<HHI', out, fd_ids + 8 * i,
                             self.tidx[cls], self.tidx[desc], self.sidx[name])
        # method ids
        for old in range(nmethod):
            i = self.midx[old]
            cls, name, ret, params = d.methods[old]
            pk = self._proto_key_of(old)
            struct.pack_into('<HHI', out, m_ids + 8 * i,
                             self.tidx[cls], self.pidx[d.proto_map[pk]], self.sidx[name])

        # ---- Dialect data-region order (matches stock classes.dex):
        #      code items FIRST at data_off, then type-lists, then
        #      string-data, then class-data, then the map.
        u = self.unwrap
        code_off_of = {}
        for c in d.classes:
            for (k, ac) in list(c['directs']) + list(c['virtuals']):
                k = u(k)
                regs, ins, outs, insns, tries, ntry = code_blobs[k]
                co = put(struct.pack('<HHHHII', regs, ins, outs, ntry, 0,
                                     len(insns) // 2) + insns + tries)
                code_offs.append(co)
                code_off_of[k] = co

        # ---- ALL type-lists (proto params + interfaces) after code
        for i, params in proto_param_lists:
            tlist(params)
        for c in d.classes:
            tlist(c['interfaces'])
        for i, params in proto_param_lists:
            struct.pack_into('<I', out, p_ids + 12 * i + 8, tlist(params))
        while (doff + len(data)) % 4:  # keep next region 4-aligned (stock layout)
            data.append(0)

        # ---- string data
        sd_offs = []
        for s in self.strings:
            sd_offs.append(put(uleb(len(s)) + s.encode('utf-8') + b'\x00', align4=False))
        while (doff + len(data)) % 4:
            data.append(0)
        for i, off in enumerate(sd_offs):
            struct.pack_into('<I', out, s_ids + 4 * i, off)

        # ---- class_data items (after string data, per stock layout)
        for c in d.classes:
            sf = sorted((self.fidx[d.field_map[u(k)]], u(k), ac) for (k, ac) in c['statics'])
            iff = sorted((self.fidx[d.field_map[u(k)]], u(k), ac) for (k, ac) in c['instances'])
            dm = sorted((self.midx[d.method_map[u(k)]], u(k), ac) for (k, ac) in c['directs'])
            vm = sorted((self.midx[d.method_map[u(k)]], u(k), ac) for (k, ac) in c['virtuals'])
            cd = uleb(len(sf)) + uleb(len(iff)) + uleb(len(dm)) + uleb(len(vm))
            prev = 0
            for gi, k, ac in sf:
                cd += uleb(gi - prev) + uleb(ac); prev = gi
            prev = 0
            for gi, k, ac in iff:
                cd += uleb(gi - prev) + uleb(ac); prev = gi
            prev = 0
            for gi, k, ac in dm:
                cd += uleb(gi - prev) + uleb(ac) + uleb(code_off_of[k]); prev = gi
            prev = 0
            for gi, k, ac in vm:
                cd += uleb(gi - prev) + uleb(ac) + uleb(code_off_of[k]); prev = gi
            cdata_offs.append(put(cd, align4=False))

        # class defs (standard 32-byte class_def_item, 035-038 layout:
        # [class_idx][access][super][interfaces_off][source_file_idx]
        # [annotations_off][class_data_off][static_values_off])
        for i, c in enumerate(d.classes):
            struct.pack_into('<IIIIIIII', out, c_ids + 32 * i,
                             self.tidx[c['desc']], c['access'],
                             self.tidx[c['super']] if c['super'] else NO_INDEX,
                             tlist(c['interfaces']), NO_INDEX, 0,
                             cdata_offs[i], 0)

        # map
        map_off = doff + len(data)
        items = [(0x0000, 1, 0), (0x0001, nstr, s_ids), (0x0002, ntype, t_ids),
                 (0x0003, nproto, p_ids), (0x0004, nfield, fd_ids),
                 (0x0005, nmethod, m_ids), (0x0006, nclass, c_ids)]
        if type_list_offs:
            items.append((0x1001, len(type_list_offs), min(type_list_offs.values())))
        items.append((0x2000, nclass, min(cdata_offs)))
        if code_offs:
            items.append((0x2001, len(code_offs), min(code_offs)))
        items.append((0x2002, nstr, sd_offs[0]))
        items.append((0x1000, 1, map_off))
        mb = struct.pack('<I', len(items))
        for ty, sz, off in sorted(items, key=lambda x: x[2]):
            mb += struct.pack('<HHII', ty, 0, sz, off)  # standard 8-byte map_item: [u16 type][u16 unused][u32 size][u32 offset]
        data.extend(mb)

        file_size = doff + len(data)
        full = bytes(out) + bytes(data)
        # standard 112-byte header:
        # magic, checksum, sha1, file_size, header_size(0x70), endian_tag,
        # link_size=0, link_off=0, map_off, 6x (size,off), data_size, data_off
        hdr_b = struct.pack('<8sI20sIIIIIIIIIIIIIIIIIIII',
                            b'dex\n035\x00', 0, b'\x00' * 20, file_size, 0x70,
                            0x12345678, 0, 0, map_off,
                            nstr, s_ids, ntype, t_ids, nproto, p_ids,
                            nfield, fd_ids, nmethod, m_ids, nclass, c_ids,
                            file_size - data0, data0)
        full = hdr_b + full[0x70:]
        sha1 = hashlib.sha1(full[32:]).digest()
        full = full[:12] + sha1 + full[32:]
        chk = zlib.adler32(full[12:]) & 0xFFFFFFFF
        full = full[:8] + struct.pack('<I', chk) + full[12:]
        return full
