#!/usr/bin/env python3
"""Stage 1: pure-Python ELF64 analysis of libtopfollow.so (v846 vs v845)."""
import struct, sys, json

def elf64(path):
    raw = open(path, 'rb').read()
    assert raw[:4] == b'\x7fELF', 'not ELF'
    assert raw[4] == 2, 'not 64-bit'
    end = '<' if raw[5] == 1 else '>'
    ei = dict(osabi=raw[7])
    (e_type, e_machine, e_version, e_entry, e_phoff, e_shoff, e_flags) = struct.unpack_from(end + 'HHIQQQI', raw, 16)
    e_phentsize, e_phnum = struct.unpack_from(end + 'HH', raw, 54)
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(end + 'HHH', raw, 58)

    PT_LOAD, PT_DYNAMIC, PT_INTERP, PT_NOTE = 1, 2, 3, 4
    segs = []
    for i in range(e_phnum):
        o = e_phoff + i * e_phentsize
        p_type, p_flags = struct.unpack_from(end + 'II', raw, o)
        p_off, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = struct.unpack_from(end + 'QQQQQQ', raw, o + 8)
        segs.append(dict(type=p_type, flags=p_flags, off=p_off, vaddr=p_vaddr,
                         filesz=p_filesz, memsz=p_memsz, align=p_align))

    # section headers
    secs = []
    if e_shoff:
        for i in range(e_shnum):
            o = e_shoff + i * e_shentsize
            sh_name, sh_type, sh_flags, sh_addr, sh_off, sh_size = struct.unpack_from(end + 'IIQQQQ', raw, o)
            sh_link, sh_info = struct.unpack_from(end + 'II', raw, o + 56)
            secs.append(dict(name=sh_name, type=sh_type, flags=sh_flags, addr=sh_addr,
                             off=sh_off, size=sh_size, link=sh_link, info=sh_info))
    # section names
    if secs and e_shstrndx < len(secs):
        strtab = secs[e_shstrndx]
        for s in secs:
            e = raw.find(b'\x00', strtab['off'] + s['name'])
            s['name'] = raw[strtab['off'] + s['name']:e].decode('utf-8', 'replace')

    # dynamic
    dyns = []
    for s in segs:
        if s['type'] == PT_DYNAMIC:
            base = s['off']
            sz = s['filesz']
            for i in range(sz // 16):
                d_tag, d_val = struct.unpack_from(end + 'qQ', raw, base + i * 16)
                dyns.append((d_tag, d_val))
            break

    # dynsym + dynstr
    symtab, symstr = None, None
    for s in secs:
        if s['type'] == 11:  # DYNSYM
            symtab = s
        if s['type'] == 3:   # STRTAB
            if symtab and s['link'] == 0 and symstr is None and s['name'] == '.dynstr':
                symstr = s
            if s['name'] == '.dynstr':
                symstr = s
    exports, imports = [], []
    if symtab:
        stsz = symtab['size'] // 24
        for i in range(stsz):
            o = symtab['off'] + i * 24
            st_name, st_info, st_other, st_shndx, st_value, st_size = struct.unpack_from(end + 'IBBHQQ', raw, o)
            e2 = raw.find(b'\x00', symstr['off'] + st_name)
            name = raw[symstr['off'] + st_name:e2].decode('utf-8', 'replace')
            bind, typ = st_info >> 4, st_info & 15
            if typ == 2:  # FUNC
                if st_shndx == 0:
                    imports.append(name)
                elif name:
                    exports.append((name, st_value, st_size))
    return dict(raw=raw, endian=end, entry=e_entry, machine=e_machine, phnum=e_phnum,
                segs=segs, secs=secs, dyn=dyns, exports=exports, imports=imports)

def load_map(e):
    loads = [(s['vaddr'], s['off'], max(s['filesz'], s['memsz'])) for s in e['segs'] if s['type'] == 1]
    return loads

def va2off(e, va):
    for v, fo, sz in load_map(e):
        if v <= va < v + sz:
            return fo + (va - v)
    return None

def off2va(e, off):
    for v, fo, sz in load_map(e):
        if fo <= off < fo + max(sz, 1):
            return v + (off - fo)
    return None

if __name__ == '__main__':
    path = sys.argv[1]
    tag = sys.argv[2] if len(sys.argv) > 2 else 'so'
    e = elf64(path)
    raw = e['raw']
    print(f'===== {tag}: {path} =====')
    print(f'size={len(raw)}  entry={hex(e["entry"])}  machine={e["machine"]} (183=AArch64)')
    print(f'phnum={e["phnum"]}  sections={len(e["secs"])}')
    print()
    print('--- program headers ---')
    for s in e['segs']:
        t = {1: 'LOAD', 2: 'DYNAMIC', 3: 'INTERP', 4: 'NOTE', 6: 'GNU_EH_FRAME', 16: 'GNU_STACK', 17: 'GNU_RELRO'}.get(s['type'], str(s['type']))
        print(f'  {t:12s} off={s["off"]:>#10x} vaddr={s["vaddr"]:>#10x} filesz={s["filesz"]:>#10x} memsz={s["memsz"]:>#10x} flags={s["flags"]}')
    rx = [s for s in e['segs'] if s['type'] == 1 and (s['flags'] & 5) == 5]
    for s in rx:
        print(f'  RX segment: p_off={s["off"]:#x} p_vaddr={s["vaddr"]:#x} -> file-off==vaddr: {s["off"] == s["vaddr"]}')
    print()
    print('--- sections ---')
    for s in e['secs']:
        if s['size']:
            print(f'  {s["name"]:20s} off={s["off"]:>#10x} addr={s["addr"]:>#10x} size={s["size"]:>#10x}')
    print()
    print(f'--- exports ({len(e["exports"])}) ---')
    for name, va, sz in e['exports']:
        o = va2off(e, va)
        print(f'  {name:20s} va={va:#x} off={"0x%x" % o if o is not None else None} size={sz}')
    print(f'--- imports ({len(e["imports"])}) ---')
    print('  ' + ', '.join(sorted(e['imports'])))
    print()
    print('--- NEEDED ---')
    DT_NEEDED = 1
    for t, v in e['dyn']:
        if t == DT_NEEDED:
            # v is an offset into .dynstr (file offset here since ro segment at 0)
            e2 = raw.find(b'\x00', v)
            print(f'  {raw[v:e2].decode()}')
