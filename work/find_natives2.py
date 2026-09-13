import lief, struct, sys, json
arch_map={'arm64-v8a':('apk/lib/arm64-v8a/libtopfollow.so',8),
          'x86_64':('apk/lib/x86_64/libtopfollow.so',8),
          'x86':('apk/lib/x86/libtopfollow.so',4)}
names=["x00105e9b","x0010e27f","x00113f7a","x0011a4c2","x0011e28b","x0011f1a2","x0011f42b","x00120b1e","x00126f7c","x0012d3e0","x0012e5a1","x0012f5b7","x00135e2a","x0014b4f3","x0014c1f9","x0014e2e9","x0015a3b7","x0015b1e9","x0015e49c","x0016d3b9","x0017b62c","x0018d3f7"]
out={}
for tag,(p,ptrsz) in arch_map.items():
    b=lief.parse(p); raw=open(p,'rb').read()
    loads=[(s.virtual_address,s.file_offset,max(s.virtual_size,s.physical_size)) for s in b.segments if 'LOAD' in str(s.type)]
    exec_seg=[(s.virtual_address,s.file_offset,max(s.virtual_size,s.physical_size)) for s in b.segments if 'LOAD' in str(s.type) and 'X' in str(s.flags)]
    def va2off(va):
        for v,fo,sz in loads:
            if v<=va<v+sz: return fo+(va-v)
        return None
    def off2va(off):
        for v,fo,sz in loads:
            if fo<=off<fo+sz: return v+(off-fo)
        return None
    def in_exec(va):
        return any(v<=va<v+sz for v,fo,sz in exec_seg)
    def cstr_at_va(va):
        o=va2off(va)
        if o is None or o<0 or o>=len(raw): return None
        e=raw.find(b'\x00',o)
        if e<0 or e-o>400: return None
        try: return raw[o:e].decode('ascii')
        except Exception: return None
    fmt='<'+('Q' if ptrsz==8 else 'I')
    entries={}
    for n in names:
        so=raw.find(n.encode()+b'\x00')
        if so<0: continue
        va_name=off2va(so)
        if va_name is None: continue
        pat=struct.pack(fmt,va_name)
        st=0
        while True:
            i=raw.find(pat,st)
            if i<0: break
            st=i+1
            sigva=struct.unpack_from(fmt,raw,i+ptrsz)[0]
            fnva =struct.unpack_from(fmt,raw,i+2*ptrsz)[0] if i+3*ptrsz<=len(raw) else 0
            sig=cstr_at_va(sigva)
            if sig and sig.startswith('(') and ')' in sig and in_exec(fnva):
                entries[n]={'slot_off':hex(i),'slot_va':hex(off2va(i)) if off2va(i) else None,
                            'name':n,'signature':sig,'fn_va':hex(fnva),'fn_off':hex(va2off(fnva))}
                break
    out[tag]=entries
    print("=== %s : %d/%d native entries resolved"%(tag,len(entries),len(names)))
    for n in names:
        e=entries.get(n)
        if e: print("   %-12s %-78s fn=%-12s (file %s) slot=%s"%(n,e['signature'],e['fn_va'],e['fn_off'],e['slot_off']))
        else: print("   %-12s <unresolved>"%n)
json.dump(out,open('out/14_jni_natives.json','w'),indent=1)
