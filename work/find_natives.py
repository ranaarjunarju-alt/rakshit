import lief, struct, sys, json
arch_map={'arm64-v8a':('apk/lib/arm64-v8a/libtopfollow.so','AARCH64'),
          'x86_64':('apk/lib/x86_64/libtopfollow.so','X86_64'),
          'x86':('apk/lib/x86/libtopfollow.so','I386')}
names=["x00105e9b","x0010e27f","x00113f7a","x0011a4c2","x0011e28b","x0011f1a2","x0011f42b","x00120b1e","x00126f7c","x0012d3e0","x0012e5a1","x0012f5b7","x00135e2a","x0014b4f3","x0014c1f9","x0014e2e9","x0015a3b7","x0015b1e9","x0015e49c","x0016d3b9","x0017b62c","x0018d3f7"]
out={}
for tag,(p,arch) in arch_map.items():
    b=lief.parse(p); raw=open(p,'rb').read()
    # build VA -> offset map
    segs=[(s.virtual_address, s.virtual_size, s.file_offset, s.physical_size) for s in b.segments if 'LOAD' in str(s.type)]
    def va2off(va):
        for v,vs,fo,ps in segs:
            if v<=va<v+max(vs,ps): return fo+(va-v)
        return None
    def off2va(off):
        for v,vs,fo,ps in segs:
            if fo<=off<fo+max(vs,ps): return v+(off-fo)
        return None
    endian='<'
    ptrsz=8 if arch!='I386' else 4
    fmt=endian+('Q' if ptrsz==8 else 'I')
    # locate string offsets
    str_off={}
    for n in names:
        i=raw.find(n.encode()+b'\x00')
        if i>0: str_off[n]=i
    print(f"--- {tag}: found {len(str_off)}/{len(names)} name strings", file=sys.stderr)
    if not str_off: continue
    # search pointer-sized slots holding VA of each name
    refs={}
    for n,o in str_off.items():
        va=off2va(o)
        if va is None: continue
        pat=struct.pack(fmt, va)
        pos=[]
        st=0
        while True:
            i=raw.find(pat, st)
            if i<0: break
            if i%ptrsz==0 or True: pos.append(i)
            st=i+1
        if pos: refs[n]=pos
    print(f"    refs found for {len(refs)} names", file=sys.stderr)
    # group into table: find a base offset such that many names appear at base + k*4*ptrsz
    best=None
    for n,poss in refs.items():
        for pos in poss:
            # assume this is entry k of table; try each k
            for k in range(0,40):
                base=pos-k*4*ptrsz
                if base<0: continue
                cnt=0; entries=[]
                for j in range(0,40):
                    off=base+j*4*ptrsz
                    if off+4*ptrsz>len(raw): break
                    np_=struct.unpack_from(fmt,raw,off)[0]
                    sp_=struct.unpack_from(fmt,raw,off+ptrsz)[0]
                    fp_=struct.unpack_from(fmt,raw,off+2*ptrsz)[0]
                    nva2=va2off(np_); 
                    nm=None
                    if nva2 is not None and 0<=nva2<len(raw):
                        e=raw.find(b'\x00',nva2); nm=raw[nva2:e].decode('ascii','replace')
                    if nm in names:
                        cnt+=1
                        sova2=va2off(sp_)
                        sig=None
                        if sova2 is not None and 0<=sova2<len(raw):
                            e=raw.find(b'\x00',sova2); sig=raw[sova2:e].decode('ascii','replace')
                        entries.append({'idx':j,'name':nm,'sig':sig,'fnptr_va':hex(fp_),'fnptr_off':hex(va2off(fp_)) if va2off(fp_) else None,'slot_file_off':hex(off)})
                    else: break
                if best is None or cnt>best['count']:
                    best={'count':cnt,'base_off':hex(base),'base_va':hex(off2va(base)) if off2va(base) else None,'entries':entries}
    if best:
        out[tag]=best
        print(f"=== {tag}: JNINativeMethod table @file {best['base_off']} va {best['base_va']} count={best['count']}")
        for e in best['entries']:
            print("   [%2d] %-12s %-70s fn=%s (off %s)"%(e['idx'],e['name'],e['sig'] or '',e['fnptr_va'],e['fnptr_off']))
json.dump(out,open('out/14_jni_natives.json','w'),indent=1)
