import lief, json
files={'arm64-v8a/libtopfollow.so':'apk/lib/arm64-v8a/libtopfollow.so',
       'x86_64/libtopfollow.so':'apk/lib/x86_64/libtopfollow.so',
       'x86/libtopfollow.so':'apk/lib/x86/libtopfollow.so',
       'arm64-v8a/libdatastore_shared_counter.so':'apk/lib/arm64-v8a/libdatastore_shared_counter.so',
       'x86_64/libdatastore_shared_counter.so':'apk/lib/x86_64/libdatastore_shared_counter.so',
       'x86/libdatastore_shared_counter.so':'apk/lib/x86/libdatastore_shared_counter.so'}
def g(o,*names):
    for n in names:
        if hasattr(o,n):
            try: return getattr(o,n)
            except Exception: pass
    return None
out={}
for tag,p in files.items():
    b=lief.parse(p); hdr=b.header; d={}
    d['file_size']=len(open(p,'rb').read())
    d['type']=str(g(hdr,'file_type')); d['machine']=str(g(hdr,'machine_type','machine'))
    d['entrypoint']=hex(int(g(hdr,'entrypoint') or 0))
    d['num_sections']=len(b.sections); d['num_symbols']=len(b.symbols)
    d['exported']=[s.name for s in b.exported_symbols]
    d['imported']=sorted({s.name for s in b.imported_symbols if s.name})
    d['needed']=list(b.libraries)
    d['PIE']=bool(getattr(b,'is_pie',None))
    segtypes=[str(s.type) for s in b.segments]
    d['segment_types']=segtypes
    d['RELRO']='Full' if any('GNU_RELRO' in t for t in segtypes) else 'None'
    flags=str(g(hdr,'flags_list','flags'))
    d['hdr_flags']=flags
    dynflags=[]
    for e in b.dynamic_entries:
        t=str(getattr(e,'tag',''))
        if 'FLAGS' in t: dynflags.append((t,str(getattr(e,'flags',getattr(e,'value','')))))
    d['dynamic_flags']=dynflags
    d['BIND_NOW']=any('BIND_NOW' in str(x) or 'NOW' in str(x) for x in dynflags)
    if d['RELRO']!='None' and d['BIND_NOW']: d['RELRO']='Full (BIND_NOW)'
    elif d['RELRO']!='None': d['RELRO']='Partial'
    syms=[s.name for s in b.symbols]
    d['stack_canary']='__stack_chk_fail' in syms
    d['fortify']=sorted({s for s in syms if s and s.endswith('_chk')})
    d['sections']=[[s.name, hex(s.virtual_address), s.size, s.offset, str(s.type), str(getattr(s,'flags',''))] for s in b.sections]
    d['symbols_count_by_bind']={}
    out[tag]=d
json.dump(out,open('out/13_so_checksec.json','w'),indent=1)
for tag,d in out.items():
    print("="*78); print(tag)
    for k in ['file_size','type','machine','entrypoint','num_sections','num_symbols','PIE','RELRO','BIND_NOW','stack_canary','fortify','needed']:
        print("  %-15s %s"%(k,d[k]))
    print("  exported      ", d['exported'])
    print("  imports(%d)"%len(d['imported']))
    print("   ", ', '.join(d['imported']))
