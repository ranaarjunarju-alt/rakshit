import struct, sys, json, collections
# Minimal DEX parser focused on annotations of methods (Retrofit @POST/@GET values)
f=open('apk/classes.dex','rb').read()
def u32(o): return struct.unpack_from('<I',f,o)[0]
def u16(o): return struct.unpack_from('<H',f,o)[0]
def uleb(o):
    r=0;s=0
    while True:
        b=f[o];o+=1;r|=(b&0x7f)<<s
        if not b&0x80: break
        s+=7
    return r,o
string_ids_size=u32(56); string_ids_off=u32(60)
type_ids_size=u32(64); type_ids_off=u32(68)
proto_ids_size=u32(72); proto_ids_off=u32(76)
field_ids_size=u32(80); field_ids_off=u32(84)
method_ids_size=u32(88); method_ids_off=u32(92)
class_defs_size=u32(96); class_defs_off=u32(100)
def get_string(i):
    if i==0xffffffff: return None
    off=u32(string_ids_off+4*i)
    n,o=uleb(off)
    end=f.index(b'\x00',o)
    return f[o:end].decode('utf-8','replace')
def get_type(i):
    if i==0xffffffff or i>=type_ids_size: return None
    return get_string(u16(type_ids_off+2*i))
def method_name(mi):
    off=method_ids_off+8*mi
    cls=u16(off); proto=u16(off+2); name=u32(off+4)
    return get_type(cls), get_string(name)
# annotations directories
annsets_off=u32(0x68-0x68+ 0)  # placeholder
# map_list
map_off=u32(52)
n=u32(map_off)
items={}
p=map_off+4
for i in range(n):
    t=u16(p); sz=u32(p+4); off=u32(p+8); p+=12
    items[t]=(sz,off)
print("map types:",{hex(k):v[0] for k,v in items.items()},file=sys.stderr)
TYPE_ANNOTATION_SET_ITEM=0x1000
TYPE_ANNOTATION_SET_REF_LIST=0x1001
TYPE_ANNOTATION_ITEM=0x2004
TYPE_ENCODED_ARRAY=0x2005
TYPE_ANNOTATIONS_DIRECTORY=0x2006
def read_encoded_value(o):
    b=f[o]; o+=1
    va=b&0x1f; at=(b>>5)&7
    if at==0x00: # BYTE
        v=struct.unpack_from('<b',f,o)[0]; return ('byte',v), o+1
    if at==0x01: return ('short',struct.unpack_from('<h',f,o)[0]), o+2
    if at in (0x02,): return ('char',u16(o)), o+2
    if at==0x03: return ('int',struct.unpack_from('<i',f,o)[0]), o+4
    if at==0x04: return ('long',struct.unpack_from('<q',f,o)[0]), o+8
    if at==0x15: return ('method_type',u32(o)), o+4
    if at==0x16: return ('method_handle',u32(o)), o+4
    if at==0x17: return ('string',get_string(u32(o))), o+4
    if at==0x18: return ('type',get_type(u32(o))), o+4
    if at==0x19: return ('field',u32(o)), o+4
    if at==0x1a: return ('method',u32(o)), o+4
    if at==0x1b: return ('enum',u32(o)), o+4
    if at==0x1c: # ARRAY
        sz,o2=uleb(o+1)
        vals=[]
        for i in range(sz):
            v,o2=read_encoded_value(o2); vals.append(v)
        return ('array',vals), o2
    if at==0x1d: # ANNOTATION
        sz,o2=uleb(o+1)
        tidx,o2=uleb(o2)
        elems=[]
        for i in range(sz):
            no,o2=uleb(o2)
            v,o2=read_encoded_value(o2)
            elems.append((get_string(no),v))
        return ('annotation',get_type(tidx),elems), o2
    if at==0x1e: return ('null',None), o
    if at==0x1f: return ('bool',bool(va)), o
    return ('unknown_at_%x'%at, va), o
# annotations directory items
res=collections.defaultdict(dict)
sz,off=items.get(TYPE_ANNOTATIONS_DIRECTORY,(0,0))
for i in range(sz):
    base=off+32*i
    class_idx=u32(base)
    ann_off=u32(base+4)
    fields_size=u32(base+8); ann_methods_size=u32(base+12); ann_params_size=u32(base+16)
    p2=base+20
    clsname=get_type(class_idx)
    for _ in range(fields_size): p2+=8
    meths=[]
    for _ in range(ann_methods_size):
        mi=u32(p2); ao=u32(p2+4); p2+=8
        meths.append((mi,ao))
    for _ in range(ann_params_size): p2+=8
    for mi,ao in meths:
        c,mn=method_name(mi)
        # annotation_set_item
        cnt=u32(ao)
        vals=[]
        for k in range(cnt):
            ent=u32(ao+4+4*k)  # annotation_off
            vis=f[ent]; item=ent+1
            tidx,u1=uleb(item)
            aname=get_type(tidx)
            sz2,u2=uleb(u1)
            elems=[]
            q=u2
            for e in range(sz2):
                no,q=uleb(q)
                v,q=read_encoded_value(q)
                elems.append((get_string(no),v))
            vals.append((aname,elems))
        if vals:
            res[clsname][mn]=vals
print("classes with method annotations:",len(res),file=sys.stderr)
# Filter retrofit
RETRO=('Lretrofit2/http/','Lretrofit2/','Lokhttp3/')
out={}
for cls,ms in res.items():
    keep={}
    for mn,vals in ms.items():
        rel=[v for v in vals if any(v[0].startswith(p) for p in RETRO)]
        if rel: keep[mn]=rel
    if keep: out[cls]=keep
json.dump(out,open('out/11_retrofit_map.json','w'),indent=1,default=str)
print("retrofit-annotated classes:",len(out),file=sys.stderr)
for cls in sorted(out):
    print("=== "+cls)
    for mn in sorted(out[cls]):
        parts=[]
        for aname,elems in out[cls][mn]:
            a=aname.split('/')[-1].rstrip(';')
            d=[]
            for en,ev in elems:
                if ev[0]=='array':
                    d.append(en+'=['+', '.join(str(x[1]) for x in ev[1])+']')
                elif ev[0]=='annotation':
                    sub=[]
                    for sen,sev in ev[2]:
                        sub.append(f"{sen}={sev[1] if sev[0]!='array' else [x[1] for x in sev[1]]}")
                    d.append(en+'={'+', '.join(sub)+'}')
                else:
                    d.append(f"{en}={ev[1]}")
            parts.append('@'+a+'('+', '.join(d)+')')
        print('   %-28s %s'%(mn,' '.join(parts)))
