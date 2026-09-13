"""SUPERSEDED -- DO NOT USE.

This resolved .rodata references against a single GLOBAL GOT base, which
mis-aligns on this binary and produces wrong strings. Kept only to document the
dead end.

Use fn_strings3.py instead: it derives a PER-FUNCTION .rodata base from each
position-independent thunk (call $+5; pop reg; add reg, K), which is what made
the 760 correct references -- and therefore every native secret -- recoverable.
"""
import lief, capstone, json, re, base64, collections
p='apk/lib/x86/libtopfollow.so'
b=lief.parse(p); raw=open(p,'rb').read()
loads=[(s.virtual_address,s.file_offset,max(s.virtual_size,s.physical_size)) for s in b.segments if 'LOAD' in str(s.type)]
rodata=[s for s in b.sections if s.name=='.rodata'][0]
RO_VA, RO_SIZE, RO_OFF = rodata.virtual_address, rodata.size, rodata.offset
def va2off(va):
    for v,fo,sz in loads:
        if v<=va<v+sz: return fo+(va-v)
def off2va(o):
    for v,fo,sz in loads:
        if fo<=o<fo+sz: return v+(o-fo)
def cstr(va,maxlen=400):
    o=va2off(va)
    if o is None or o<0 or o>=len(raw): return None
    e=raw.find(b'\x00',o,o+maxlen)
    if e<0: return None
    try:
        s=raw[o:e].decode('utf-8')
    except Exception: return None
    if not s: return None
    if sum(1 for c in s if 32<=ord(c)<127) < len(s)*0.9: return None
    return s
md=capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32); md.detail=True
GOT_BASE=0xdfc4c
natives=json.load(open('out/14_jni_natives.json'))['x86']
order=[natives[n]['name'] for n in sorted(natives, key=lambda k:int(natives[k]['fn_va'],16))]
addrs={n:int(natives[n]['fn_va'],16) for n in natives}
sorted_fns=sorted(addrs.items(), key=lambda kv: kv[1])
result={}
for idx,(n,va) in enumerate(sorted_fns):
    end = sorted_fns[idx+1][1] if idx+1<len(sorted_fns) else va+0x4000
    size=min(end-va, 0x6000)
    o=va2off(va); code=raw[o:o+size]
    got=[]; imm=[]; calls=[]
    for ins in md.disasm(code, va):
        for tok in re.findall(r'0x[0-9a-fA-F]+', ins.op_str):
            v=int(tok,16)
            if RO_VA<=v<RO_VA+RO_SIZE:
                s=cstr(v)
                if s: imm.append((hex(ins.address),ins.mnemonic,ins.op_str,v,s))
        m=re.search(r'\[esi ([+-]) 0x([0-9a-f]+)\]', ins.op_str)
        if m:
            delta=int(m.group(2),16)*(1 if m.group(1)=='+' else -1)
            v=GOT_BASE+delta
            if RO_VA<=v<RO_VA+RO_SIZE:
                s=cstr(v)
                if s: got.append((hex(ins.address),ins.mnemonic,ins.op_str,v,s))
        if ins.mnemonic=='call': calls.append((hex(ins.address),ins.op_str))
    result[n]={'va':hex(va),'size':size,'sig':natives[n]['signature'],
               'rodata_refs_imm':[[a,mn,op,hex(v),s] for a,mn,op,v,s in imm],
               'rodata_refs_got':[[a,mn,op,hex(v),s] for a,mn,op,v,s in got],
               'num_calls':len(calls)}
json.dump(result,open('out/16_native_fn_strings.json','w'),indent=1)
for n in sorted(result, key=lambda k:int(result[k]['va'],16)):
    r=result[n]
    allrefs=r['rodata_refs_imm']+r['rodata_refs_got']
    print("="*84)
    print("%s  va=%s size=%d  %s"%(n,r['va'],r['size'],r['sig']))
    seen=set()
    for a,mn,op,v,s in allrefs:
        if s in seen: continue
        seen.add(s)
        b64=''
        if re.fullmatch(r'[A-Za-z0-9+/]{6,}={0,2}',s):
            try:
                dec=base64.b64decode(s+'='*((4-len(s)%4)%4)).decode('utf-8')
                if all(32<=ord(c)<127 for c in dec): b64='   ==> b64: %r'%dec
            except Exception: pass
        print("   %-9s %-6s %-34s %s%s"%(a,mn,op[:34],repr(s[:110]),b64))
