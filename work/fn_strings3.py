import lief, capstone, json, re, base64, collections
p='apk/lib/x86/libtopfollow.so'
b=lief.parse(p); raw=open(p,'rb').read()
loads=[(s.virtual_address,s.file_offset,max(s.virtual_size,s.physical_size)) for s in b.segments if 'LOAD' in str(s.type)]
secs={s.name:s for s in b.sections}
RO=secs['.rodata']; TEXT=secs['.text']
RO_VA,RO_SIZE=RO.virtual_address,RO.size
def va2off(va):
    for v,fo,sz in loads:
        if v<=va<v+sz: return fo+(va-v)
def cstr(va,maxlen=600):
    o=va2off(va)
    if o is None or o<0 or o>=len(raw): return None
    e=raw.find(b'\x00',o,o+maxlen)
    if e<0: return None
    try: s=raw[o:e].decode('utf-8')
    except Exception: return None
    if not s or sum(1 for c in s if 32<=ord(c)<127)<len(s)*0.92: return None
    return s
md=capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32); md.detail=True
natives=json.load(open('out/14_jni_natives.json'))['x86']
addrs={n:int(natives[n]['fn_va'],16) for n in natives}
sf=sorted(addrs.items(), key=lambda kv: kv[1])
o=va2off(TEXT.virtual_address); code=raw[o:o+TEXT.size]
insns=list(md.disasm(code, TEXT.virtual_address))
print("disassembled %d instructions of .text (%d bytes)"%(len(insns),TEXT.size))
# locate PIC thunks: call <next>; pop REG ; add REG, K   (within 3 insns)
thunks=[]
for i in range(len(insns)-3):
    a,b2,c=insns[i],insns[i+1],insns[i+2]
    if a.mnemonic=='call' and a.op_str.startswith('0x') and int(a.op_str,16)==b2.address:
        if b2.mnemonic=='pop' and c.mnemonic=='add' and c.op_str.startswith(b2.op_str+','):
            k=int(c.op_str.split(',')[1].strip(),16)
            thunks.append({'at':a.address,'reg':b2.op_str,'base':b2.address+k})
print("PIC thunks found:",len(thunks))
def base_for(va):
    best=None
    for t in thunks:
        if t['at']<=va: best=t
        else: break
    return best['base'] if best else None
def which_fn(va):
    cur='<pre>'
    for n,a in sf:
        if a<=va: cur=n
        else: break
    return cur
refs=[]
for ins in insns:
    op=ins.op_str
    cands=[]
    for m in re.finditer(r'\[(e[sd]i|ebx|ebp|ecx|edx|eax) ([+-]) 0x([0-9a-f]+)\]', op):
        d=int(m.group(3),16)*(1 if m.group(2)=='+' else -1)
        base=base_for(ins.address)
        if base is not None: cands.append(base+d)
    for tok in re.findall(r'(?<![\w])0x([0-9a-f]{4,})', op):
        cands.append(int(tok,16))
    for v in cands:
        if RO_VA<=v<RO_VA+RO_SIZE:
            s=cstr(v)
            if s and len(s)>=3:
                refs.append({'va':hex(ins.address),'mn':ins.mnemonic,'op':op,'str_va':hex(v),'str':s,'fn':which_fn(ins.address)})
json.dump(refs,open('out/18_text_refs.json','w'),indent=1)
print("refs:",len(refs))
byfn=collections.OrderedDict()
for r in refs: byfn.setdefault(r['fn'],[]).append(r)
def dec(s):
    out=[];cur=s
    for _ in range(6):
        if not re.fullmatch(r'[A-Za-z0-9+/]{6,}={0,2}',cur): break
        try: t=base64.b64decode(cur+'='*((4-len(cur)%4)%4)).decode('utf-8')
        except Exception: break
        out.append(t); cur=t
    return out
lines=[]
for n,a in sf:
    rs=byfn.get(n,[])
    sig=natives[n]['signature']
    lines.append("="*92); lines.append("%s  va=%s  %s   (%d refs)"%(n,hex(a),sig,len(rs)))
    seen=set()
    for r in rs:
        if r['str'] in seen: continue
        seen.add(r['str'])
        ch=dec(r['str'])
        lines.append("   %-9s %-7s %-30s %r%s"%(r['va'],r['mn'],r['op'][:30],r['str'][:120], ('  ==> '+' | '.join(repr(x) for x in ch)) if ch else ''))
rs=byfn.get('<pre>',[])
lines.append("="*92); lines.append("<pre-JNI / runtime helpers>  (%d refs)"%len(rs))
seen=set()
for r in rs:
    if r['str'] in seen: continue
    seen.add(r['str'])
    ch=dec(r['str'])
    lines.append("   %-9s %-7s %-30s %r%s"%(r['va'],r['mn'],r['op'][:30],r['str'][:120], ('  ==> '+' | '.join(repr(x) for x in ch)) if ch else ''))
open('out/18_native_strings_by_fn.txt','w').write("\n".join(lines))
print("\n".join(lines[:8]))
