import lief, capstone, json, re, base64
p='apk/lib/x86/libtopfollow.so'
b=lief.parse(p); raw=open(p,'rb').read()
loads=[(s.virtual_address,s.file_offset,max(s.virtual_size,s.physical_size)) for s in b.segments if 'LOAD' in str(s.type)]
secs={s.name:s for s in b.sections}
RO=secs['.rodata']; TEXT=secs['.text']
RO_VA,RO_SIZE=RO.virtual_address,RO.size
def va2off(va):
    for v,fo,sz in loads:
        if v<=va<v+sz: return fo+(va-v)
def off2va(o):
    for v,fo,sz in loads:
        if fo<=o<fo+sz: return v+(o-fo)
def cstr(va,maxlen=500):
    o=va2off(va)
    if o is None or o<0 or o>=len(raw): return None
    e=raw.find(b'\x00',o,o+maxlen)
    if e<0: return None
    try: s=raw[o:e].decode('utf-8')
    except Exception: return None
    if not s or sum(1 for c in s if 32<=ord(c)<127)<len(s)*0.92: return None
    return s
md=capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32); md.detail=True
GOT=0xdfcac
# confirm: find 'add esi, 0x85d80' after 'call $+5; pop esi'
natives=json.load(open('out/14_jni_natives.json'))['x86']
addrs={n:int(natives[n]['fn_va'],16) for n in natives}
sf=sorted(addrs.items(), key=lambda kv: kv[1])
def which_fn(va):
    cur=None
    for n,a in sf:
        if a<=va: cur=n
        else: break
    return cur
o=va2off(TEXT.virtual_address); code=raw[o:o+TEXT.size]
refs=[]
imm_re=re.compile(r'0x([0-9a-f]+)')
for ins in md.disasm(code, TEXT.virtual_address):
    op=ins.op_str
    cands=[]
    m=re.search(r'\[esi ([+-]) 0x([0-9a-f]+)\]', op)
    if m:
        d=int(m.group(2),16)*(1 if m.group(1)=='+' else -1); cands.append(GOT+d)
    m2=re.search(r'\[ebx ([+-]) 0x([0-9a-f]+)\]', op)
    if m2:
        d=int(m2.group(2),16)*(1 if m2.group(1)=='+' else -1); cands.append(GOT+d)
    for tok in imm_re.findall(op):
        cands.append(int(tok,16))
    for v in cands:
        if RO_VA<=v<RO_VA+RO_SIZE:
            s=cstr(v)
            if s and len(s)>=3:
                refs.append({'ins_va':hex(ins.address),'mn':ins.mnemonic,'op':op,'str_va':hex(v),'str':s,'fn':which_fn(ins.address)})
json.dump(refs,open('out/17_text_rodata_refs.json','w'),indent=1)
print("total refs:",len(refs))
import collections
byfn=collections.OrderedDict()
for r in refs: byfn.setdefault(r['fn'] or '<pre>',[]).append(r)
def dec(s):
    chain=[]
    cur=s
    for _ in range(5):
        if not re.fullmatch(r'[A-Za-z0-9+/]{6,}={0,2}',cur): break
        try: t=base64.b64decode(cur+'='*((4-len(cur)%4)%4)).decode('utf-8')
        except Exception: break
        chain.append(t); cur=t
    return chain
for fn,rs in byfn.items():
    sig=natives.get(fn,{}).get('signature','')
    print("="*90); print("%s  %s   (%d refs)"%(fn,sig,len(rs)))
    seen=set()
    for r in rs:
        if r['str'] in seen: continue
        seen.add(r['str'])
        ch=dec(r['str'])
        print("   %-10s %-6s %-32s %r%s"%(r['ins_va'],r['mn'],r['op'][:32],r['str'][:100], ('   ==> '+' | '.join(repr(x) for x in ch)) if ch else ''))
