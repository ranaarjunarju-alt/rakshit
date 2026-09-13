import lief, capstone, sys, json, struct
p='apk/lib/x86/libtopfollow.so'
b=lief.parse(p); raw=open(p,'rb').read()
loads=[(s.virtual_address,s.file_offset,max(s.virtual_size,s.physical_size)) for s in b.segments if 'LOAD' in str(s.type)]
def va2off(va):
    for v,fo,sz in loads:
        if v<=va<v+sz: return fo+(va-v)
def off2va(o):
    for v,fo,sz in loads:
        if fo<=o<fo+sz: return v+(o-fo)
md=capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
md.detail=True
def cstr(va,maxlen=200):
    o=va2off(va)
    if o is None: return None
    e=raw.find(b'\x00',o,o+maxlen)
    if e<0: return None
    try:
        s=raw[o:e].decode('ascii')
        return s if all(32<=ord(c)<127 for c in s) else None
    except Exception: return None
def disasm(va, nbytes=900, label=''):
    o=va2off(va)
    if o is None: print("bad va"); return
    print(f"\n######## {label} @ va=0x{va:x} off=0x{o:x}")
    code=raw[o:o+nbytes]
    for ins in md.disasm(code, va):
        ann=''
        # try resolve immediate as string
        for tok in ins.op_str.replace(',',' ').replace('[',' ').replace(']',' ').replace('+',' ').split():
            tok=tok.strip()
            if tok.startswith('0x'):
                try:
                    v=int(tok,16)
                    s=cstr(v)
                    if s and len(s)>=3: ann='   ; "%s"'%s[:120]
                except Exception: pass
        print("  0x%06x: %-8s %-42s%s"%(ins.address, ins.mnemonic, ins.op_str, ann))
        if ins.mnemonic=='ret' and ins.address>va+32: break
targets=[(0x5a080,'x0018d3f7  q.l(int) -> Retrofit[which]  (BASE URLs)'),
         (0x58a00,'x00126f7c  q.k(bool,String) -> Retrofit  (PINNING)'),
         (0x51280,'x0011f1a2  q.h(Order) -> String  (signed_body?)'),
         ]
for va,lab in targets: disasm(va, 1400, lab)
