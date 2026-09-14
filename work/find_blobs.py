import lief, struct, json
p='apk/lib/x86/libtopfollow.so'; ptrsz=4
b=lief.parse(p); raw=open(p,'rb').read()
loads=[(s.virtual_address,s.file_offset,max(s.virtual_size,s.physical_size)) for s in b.segments if 'LOAD' in str(s.type)]
def va2off(va):
    for v,fo,sz in loads:
        if v<=va<v+sz: return fo+(va-v)
    return None
def off2va(o):
    for v,fo,sz in loads:
        if fo<=o<fo+sz: return v+(o-fo)
    return None
blobs=["ZDg0NTU5MWUwODYwMzNhOTAzNWZkNmI2NmMzYzNkNzNhYTMzYWY5MDc5NGQ2Yjk4NmU2NDc3OWVlYTZiZWM1ZQ==",
"YUhSMGNITTZMeTkzZDNjdWFXNXpkR0ZuY21GdExtTnZiUzg9",
"YUhSMGNITTZMeTlwTG1sdWMzUmhaM0poYlM1amIyMHZZWEJwTDNZeUx3PT0=",
"aHR0cHM6Ly93d3cuaW5zdGFncmFtLmNvbS8=",
"WTNKbFlYUmxYMjV2ZEdVdmRqSXY=",
"WVVoU01HTklUVFpNZVRr",
"bGliZnJpZGEtZ2FkZ2V0","cmUuZnJpZGEuc2VydmVy",
"bGliYXJ0LnNvIChkZWxldGVkKQ==","bGliYy5zbyAoZGVsZXRlZCk=",
"TGJGMExoNWxw","SGJGME5oNWxw","L3NhdmUv","Y3JlYXRlX25vdGUvdjIv","YmFzZVVybA=="]
print("=== blob locations & xrefs (x86 libtopfollow.so) ===")
for blob in blobs:
    bb=blob.encode()
    offs=[]
    st=0
    while True:
        i=raw.find(bb,st)
        if i<0: break
        offs.append(i); st=i+1
    if not offs:
        print(f"  {blob[:44]:46s} NOT FOUND"); continue
    for o in offs:
        va=off2va(o)
        # find 4-byte LE pointer refs to va
        refs=[]
        if va is not None:
            pat=struct.pack('<I',va); st2=0
            while True:
                j=raw.find(pat,st2)
                if j<0: break
                refs.append(j); st2=j+1
        print(f"  {blob[:44]:46s} off={hex(o)} va={hex(va) if va else '-'}  xref_slots={[hex(r) for r in refs[:6]]}")
