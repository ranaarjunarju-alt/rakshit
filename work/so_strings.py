import re,sys,json,collections
files={
 'arm64':'apk/lib/arm64-v8a/libtopfollow.so',
 'x86_64':'apk/lib/x86_64/libtopfollow.so',
 'x86':'apk/lib/x86/libtopfollow.so',
 'ds_arm64':'apk/lib/arm64-v8a/libdatastore_shared_counter.so',
}
RE=re.compile(rb"[\x20-\x7e]{4,}")
RE16=re.compile(rb"(?:[\x20-\x7e]\x00){4,}")
def score(s):
    letters=[c for c in s if c.isalpha()]
    if len(letters)<3: return -1
    v=sum(1 for c in s.lower() if c in 'aeiou')
    words=len(re.findall(r"[A-Za-z]{3,}",s))
    if words>=1 and v>=2: return words+v*0.1
    if re.search(r"(://|L[a-z]+/|Ljava|Lokhttp|Lcom/|\(\)|\)[VLZIJ]|\.[a-z]{2,}|^[a-z0-9_]+$|/[a-z])",s): return 2
    return -1
allout={}
for tag,f in files.items():
    d=open(f,'rb').read()
    a=set()
    for m in RE.finditer(d):
        s=m.group().decode('ascii')
        if score(s)>0: a.add(s)
    u=set()
    for m in RE16.finditer(d):
        s=m.group().decode('utf-16-le')
        if score(s)>0: u.add(s)
    allout[tag]={'ascii':sorted(a),'utf16':sorted(u),'file_size':len(d)}
    print(f"{tag}: file={len(d)} ascii_str={len(a)} utf16_str={len(u)}",file=sys.stderr)
json.dump(allout,open('out/08_so_strings.json','w'),indent=1)
