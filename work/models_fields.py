import os,re,glob
for f in sorted(glob.glob('out/smali/com.nivaroid.topfollow.models.*.smali')):
    t=open(f).read()
    name=os.path.basename(f)[:-6]
    if name.endswith('$1'): continue
    # fields appear as:  <accessflags> <type> <name>;   in the "## FIELDS" section OR in java-like header
    hdr=t.split('## FIELDS')[0]
    flds=re.findall(r'^\s*(?:public|private|protected)\s+(?:static\s+)?(?:final\s+)?([\w\.<>\[\]]+)\s+(\w+)\s*[;=]',hdr,re.M)
    # also from ## FIELDS section
    fs=t.split('## FIELDS')
    sec=fs[1].split('## METHODS')[0] if len(fs)>1 else ''
    flds2=re.findall(r'^\s*(\S+)\s+(\S+)\s+(\S+)\s+#',sec,re.M)
    print("="*4,name, "="*4)
    if flds: print("  java-hdr:", ", ".join(f"{b}:{a}" for a,b in flds)[:900])
    if flds2: print("  smali:", ", ".join(f"{c.replace('L','').replace(';','')}:{b}" for a,b,c in flds2)[:900])
