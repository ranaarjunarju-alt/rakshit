import os,sys,re,collections,json
os.environ['LOGURU_LEVEL']='ERROR'
from loguru import logger; logger.remove()
from androguard.misc import AnalyzeAPK
a,d_list,dx=AnalyzeAPK("/home/user/rakshit/TopFollow_v845-Beta (1).apk")
classes={c.get_name():c for d in d_list for c in d.get_classes()}
def dump(c):
    buf=["# CLASS %s  super=%s"%(c.get_name(),c.get_superclassname())]
    try:
        s=c.get_source()
        if s: buf.append(s)
    except Exception as e: buf.append("# src fail %s"%e)
    return "\n".join(buf)
# seed = app classes
seed=[n for n in classes if n.startswith('Lcom/nivaroid/')]
# BFS over class references in code (const-class / invoke / new-instance / field types)
seen=set(seed); frontier=list(seed)
ref=re.compile(r'L([A-Za-z0-9_$/]+);')
skip_pref=('Landroid','Landroidx','Lkotlin','Ljava','Ljavax','Lcom/google','Lcom/bumptech','Lretrofit2','Lokhttp3','Lokio','Lcom/squareup','Ldalvik','Lorg/json','Lcom/nivaroid')
depth=0
while frontier and depth<3:
    nxt=[]
    for n in frontier:
        c=classes.get(n)
        if c is None: continue
        txt=dump(c)
        for m in ref.finditer(txt):
            cn='L'+m.group(1)+';'
            if cn in seen or cn in classes and cn.startswith(skip_pref): continue
            if cn in classes:
                seen.add(cn); nxt.append(cn)
    frontier=nxt; depth+=1
    print("depth %d -> total %d"%(depth,len(seen)),file=sys.stderr)
os.makedirs('out/xref',exist_ok=True)
cnt=0
for n in sorted(seen):
    c=classes.get(n)
    if c is None: continue
    safe=n.strip('L;').replace('/','.')+'.java'
    open('out/xref/'+safe,'w').write(dump(c)); cnt+=1
print("dumped %d classes to out/xref"%cnt)
json.dump(sorted(seen),open('out/09_xref_classes.json','w'),indent=0)
