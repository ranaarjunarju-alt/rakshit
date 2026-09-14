import sys, json, time, collections, re
from androguard.misc import AnalyzeAPK
t=time.time()
p="/home/user/rakshit/TopFollow_v845-Beta (1).apk"
a, d_list, dx = AnalyzeAPK(p)
print("loaded in %.1fs, dex count=%d"%(time.time()-t,len(d_list)), file=sys.stderr)
out={}
# class list
classes=[]
for d in d_list:
    for c in d.get_classes():
        classes.append(c.get_name())
out['class_count']=len(classes)
out['method_count']=sum(len(d.get_methods()) for d in d_list)
out['field_count']=sum(len(d.get_fields()) for d in d_list)
# package heatmap (top 3 segments)
def pkg(n):
    s=n.strip('L;').split('/')
    return '/'.join(s[:3]) if len(s)>=3 else '/'.join(s[:-1])
c=collections.Counter(pkg(x) for x in classes)
out['package_heatmap']=c.most_common(80)
# app classes only
appc=[x for x in classes if x.startswith('Lcom/nivaroid/')]
out['app_class_count']=len(appc)
out['app_classes']=sorted(appc)
# strings of interest
json.dump(out, open('out/02_dex_overview.json','w'), indent=1)
print("WROTE overview app_classes=%d"%len(appc), file=sys.stderr)

# ALL strings -> file
strs=set()
for d in d_list:
    for s in d.get_strings():
        strs.add(str(s) if not isinstance(s,str) else s)
with open('out/03_all_strings.txt','w') as f:
    for s in sorted(strs):
        f.write(s.replace('\n','\\n')+"\n")
print("strings=%d"%len(strs), file=sys.stderr)

# native methods
natives=[]
for cls in dx.get_classes():
    for m in cls.get_methods():
        mm=m.get_method()
        try:
            if mm.get_access_flags() & 0x0100:  # ACC_NATIVE
                natives.append(mm.get_class_name()+"->"+mm.get_name()+str(mm.get_descriptor()))
        except Exception: pass
out['native_methods']=sorted(set(natives))
json.dump(out, open('out/02_dex_overview.json','w'), indent=1)
print("native_methods=%d"%len(set(natives)), file=sys.stderr)
print("DONE %.1fs"%(time.time()-t), file=sys.stderr)
