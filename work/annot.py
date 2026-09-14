import os,sys,json,collections
os.environ['LOGURU_LEVEL']='ERROR'
from loguru import logger; logger.remove()
from androguard.misc import AnalyzeAPK
a,d_list,dx=AnalyzeAPK("/home/user/rakshit/TopFollow_v845-Beta (1).apk")
res=collections.defaultdict(dict)
cnt=0
for d in d_list:
    for c in d.get_classes():
        for m in c.get_methods():
            ann=None
            try: ann=m.get_annotations()
            except Exception: pass
            if not ann: continue
            # ann = (class_annotations, {method_annotations...}) shapes vary
            s=json.dumps(ann, default=str)
            if 'retrofit2' in s or 'POST' in s or 'GET' in s or 'FormUrlEncoded' in s:
                key=c.get_name()+"->"+m.get_name()+m.get_descriptor()
                res[c.get_name()][m.get_name()+m.get_descriptor()]=ann
                cnt+=1
print("methods with retrofit annotations:",cnt,"classes:",len(res),file=sys.stderr)
json.dump(res, open('out/10_retrofit_annotations.json','w'), indent=1, default=str)
# print readable
for cls in sorted(res):
    print("=== ",cls)
    for mn,ann in sorted(res[cls].items()):
        print("   ",mn)
        print("       ",json.dumps(ann,default=str)[:1200])
