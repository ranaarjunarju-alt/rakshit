import os,sys,json
os.environ['LOGURU_LEVEL']='ERROR'
from loguru import logger; logger.remove()
from androguard.misc import AnalyzeAPK
a,d_list,dx=AnalyzeAPK("/home/user/rakshit/TopFollow_v845-Beta (1).apk")
os.makedirs('out/all',exist_ok=True)
n=0; fails=0
for d in d_list:
    for c in d.get_classes():
        name=c.get_name()
        safe=name.strip('L;').replace('/','.')+'.java'
        buf=["# CLASS %s super=%s access=0x%x"%(name,c.get_superclassname(),c.get_access_flags())]
        try:
            s=c.get_source()
            if s: buf.append(s)
            else: fails+=1
        except Exception as e:
            buf.append("# src fail %s"%e); fails+=1
        open('out/all/'+safe,'w').write("\n".join(buf)); n+=1
print("dumped",n,"empty_src",fails)
