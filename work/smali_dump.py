import os,sys,re
os.environ['LOGURU_LEVEL']='ERROR'
from loguru import logger
logger.remove()
from androguard.misc import AnalyzeAPK
p="/home/user/rakshit/TopFollow_v845-Beta (1).apk"
a,d_list,dx=AnalyzeAPK(p)
os.makedirs('out/smali',exist_ok=True)
n=0; total_lines=0
for d in d_list:
    for c in d.get_classes():
        name=c.get_name()
        if not name.startswith('Lcom/nivaroid/'): continue
        safe=name.strip('L;').replace('/','.')+'.smali'
        buf=[]
        buf.append("# CLASS %s  access=0x%x  super=%s"%(name,c.get_access_flags(),c.get_superclassname()))
        ifs=c.get_interfaces()
        if ifs: buf.append("# interfaces=%s"%(ifs,))
        try:
            src=c.get_source()
            if src: buf.append(src); 
        except Exception as e:
            buf.append("# get_source failed: %s"%e)
        if len(buf)<=2 or not buf[-1].strip():
            # manual dump
            buf.append("## FIELDS")
            for f in c.get_fields():
                buf.append("  %s %s %s  # access=0x%x"%(f.get_access_flags_string(),f.get_descriptor(),f.get_name(),f.get_access_flags()))
                try:
                    v=f.get_init_value()
                    if v is not None: buf.append("      = %r"%(v.get_value(),))
                except Exception: pass
            buf.append("## METHODS")
            for m in c.get_methods():
                buf.append("\n  .method %s %s%s"%(m.get_access_flags_string(),m.get_name(),m.get_descriptor()))
                code=m.get_code()
                if code is None:
                    buf.append("      # no code (abstract/native)")
                else:
                    buf.append("      registers=%d ins=%d outs=%d"%(code.get_registers_size(),code.get_ins_size(),code.get_outs_size()))
                    try:
                        from androguard.core.dex import Kind
                    except Exception:
                        Kind=None
                    bc=m.get_instructions()
                    for idx,ins in enumerate(bc):
                        try:
                            out=ins.get_output()
                        except Exception:
                            out=''
                        buf.append("      %04x: %-12s %s"%(idx*2,ins.get_name(),out.replace('\n',' | ')))
                buf.append("  .end method")
        txt="\n".join(buf)
        open('out/smali/'+safe,'w').write(txt)
        total_lines+=txt.count('\n'); n+=1
print("dumped %d classes, %d lines"%(n,total_lines))
