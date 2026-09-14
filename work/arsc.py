from androguard.core.axml import ARSCParser
import zipfile,json
z=zipfile.ZipFile("/home/user/rakshit/TopFollow_v845-Beta (1).apk")
arsc=ARSCParser(z.read('resources.arsc'))
out={}
for pkg in arsc.get_packages_names():
    out[pkg]={}
    for locale in arsc.get_locales(pkg):
        try:
            t=arsc.get_types(pkg, locale)
        except Exception: continue
    # just dump all ids for xml type
ids=set()
for rid in [0x7F160000,0x7F160001,0x7F13002D,0x7F1402DF,0x7F100000]:
    ids.add(rid)
# brute force: iterate configs
res={}
for pkg in arsc.get_packages_names():
    for rid in ids:
        try:
            v=arsc.get_resource_xml_name(rid)
        except Exception as e:
            v=None
        try:
            vals=arsc.get_resolved_res_configs(rid)
        except Exception as e:
            vals=str(e)
        res[hex(rid)]={'xml_name':v,'configs':vals[:3] if isinstance(vals,list) else vals}
print(json.dumps(res,indent=1,default=str))
