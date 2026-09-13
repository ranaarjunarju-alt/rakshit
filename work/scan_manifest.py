from androguard.core.apk import APK
import json,sys
p="/home/user/rakshit/TopFollow_v845-Beta (1).apk"
a=APK(p)
info={}
info['package']=a.get_package()
info['app_name']=a.get_app_name()
info['version_name']=a.get_androidversion_name()
info['version_code']=a.get_androidversion_code()
info['min_sdk']=a.get_min_sdk_version()
info['target_sdk']=a.get_target_sdk_version()
info['max_sdk']=a.get_max_sdk_version()
info['permissions']=sorted(a.get_permissions())
info['declared_permissions']=a.get_declared_permissions()
info['activities']=a.get_activities()
info['services']=a.get_services()
info['receivers']=a.get_receivers()
info['providers']=a.get_providers()
info['main_activity']=a.get_main_activity()
info['libraries']=a.get_libraries()
info['signature_names']=a.get_signature_names()
info['files_cert']=a.get_files_certificates() if hasattr(a,'get_files_certificates') else None
try:
    certs=a.get_certificates()
    info['certs']=[{'subject':c.subject.human_friendly,'issuer':c.issuer.human_friendly,'serial':str(c.serial_number),'not_before':str(c.not_valid_before),'not_after':str(c.not_valid_after),'sig_algo':str(c.signature_algo),'sha256':c.sha256_fingerprint,'sha1':c.sha1_fingerprint,'md5':c.md5_fingerprint,'key_size':c.public_key.native.__len__() if c.public_key else None} for c in certs]
except Exception as e:
    info['cert_error']=str(e)
print(json.dumps(info,indent=2,default=str))
